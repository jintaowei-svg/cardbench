"""Build a canonical result tree that follows the paper's experiment sections.

Cross-protocol results are read only from the native transfer experiment. Old
source-host, ANP wrapper, and LangGraph runs are never canonical inputs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
ACTIVE_ATTACKS = ("A1", "A2", "A3", "B1", "B2", "C1", "C2")
DOMAINS = ("travel", "healthcare", "finance")
OFFICIAL_A2A_MODELS = (
    "claude-sonnet-5",
    "deepseek-v4-flash",
    "gemini-2.5-flash",
    "gemini-3.5-flash",
    "gpt-5-mini",
    "gpt-5.4-mini",
    "gpt-5.6-Luna",
    "grok-4.5",
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
    return rows


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def attack_domain_variant(case_id: str) -> tuple[str, str, str]:
    parts = case_id.split("_")
    if len(parts) < 5 or parts[0] != "CARDDIFF":
        raise ValueError(f"Unrecognized CardDiff case id: {case_id}")
    return parts[1], parts[2].lower(), parts[-1].removeprefix("V")


def row_case_id(row: dict[str, Any]) -> str:
    for key in ("case_id", "source_case_id"):
        value = row.get(key)
        if value:
            return str(value)
    raise ValueError("Result row does not expose case_id or source_case_id")


def canonical_sort_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    case_id = row_case_id(row)
    attack, domain, variant = attack_domain_variant(case_id)
    return attack, domain, variant, case_id


def validate_unique(rows: list[dict[str, Any]], expected: int, label: str) -> None:
    ids = [row_case_id(row) for row in rows]
    duplicates = len(ids) - len(set(ids))
    if duplicates:
        raise ValueError(f"{label}: {duplicates} duplicate case ids remain")
    if len(rows) != expected:
        raise ValueError(f"{label}: expected {expected} rows, found {len(rows)}")


def summarize_asr(rows: list[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, dict[str, list[int]]] = {
        "by_attack": defaultdict(lambda: [0, 0]),
        "by_domain": defaultdict(lambda: [0, 0]),
        "by_variant": defaultdict(lambda: [0, 0]),
    }
    matrix: dict[str, dict[str, list[int]]] = defaultdict(
        lambda: defaultdict(lambda: [0, 0])
    )
    successes = 0
    error_records = 0
    for row in rows:
        attack, domain, variant = attack_domain_variant(row_case_id(row))
        success = int(bool(row.get("success")))
        successes += success
        error_records += int(bool(row.get("errors") or row.get("error")))
        for name, key in (
            ("by_attack", attack),
            ("by_domain", domain),
            ("by_variant", variant),
        ):
            buckets[name][key][0] += success
            buckets[name][key][1] += 1
        matrix[attack][domain][0] += success
        matrix[attack][domain][1] += 1

    def render(bucket: dict[str, list[int]]) -> dict[str, dict[str, float | int]]:
        return {
            key: {
                "successes": value[0],
                "trials": value[1],
                "asr": value[0] / value[1] if value[1] else 0.0,
            }
            for key, value in sorted(bucket.items())
        }

    return {
        "metric": "ASR",
        "successes": successes,
        "trials": len(rows),
        "asr": successes / len(rows) if rows else 0.0,
        "error_records": error_records,
        "by_attack": render(buckets["by_attack"]),
        "by_domain": render(buckets["by_domain"]),
        "by_variant": render(buckets["by_variant"]),
        "matrix": {
            attack: render(domains) for attack, domains in sorted(matrix.items())
        },
    }


def selected_ledger_rows(ledger: Path) -> tuple[list[dict[str, Any]], list[Path]]:
    rows: list[dict[str, Any]] = []
    sources: list[Path] = []
    with ledger.open(encoding="utf-8-sig", newline="") as handle:
        entries = list(csv.DictReader(handle))
    selected = [
        entry
        for entry in entries
        if entry.get("status") == "complete" and entry.get("attack") in ACTIVE_ATTACKS
    ]
    if len(selected) != 21:
        raise ValueError(f"{ledger}: expected 21 accepted active batches, found {len(selected)}")
    for entry in selected:
        source = ROOT / str(entry["run_jsonl"]).replace("\\", "/")
        sources.append(source)
        batch = read_jsonl(source)
        if len(batch) != 150:
            raise ValueError(f"{source}: expected 150 rows, found {len(batch)}")
        rows.extend(batch)
    validate_unique(rows, 3150, ledger.name)
    return sorted(rows, key=canonical_sort_key), sources


def active_rows(paths: Iterable[Path], label: str) -> tuple[list[dict[str, Any]], list[Path]]:
    source_paths = list(paths)
    rows = [row for path in source_paths for row in read_jsonl(path)]
    rows = [row for row in rows if attack_domain_variant(str(row["case_id"]))[0] in ACTIVE_ATTACKS]
    validate_unique(rows, 3150, label)
    return sorted(rows, key=canonical_sort_key), source_paths


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_record(path: Path, role: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "role": role,
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def main_and_cross_model(output: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    inventory: list[dict[str, Any]] = []
    result_root = ROOT / "results/official_a2a_main"
    model_rows: dict[str, list[dict[str, Any]]] = {}
    for model in OFFICIAL_A2A_MODELS:
        details_path = result_root / model / "details.jsonl"
        summary_path = result_root / model / "summary.json"
        rows = sorted(read_jsonl(details_path), key=canonical_sort_key)
        validate_unique(rows, 3150, f"Official A2A {model}")
        model_rows[model] = rows
        inventory.extend(
            (
                source_record(details_path, "official_a2a_model_details"),
                source_record(summary_path, "official_a2a_model_summary"),
            )
        )

    main_rows = model_rows["gpt-5-mini"]
    main_dir = output / "01_main"
    write_jsonl(main_dir / "details.jsonl", main_rows)
    main_summary = summarize_asr(main_rows)
    main_summary.update({"model": "gpt-5-mini", "paper_section": "Main Results"})
    write_json(main_dir / "summary.json", main_summary)

    combined: list[dict[str, Any]] = []
    model_summaries: dict[str, Any] = {}
    for model in OFFICIAL_A2A_MODELS:
        rows = model_rows[model]
        for row in rows:
            combined.append({"paper_model": model, **row})
        model_summaries[model] = summarize_asr(rows)
    expected_cross_trials = len(OFFICIAL_A2A_MODELS) * 3150
    if len(combined) != expected_cross_trials:
        raise ValueError(
            f"cross-model: expected {expected_cross_trials} rows, found {len(combined)}"
        )
    cross_dir = output / "02_cross_model"
    write_jsonl(cross_dir / "details.jsonl", combined)
    write_json(
        cross_dir / "summary.json",
        {
            "paper_section": "Cross-Model Matrix",
            "active_attacks": list(ACTIVE_ATTACKS),
            "models": model_summaries,
            "models_count": len(model_summaries),
            "trials": len(combined),
        },
    )
    return main_summary, inventory


def transferability(output: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    inventory: list[dict[str, Any]] = []
    transfer_dir = output / "03_transferability"
    applicability_path = ROOT / "attacks/carddiff/transfer_native/applicability.json"
    applicability = json.loads(applicability_path.read_text(encoding="utf-8"))
    if applicability.get("frozen") is not True:
        raise ValueError("Native transfer applicability is not frozen")

    official_path = ROOT / "results/transfer_native/official_a2a_reference/details.jsonl"
    official_rows = sorted(read_jsonl(official_path), key=canonical_sort_key)
    validate_unique(official_rows, 540, "Official A2A native reference")
    write_jsonl(transfer_dir / "official_a2a.jsonl", official_rows)
    official_summary = summarize_asr(official_rows)
    official_summary.update({"target": "Official A2A", "execution": "extracted_from_main_results"})
    write_json(transfer_dir / "official_a2a_summary.json", official_summary)
    inventory.extend([source_record(official_path, "official_a2a_reference"), source_record(applicability_path, "frozen_applicability")])

    targets: dict[str, Any] = {"official_a2a": official_summary}
    expected_trials = {
        protocol: 90 * sum(1 for status in applicability[protocol].values() if status == "applicable")
        for protocol in ("anp", "nlip")
    }
    for protocol, expected in expected_trials.items():
        path = ROOT / f"results/transfer_native/{protocol}/details.jsonl"
        if not path.is_file():
            targets[protocol] = {
                "status": "formal_run_pending",
                "expected_trials": expected,
                "applicable_attacks": [attack for attack, status in applicability[protocol].items() if status == "applicable"],
            }
            continue
        rows = sorted(read_jsonl(path), key=lambda row: str(row.get("target_case_id", "")))
        validate_unique(rows, expected, f"{protocol} native results")
        invalid_rows = [row for row in rows if row.get("native_execution_valid") is False]
        native_rows = [row for row in rows if row.get("native_execution_valid") is not None]
        non_dispatched_rows = [row for row in rows if row.get("native_execution_valid") is None]
        protocol_summary = summarize_asr(rows)
        protocol_summary.update(
            {
                "target": protocol.upper(),
                "native_execution_rate": (
                    (len(native_rows) - len(invalid_rows)) / len(native_rows)
                    if native_rows
                    else 0.0
                ),
                "invalid_native_execution_records": len(invalid_rows),
                "invalid_source_case_ids": [row_case_id(row) for row in invalid_rows],
                "non_dispatched_records": len(non_dispatched_rows),
                "status": "complete" if not invalid_rows else "evidence_repair_required",
                "formal_comparison_eligible": not invalid_rows,
            }
        )
        output_name = (
            f"{protocol}_summary.json"
            if not invalid_rows
            else f"{protocol}_diagnostic_summary.json"
        )
        if not invalid_rows:
            write_jsonl(transfer_dir / f"{protocol}.jsonl", rows)
        write_json(transfer_dir / output_name, protocol_summary)
        targets[protocol] = protocol_summary
        role = f"{protocol}_native_formal" if not invalid_rows else f"{protocol}_native_diagnostic"
        inventory.append(source_record(path, role))

    summary = {
        "paper_section": "Transferability Experiment",
        "common_attacks": ["A3", "C1"],
        "targets": targets,
        "excluded_legacy_targets": ["source", "langgraph", "anp_wrapper"],
        "overall_asr": None,
        "overall_asr_reason": "Protocol-specific attack sets differ.",
    }
    write_json(transfer_dir / "summary.json", summary)
    return summary, inventory


def downstream(output: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = ROOT / "results/downstream/official_a2a_llm_recorded_v3_full_merged_3116/details.jsonl"
    rows = sorted(read_jsonl(source), key=canonical_sort_key)
    validate_unique(rows, 3116, "downstream impact")
    target = output / "04_downstream_impact"
    write_jsonl(target / "details.jsonl", rows)

    by_attack: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"trials": 0, "impacts": 0, "impact_types": set()}
    )
    impacts = 0
    for row in rows:
        attack = str(row["attack_type"])
        hit = int(bool(row.get("impact_success")))
        impacts += hit
        by_attack[attack]["trials"] += 1
        by_attack[attack]["impacts"] += hit
        impact_type = row.get("impact_type")
        if isinstance(impact_type, str):
            by_attack[attack]["impact_types"].add(impact_type)
        elif isinstance(impact_type, list):
            by_attack[attack]["impact_types"].update(str(value) for value in impact_type)
    rendered = {
        attack: {
            "trials": item["trials"],
            "impacts": item["impacts"],
            "dir": item["impacts"] / item["trials"],
            "impact_types": sorted(item["impact_types"]),
        }
        for attack, item in sorted(by_attack.items())
    }
    summary = {
        "paper_section": "Downstream Impact Experiment",
        "metric": "DIR",
        "trials": len(rows),
        "source_trials": 3150,
        "impacts": impacts,
        "dir": impacts / len(rows),
        "eir": impacts / 3150,
        "by_attack": rendered,
    }
    write_json(target / "summary.json", summary)
    return summary, [source_record(source, "selected_downstream_final")]


def defense(output: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source_dir = ROOT / "defense/nemo/results"
    raw_path = source_dir / "raw/nemo_official_a2a_630.jsonl"
    summary_path = source_dir / "summary/nemo_official_a2a_630_summary.json"
    table_path = source_dir / "summary/defense_table.csv"
    rows = read_jsonl(raw_path)
    validate_unique(rows, 630, "NeMo defense")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    overall = summary.get("overall", {})
    if overall.get("planned") != 630:
        raise ValueError("NeMo defense summary does not cover the complete 630-case split")

    target = output / "05_defense"
    write_jsonl(target / "details.jsonl", rows)
    write_json(target / "summary.json", summary)
    shutil.copyfile(table_path, target / "defense_table.csv")
    write_json(
        target / "status.json",
        {
            "status": "complete",
            "planned_trials": overall["planned"],
            "completed_trials": overall["completed"],
            "infrastructure_errors": overall["errors"],
            "successes": overall["successes"],
            "planned_case_asr": overall["planned_case_asr"],
        },
    )
    return summary, [
        source_record(raw_path, "nemo_defense_raw"),
        source_record(summary_path, "nemo_defense_summary"),
        source_record(table_path, "nemo_defense_table"),
    ]


def legacy_inventory() -> list[dict[str, str]]:
    return [
        {"path": "results/downstream/official_a2a_llm_recorded_v3_full_merged_3116", "status": "selected_canonical_source"},
        {"path": "results/downstream/official_a2a_llm_recorded_v3_full", "status": "superseded_truncated_source"},
        {"path": "results/downstream/official_a2a_llm_recorded_v3_smoke", "status": "smoke_only"},
        {"path": "results/carddiff_llm_probe_001.jsonl", "status": "probe_only"},
        {"path": "results/carddiff_llm_probe_001_with_api.jsonl", "status": "probe_only"},
    ]


def build(output: Path) -> None:
    resolved = output.resolve()
    if ROOT.resolve() not in resolved.parents:
        raise ValueError(f"Output must stay inside the repository: {resolved}")
    for child in ("01_main", "02_cross_model", "03_transferability", "04_downstream_impact", "05_defense"):
        target = output / child
        if target.exists():
            shutil.rmtree(target)
    for child in ("manifest.json", "README.md"):
        target = output / child
        if target.exists():
            target.unlink()
    output.mkdir(parents=True, exist_ok=True)
    main_summary, inventory = main_and_cross_model(output)
    transfer_summary, transfer_sources = transferability(output)
    downstream_summary, downstream_sources = downstream(output)
    defense_summary, defense_sources = defense(output)
    inventory.extend(transfer_sources)
    inventory.extend(downstream_sources)
    inventory.extend(defense_sources)

    manifest = {
        "layout_version": 1,
        "paper_active_attacks": list(ACTIVE_ATTACKS),
        "paper_domains": list(DOMAINS),
        "canonical_experiments": {
            "01_main": {"trials": main_summary["trials"], "model": "gpt-5-mini"},
            "02_cross_model": {
                "trials": len(OFFICIAL_A2A_MODELS) * 3150,
                "models": len(OFFICIAL_A2A_MODELS),
            },
            "03_transferability": {
                "official_a2a_trials": transfer_summary["targets"]["official_a2a"]["trials"],
                "anp_status": transfer_summary["targets"]["anp"]["status"],
                "nlip_status": transfer_summary["targets"]["nlip"]["status"],
            },
            "04_downstream_impact": {"trials": downstream_summary["trials"]},
            "05_defense": {
                "status": "complete",
                "planned_trials": defense_summary["overall"]["planned"],
                "planned_case_asr": defense_summary["overall"]["planned_case_asr"],
            },
        },
        "selected_sources": inventory,
        "legacy_results": legacy_inventory(),
    }
    write_json(output / "manifest.json", manifest)
    readme = """# Canonical paper results

This directory is generated by `python scripts/consolidate_paper_results.py`.
It is the local single source of truth for the experiment structure in the paper.

- `01_main/`: completed Official A2A gpt-5-mini run over seven attacks (3,150 trials).
- `02_cross_model/`: eight complete Official A2A models over seven attacks (25,200 trials).
- `03_transferability/`: Official A2A reference extracted from the main run,
  plus protocol-native ANP/NLIP results. Runs that fail native-evidence checks
  are diagnostic only and are not eligible for formal comparison.
- `04_downstream_impact/`: recorded-trace LLM downstream result over all
  successfully triggered cases from the 3,150-case source cohort.
- `05_defense/`: the complete 630-case NeMo Guardrails result and table.

Use `manifest.json` to see exactly which source files were selected.
"""
    (output / "README.md").write_text(readme, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results/paper",
        help="Canonical output directory (default: results/paper)",
    )
    args = parser.parse_args()
    build(args.output if args.output.is_absolute() else ROOT / args.output)
    print(f"Canonical paper results written to {args.output}")


if __name__ == "__main__":
    main()
