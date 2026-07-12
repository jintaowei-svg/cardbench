"""Build a canonical result tree that follows the paper's experiment sections.

The repository contains raw batches, retries, repaired batches, smoke runs, and
already-merged outputs.  This script does not delete those provenance sources.
It selects the accepted batches, replaces only explicitly rerun cases, excludes
the inactive B2 attack, and writes one canonical JSONL per paper experiment.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
ACTIVE_ATTACKS = ("A1", "A2", "A3", "B1", "B3", "C1", "C2")
DOMAINS = ("travel", "healthcare", "finance")


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


def canonical_sort_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    attack, domain, variant = attack_domain_variant(str(row["case_id"]))
    return attack, domain, variant, str(row["case_id"])


def validate_unique(rows: list[dict[str, Any]], expected: int, label: str) -> None:
    ids = [str(row["case_id"]) for row in rows]
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
        attack, domain, variant = attack_domain_variant(str(row["case_id"]))
        success = int(bool(row.get("success")))
        successes += success
        error_records += int(bool(row.get("errors")))
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
    main_rows, main_sources = selected_ledger_rows(
        ROOT / ".codex_work/experiment_planning/run_ledger.csv"
    )
    main_ledger = ROOT / ".codex_work/experiment_planning/run_ledger.csv"
    main_dir = output / "01_main"
    write_jsonl(main_dir / "details.jsonl", main_rows)
    main_summary = summarize_asr(main_rows)
    main_summary.update({"model": "gpt-5-mini", "paper_section": "Main Results"})
    write_json(main_dir / "summary.json", main_summary)
    inventory.extend(source_record(path, "selected_main_batch") for path in main_sources)
    inventory.append(source_record(main_ledger, "main_batch_selection_ledger"))

    cross_specs: list[tuple[str, list[dict[str, Any]], list[Path]]] = []
    luna_paths = [
        ROOT / ".codex_work/carddiff_full_results.jsonl",
        ROOT / ".codex_work/gpt56_luna_resume_307_3600_results.jsonl",
    ]
    luna_rows, luna_sources = active_rows(luna_paths, "gpt-5.6-Luna")
    cross_specs.append(("gpt-5.6-Luna", luna_rows, luna_sources))

    for model, ledger in (
        ("gpt-5.4-mini", ROOT / ".codex_work/gpt54mini_perturbed3600/gpt54mini_perturbed3600_ledger.csv"),
        ("gemini-2.5-flash", ROOT / ".codex_work/gemini25flash_perturbed3600/gemini25flash_perturbed3600_ledger.csv"),
    ):
        rows, sources = selected_ledger_rows(ledger)
        cross_specs.append((model, rows, sources))
        inventory.append(source_record(ledger, "cross_model_batch_selection_ledger"))

    server_root = ROOT / ".codex_work/server_sync_20260710_125502/CardDiffBench/.codex_work/runs"
    for model, relative in (
        (
            "gemini-3.5-flash",
            "full_gemini35flash_20260709_214230/results/full_gemini35flash_combined.jsonl",
        ),
        (
            "claude-haiku-4.5",
            "full_claude_haiku45_20260709_234523/results/full_claude_haiku45_combined.jsonl",
        ),
    ):
        rows, sources = active_rows([server_root / relative], model)
        cross_specs.append((model, rows, sources))

    combined: list[dict[str, Any]] = []
    model_summaries: dict[str, Any] = {}
    for model, rows, sources in cross_specs:
        for row in rows:
            combined.append({"paper_model": model, **row})
        model_summaries[model] = summarize_asr(rows)
        inventory.extend(source_record(path, "selected_cross_model_source") for path in sources)
    if len(combined) != 5 * 3150:
        raise ValueError(f"cross-model: expected 15750 rows, found {len(combined)}")
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

    original_path = ROOT / ".codex_work/official_a2a_l3_full/details.jsonl"
    rerun_path = ROOT / "remote_results/official_a2a_l3_rerun_nonjudgment_20260711/details.jsonl"
    original = {
        str(row["case_id"]): {"result_phase": "original", **row}
        for row in read_jsonl(original_path)
        if row.get("attack_type") in ACTIVE_ATTACKS
    }
    reruns = read_jsonl(rerun_path)
    unknown = sorted({str(row["case_id"]) for row in reruns} - set(original))
    if unknown:
        raise ValueError(f"Official A2A rerun contains {len(unknown)} unknown case ids")
    for row in reruns:
        original[str(row["case_id"])] = {"result_phase": "rerun", **row}
    official_rows = sorted(original.values(), key=canonical_sort_key)
    validate_unique(official_rows, 630, "Official A2A transfer")
    write_jsonl(transfer_dir / "official_a2a.jsonl", official_rows)
    official_summary = summarize_asr(official_rows)
    official_summary.update({"target": "Official A2A", "replaced_cases": len(reruns)})
    write_json(transfer_dir / "official_a2a_summary.json", official_summary)
    inventory.extend(
        [source_record(original_path, "official_a2a_original"), source_record(rerun_path, "official_a2a_replacements")]
    )

    langgraph_path = ROOT / "remote_results/langgraph_transfer_20260710/langgraph_timeout_retry/langgraph_270_timeout_repaired.jsonl"
    langgraph_rows = [
        row
        for row in read_jsonl(langgraph_path)
        if attack_domain_variant(str(row["case_id"]))[0] in ("C1", "C2")
    ]
    langgraph_rows = sorted(langgraph_rows, key=canonical_sort_key)
    validate_unique(langgraph_rows, 180, "LangGraph transfer")
    write_jsonl(transfer_dir / "langgraph.jsonl", langgraph_rows)
    langgraph_summary = summarize_asr(langgraph_rows)
    langgraph_summary.update({"target": "LangGraph", "applicable_attacks": ["C1", "C2"]})
    write_json(transfer_dir / "langgraph_summary.json", langgraph_summary)
    inventory.append(source_record(langgraph_path, "langgraph_timeout_repaired"))

    summary = {
        "paper_section": "Transferability Experiment",
        "targets": {
            "official_a2a": official_summary,
            "langgraph": langgraph_summary,
            "anp": {
                "status": "raw_results_missing_locally",
                "paper_applicable_attacks": ["A1", "A2", "B1", "B3", "C1", "C2"],
                "note": "The paper table contains ANP aggregates, but no ANP trial JSONL was found locally; no synthetic rows were created.",
            },
        },
    }
    write_json(transfer_dir / "summary.json", summary)
    return summary, inventory


def downstream(output: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = ROOT / "results/downstream/official_a2a_llm_rqd1_v2_final/details.jsonl"
    rows = sorted(read_jsonl(source), key=canonical_sort_key)
    validate_unique(rows, 621, "downstream impact")
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
        "impacts": impacts,
        "dir": impacts / len(rows),
        "by_attack": rendered,
    }
    write_json(target / "summary.json", summary)
    return summary, [source_record(source, "selected_downstream_final")]


def legacy_inventory() -> list[dict[str, str]]:
    return [
        {"path": "results/downstream/official_a2a_llm_rqd1_v2_final", "status": "selected_canonical_source"},
        {"path": "results/downstream/official_a2a_llm_rqd1_v2_non_c2", "status": "superseded_constituent"},
        {"path": "results/downstream/official_a2a_llm_rqd1_v2_c2_full_rerun", "status": "superseded_constituent"},
        {"path": "results/downstream/official_a2a_llm_rqd1_v2", "status": "incomplete_intermediate_run"},
        {"path": "results/downstream/official_a2a_llm_rqd1_pilot_v1", "status": "pilot_only"},
        {"path": "results/downstream/official_a2a_llm_rqd1_v2_sanity", "status": "sanity_only"},
        {"path": "results/downstream/official_a2a_llm_rqd1_v2_c2_sanity", "status": "sanity_only"},
        {"path": "results/downstream/official_a2a_llm_rqd1_v2_c2_sanity_v2", "status": "incomplete_sanity_only"},
        {"path": "results/downstream/official_a2a_llm_rqd1_v2_c2_sanity_v3", "status": "sanity_only"},
        {"path": "results/downstream/official_a2a_rqd1", "status": "pre_llm_replay_baseline"},
        {"path": "results/carddiff_llm_probe_001.jsonl", "status": "probe_only"},
        {"path": "results/carddiff_llm_probe_001_with_api.jsonl", "status": "probe_only"},
    ]


def build(output: Path) -> None:
    resolved = output.resolve()
    if ROOT.resolve() not in resolved.parents:
        raise ValueError(f"Output must stay inside the repository: {resolved}")
    output.mkdir(parents=True, exist_ok=True)
    main_summary, inventory = main_and_cross_model(output)
    transfer_summary, transfer_sources = transferability(output)
    downstream_summary, downstream_sources = downstream(output)
    inventory.extend(transfer_sources)
    inventory.extend(downstream_sources)

    manifest = {
        "layout_version": 1,
        "paper_active_attacks": list(ACTIVE_ATTACKS),
        "paper_domains": list(DOMAINS),
        "canonical_experiments": {
            "01_main": {"trials": main_summary["trials"], "model": "gpt-5-mini"},
            "02_cross_model": {"trials": 15750, "models": 5},
            "03_transferability": {
                "official_a2a_trials": transfer_summary["targets"]["official_a2a"]["trials"],
                "langgraph_trials": transfer_summary["targets"]["langgraph"]["trials"],
                "anp_status": transfer_summary["targets"]["anp"]["status"],
            },
            "04_downstream_impact": {"trials": downstream_summary["trials"]},
            "05_defense": {"status": "no_local_results_and_no_result_table_in_paper"},
        },
        "selected_sources": inventory,
        "legacy_results": legacy_inventory(),
    }
    write_json(output / "manifest.json", manifest)
    write_json(
        output / "05_defense/status.json",
        {
            "status": "not_available",
            "note": "The supplied paper describes a defense experiment design but contains no defense result table, and no local defense result run was found.",
        },
    )
    readme = """# Canonical paper results

This directory is generated by `python scripts/consolidate_paper_results.py`.
It is the local single source of truth for the experiment structure in the paper.

- `01_main/`: accepted gpt-5-mini batches, B2 excluded (3,150 trials).
- `02_cross_model/`: five comparison models in one JSONL, B2 excluded (15,750 trials).
- `03_transferability/`: repaired Official A2A and LangGraph results. ANP is marked missing because no raw local JSONL was found.
- `04_downstream_impact/`: the final 621-case LLM downstream result.
- `05_defense/`: explicit status only; the supplied paper has a design but no result table.

Raw runs and retries remain in their original locations for provenance. Use
`manifest.json` to see exactly which source files were selected and which older
downstream directories are pilot, sanity, incomplete, or superseded data.
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
