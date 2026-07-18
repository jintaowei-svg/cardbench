from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def aggregate(
    agntcy_path: Path,
    autogen_path: Path,
    langgraph_path: Path | None,
    applicability_path: Path,
    output: Path,
    expected_per_attack: int = 90,
) -> dict[str, Any]:
    applicability = json.loads(applicability_path.read_text(encoding="utf-8"))
    if applicability.get("frozen") is not True:
        raise ValueError("Extension applicability must be frozen.")
    targets = {"agntcy": _load(agntcy_path), "autogen": _load(autogen_path)}
    if langgraph_path is not None and langgraph_path.is_file():
        targets["langgraph"] = _load(langgraph_path)
    rows: list[dict[str, Any]] = []
    for target, records in targets.items():
        seen: set[str] = set()
        buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            case_id = str(record["target_case_id"])
            if case_id in seen:
                raise ValueError(f"Duplicate {target} target case: {case_id}")
            seen.add(case_id)
            attack = str(record["attack_type"])
            if applicability[target].get(attack) != "applicable":
                raise ValueError(f"Executed N/A combination: {target}/{attack}")
            if record.get("native_execution_valid") is False:
                raise ValueError(f"Invalid native evidence: {target}/{case_id}")
            buckets[attack].append(record)
        expected_attacks = {
            attack
            for attack, status in applicability[target].items()
            if status == "applicable"
        }
        if set(buckets) != expected_attacks:
            raise ValueError(f"Incomplete attack set for {target}: {sorted(buckets)}")
        for attack in sorted(buckets):
            values = buckets[attack]
            if len(values) != expected_per_attack:
                raise ValueError(
                    f"Expected {expected_per_attack} {target}/{attack} trials, found {len(values)}"
                )
            judged = [item for item in values if item.get("native_execution_valid") is True]
            successes = sum(bool(item.get("success")) for item in judged)
            rows.append(
                {
                    "target_kind": "framework" if target in {"autogen", "langgraph"} else "ecosystem_native",
                    "target": target,
                    "attack": attack,
                    "trials": len(values),
                    "judged": len(judged),
                    "successes": successes,
                    "asr": successes / expected_per_attack,
                    "asr_planned": successes / expected_per_attack,
                    "asr_judged": successes / len(judged) if judged else None,
                    "completion_rate": len(judged) / expected_per_attack,
                    "parse_or_refusal_non_dispatch": sum(
                        item.get("native_execution_valid") is None for item in values
                    ),
                }
            )
    summary = {
        "schema_version": "carddiff-transfer-extension-aggregate-v2",
        "expected_trials_per_attack": expected_per_attack,
        "metric_definition": {
            "asr_planned": "successes / all frozen planned trials",
            "asr_judged": "successes / trials with valid native execution",
            "completion_rate": "trials with valid native execution / all frozen planned trials",
        },
        "ecosystem_native": {
            "agntcy": [row for row in rows if row["target"] == "agntcy"]
        },
        "framework_native": {
            "autogen": [row for row in rows if row["target"] == "autogen"],
            "langgraph": [row for row in rows if row["target"] == "langgraph"],
        },
        "overall_asr": None,
        "overall_asr_reason": "Different target kinds and applicability sets must not be pooled.",
        "pending_targets": sorted(set(applicability) & {"agntcy", "autogen", "langgraph"} - set(targets)),
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (output / "by_attack.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agntcy", required=True, type=Path)
    parser.add_argument("--autogen", required=True, type=Path)
    parser.add_argument("--langgraph", type=Path)
    parser.add_argument(
        "--applicability",
        type=Path,
        default=ROOT / "attacks/carddiff/transfer_extension/applicability.json",
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "results/transfer_extension/aggregate"
    )
    parser.add_argument("--expected-per-attack", type=int, default=90)
    args = parser.parse_args()
    print(
        json.dumps(
            aggregate(
                args.agntcy,
                args.autogen,
                args.langgraph,
                args.applicability,
                args.output,
                args.expected_per_attack,
            ),
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
