from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "attacks/carddiff/transfer_full"
OUTPUT = ROOT / "results/transfer_full"

TARGETS = {
    "anp": {
        "existing": ROOT / "results/transfer_native/anp/details.jsonl",
        "reusable_attacks": {"A2", "B1", "B2", "C1"},
    },
    "nlip": {
        "existing": ROOT / "results/transfer_native/nlip/details.jsonl",
        "reusable_attacks": {"C2"},
    },
    "agntcy": {
        "existing": ROOT / "results/transfer_native/agntcy/details.jsonl",
        "reusable_attacks": {"A2", "B2"},
    },
    "autogen": {
        "existing": ROOT / "results/transfer_framework/autogen/details.jsonl",
        "reusable_attacks": {"C1", "C2"},
    },
    "langgraph": {
        "existing": None,
        "reusable_attacks": set(),
    },
}


def _read_jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _reusable(record: dict[str, Any], allowed_attacks: set[str]) -> bool:
    return (
        str(record.get("attack_type")) in allowed_attacks
        and record.get("native_execution_valid") is True
        and record.get("error") is None
    )


def build_plan() -> dict[str, Any]:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    reuse_dir = OUTPUT / "reuse"
    reuse_dir.mkdir(parents=True, exist_ok=True)
    run_case_ids: dict[str, list[str]] = {}
    summary: dict[str, Any] = {}

    for target, settings in TARGETS.items():
        manifest = json.loads((FULL / f"{target}_cases.json").read_text(encoding="utf-8"))
        cases = list(manifest["cases"])
        existing = _read_jsonl(settings["existing"])
        existing_by_id = {str(row["target_case_id"]): row for row in existing}
        if len(existing_by_id) != len(existing):
            raise ValueError(f"Existing {target} results contain duplicate target IDs.")

        reused: list[dict[str, Any]] = []
        missing: list[str] = []
        for case in cases:
            target_id = str(case["target_case_id"])
            record = existing_by_id.get(target_id)
            if record is not None and _reusable(record, settings["reusable_attacks"]):
                reused.append(record)
            else:
                missing.append(target_id)

        reuse_path = reuse_dir / f"{target}.jsonl"
        reuse_path.write_text(
            "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in reused),
            encoding="utf-8",
        )
        run_case_ids[target] = missing
        planned_by_attack = Counter(str(case["attack_type"]) for case in cases)
        reused_by_attack = Counter(str(row["attack_type"]) for row in reused)
        summary[target] = {
            "planned": len(cases),
            "reused": len(reused),
            "to_run": len(missing),
            "planned_by_attack": dict(sorted(planned_by_attack.items())),
            "reused_by_attack": dict(sorted(reused_by_attack.items())),
            "to_run_by_attack": {
                attack: planned_by_attack[attack] - reused_by_attack[attack]
                for attack in sorted(planned_by_attack)
            },
        }

    (FULL / "run_case_ids.json").write_text(
        json.dumps(
            {"schema_version": "carddiff-transfer-full-incremental-v1", **run_case_ids},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    plan = {
        "schema_version": "carddiff-transfer-full-plan-v1",
        "cases_per_target_attack": 450,
        "targets": summary,
        "total_planned": sum(item["planned"] for item in summary.values()),
        "total_reused": sum(item["reused"] for item in summary.values()),
        "total_to_run": sum(item["to_run"] for item in summary.values()),
        "semantic_reruns": ["anp.A3", "nlip.A3", "nlip.C1", "autogen.A3"],
    }
    (OUTPUT / "incremental_plan.json").write_text(
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return plan


if __name__ == "__main__":
    print(json.dumps(build_plan(), ensure_ascii=False, indent=2, sort_keys=True))
