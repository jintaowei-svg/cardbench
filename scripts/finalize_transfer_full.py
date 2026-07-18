from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "attacks/carddiff/transfer_full"
RESULTS = ROOT / "results/transfer_full"
TARGETS = ("anp", "nlip", "agntcy", "autogen", "langgraph")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def finalize(*, require_complete: bool = True) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for target in TARGETS:
        manifest = json.loads((FULL / f"{target}_cases.json").read_text(encoding="utf-8"))
        cases = list(manifest["cases"])
        planned = {str(case["target_case_id"]): case for case in cases}
        reuse = _read_jsonl(RESULTS / "reuse" / f"{target}.jsonl")
        supplement = _read_jsonl(RESULTS / target / "supplement.jsonl")
        combined: dict[str, dict[str, Any]] = {}
        for row in [*reuse, *supplement]:
            target_id = str(row["target_case_id"])
            if target_id in combined:
                raise ValueError(f"Duplicate final {target} result: {target_id}")
            if target_id not in planned:
                raise ValueError(f"Unexpected final {target} result: {target_id}")
            combined[target_id] = row
        missing = sorted(set(planned) - set(combined))
        if require_complete and missing:
            raise RuntimeError(f"{target} is incomplete: {len(missing)} missing")
        ordered = [combined[str(case["target_case_id"])] for case in cases if str(case["target_case_id"]) in combined]
        out = RESULTS / target / "details.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in ordered),
            encoding="utf-8",
        )
        by_attack = Counter(str(row["attack_type"]) for row in ordered)
        success = Counter(str(row["attack_type"]) for row in ordered if row.get("success") is True)
        judged = Counter(
            str(row["attack_type"])
            for row in ordered
            if row.get("native_execution_valid") is True
        )
        summary[target] = {
            "planned": len(cases),
            "completed": len(ordered),
            "missing": len(missing),
            "by_attack": {
                attack: {
                    "planned": 450,
                    "completed": by_attack[attack],
                    "judged": judged[attack],
                    "successes": success[attack],
                    "asr_planned": success[attack] / 450,
                    "asr_judged": success[attack] / judged[attack] if judged[attack] else None,
                    "completion_rate": judged[attack] / 450,
                }
                for attack in sorted({str(case["attack_type"]) for case in cases})
            },
        }
    (RESULTS / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    print(json.dumps(finalize(require_complete=not args.allow_incomplete), ensure_ascii=False, indent=2, sort_keys=True))
