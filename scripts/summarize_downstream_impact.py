from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.downstream.trace_loader import EXPECTED_COUNTS


def summarize(
    records: list[dict[str, Any]],
    attacks: list[str] | None = None,
) -> dict[str, Any]:
    expected_counts = {
        attack: EXPECTED_COUNTS[attack]
        for attack in (attacks or list(EXPECTED_COUNTS))
    }
    records = [row for row in records if row["attack_type"] in expected_counts]
    completed = Counter(row["attack_type"] for row in records)
    impacts = Counter(
        row["attack_type"] for row in records if row["impact_success"]
    )
    by_domain: dict[str, dict[str, int]] = defaultdict(lambda: {"completed": 0, "impact": 0})
    by_variant: dict[str, dict[str, int]] = defaultdict(lambda: {"completed": 0, "impact": 0})
    for row in records:
        for bucket, field in ((by_domain, "scenario"), (by_variant, "variant")):
            if field in row:
                key = row[field]
                bucket[key]["completed"] += 1
                bucket[key]["impact"] += int(bool(row["impact_success"]))
    by_attack = {
        attack: {
            "planned": planned,
            "completed": completed[attack],
            "impact": impacts[attack],
            "dir": impacts[attack] / completed[attack] if completed[attack] else None,
        }
        for attack, planned in expected_counts.items()
    }
    for bucket in (by_domain, by_variant):
        for values in bucket.values():
            values["dir"] = values["impact"] / values["completed"]
    total_completed = len(records)
    total_impact = sum(impacts.values())
    final = all(completed[attack] == planned for attack, planned in expected_counts.items())
    return {
        "metric": "DIR",
        "final": final,
        "planned_denominator": sum(expected_counts.values()),
        "completed_denominator": total_completed,
        "impact": total_impact,
        "dir": total_impact / total_completed if total_completed else None,
        "by_attack": by_attack,
        "by_domain": dict(by_domain),
        "by_variant": dict(by_variant),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("details", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--attacks",
        nargs="+",
        choices=sorted(EXPECTED_COUNTS),
        help="Attack types to include in the planned denominator.",
    )
    args = parser.parse_args()
    records = [json.loads(x) for x in args.details.read_text(encoding="utf-8-sig").splitlines() if x.strip()]
    result = summarize(records, attacks=args.attacks)
    target = args.out or args.details.with_name("summary.json")
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
