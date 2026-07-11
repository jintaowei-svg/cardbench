from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.downstream.trace_loader import EXPECTED_COUNTS


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    impacts = defaultdict(int)
    by_domain: dict[str, dict[str, int]] = defaultdict(lambda: {"triggered": 0, "impact": 0})
    by_variant: dict[str, dict[str, int]] = defaultdict(lambda: {"triggered": 0, "impact": 0})
    for row in records:
        impacts[row["attack_type"]] += int(bool(row["impact_success"]))
        for bucket, key in ((by_domain, row["scenario"]), (by_variant, row["variant"])):
            bucket[key]["triggered"] += 1; bucket[key]["impact"] += int(bool(row["impact_success"]))
    by_attack = {attack: {"triggered": count, "impact": impacts[attack],
                          "dir": impacts[attack] / count} for attack, count in EXPECTED_COUNTS.items()}
    total_impact = sum(impacts.values())
    return {"metric": "DIR", "fixed_denominator": sum(EXPECTED_COUNTS.values()),
            "impact": total_impact, "dir": total_impact / sum(EXPECTED_COUNTS.values()),
            "by_attack": by_attack, "by_domain": dict(by_domain), "by_variant": dict(by_variant)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("details", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    records = [json.loads(x) for x in args.details.read_text(encoding="utf-8").splitlines() if x.strip()]
    result = summarize(records)
    target = args.out or args.details.with_name("summary.json")
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
