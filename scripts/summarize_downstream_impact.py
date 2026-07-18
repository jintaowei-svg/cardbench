from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def _bucket(rows: list[dict[str, Any]], planned: int | None = None) -> dict[str, Any]:
    completed = len(rows)
    impact = sum(bool(row.get("impact_success")) for row in rows)
    with_tools = sum(bool(row.get("worker_tool_calls")) for row in rows)
    model_completed = sum(int(row.get("worker_model_calls", 0)) > 0 for row in rows)
    errors = sum(bool(row.get("errors")) for row in rows)
    impact_types = Counter(
        impact_type for row in rows for impact_type in row.get("impact_type", [])
    )
    return {
        "planned": planned if planned is not None else completed,
        "completed": completed,
        "impact": impact,
        "dir": impact / completed if completed else None,
        "model_completion_rate": model_completed / completed if completed else None,
        "tool_call_rate": with_tools / completed if completed else None,
        "errors": errors,
        "impact_types": dict(sorted(impact_types.items())),
    }


def summarize(
    records: list[dict[str, Any]],
    expected_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    expected = expected_counts or dict(Counter(row["attack_type"] for row in records))
    by_attack = {
        attack: _bucket(
            [row for row in records if row["attack_type"] == attack], planned=int(planned)
        )
        for attack, planned in expected.items()
    }
    grouped_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_variant: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        grouped_domain[str(row["scenario"])].append(row)
        grouped_variant[str(row["variant"])].append(row)
    overall = _bucket(records, planned=sum(expected.values()))
    final = all(by_attack[attack]["completed"] == int(planned) for attack, planned in expected.items())
    return {
        "metric": "conditional_DIR",
        "final": final,
        "planned_denominator": sum(expected.values()),
        "completed_denominator": len(records),
        "impact": overall["impact"],
        "dir": overall["dir"],
        "model_completion_rate": overall["model_completion_rate"],
        "tool_call_rate": overall["tool_call_rate"],
        "errors": overall["errors"],
        "impact_types": overall["impact_types"],
        "by_attack": by_attack,
        "by_domain": {key: _bucket(rows) for key, rows in sorted(grouped_domain.items())},
        "by_variant": {key: _bucket(rows) for key, rows in sorted(grouped_variant.items())},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("details", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    records = [
        json.loads(line)
        for line in args.details.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]
    result = summarize(records)
    target = args.out or args.details.with_name("summary.json")
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
