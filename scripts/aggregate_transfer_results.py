from __future__ import annotations

"""Validate and aggregate transferability JSONL runs without inventing metrics."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def _records(paths: list[Path]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for path in paths:
        output.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    return output


def aggregate(paths: list[Path], out_dir: Path) -> dict[str, Any]:
    records = _records(paths)
    seen: set[tuple[str, str, int]] = set()
    buckets: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"trials": 0, "successes": 0, "errors": 0, "llm_calls": 0})
    for record in records:
        transfer = record.get("transfer", {})
        target = str(transfer.get("split_id", record.get("details", {}).get("metrics", {}).get("transfer_target", "unknown")))
        key = (target, str(record["case_id"]), int(record["trial_index"]))
        if key in seen:
            raise ValueError(f"Duplicate trial in transfer inputs: {key}")
        seen.add(key)
        attack = str(record.get("details", {}).get("attack_type", "unknown"))
        bucket = buckets[(target, attack)]
        bucket["trials"] += 1
        bucket["successes"] += int(bool(record.get("success")))
        bucket["errors"] += int(bool(record.get("errors")))
        bucket["llm_calls"] += int(record.get("details", {}).get("metrics", {}).get("llm_calls", 0))
    rows = []
    for (target, attack), values in sorted(buckets.items()):
        rows.append({"target": target, "attack": attack, **values, "asr": values["successes"] / values["trials"] if values["trials"] else 0.0, "error_rate": values["errors"] / values["trials"] if values["trials"] else 0.0})
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "by_attack.csv").open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0]) if rows else ["target", "attack", "trials", "successes", "errors", "llm_calls", "asr", "error_rate"])
        writer.writeheader(); writer.writerows(rows)
    summary = {"trials": len(records), "targets": sorted({row["target"] for row in rows}), "by_attack": rows}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path("results/transfer"))
    args = parser.parse_args()
    print(json.dumps(aggregate(args.inputs, args.out_dir), indent=2))
