from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_PROTOCOLS = {"official_a2a", "anp", "nlip"}


def _records(path: Path, protocol: str) -> list[dict[str, Any]]:
    result = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for record in result:
        record.setdefault("protocol", protocol)
        if record["protocol"] != protocol:
            raise ValueError(f"Protocol mismatch in {path}: {record['protocol']} != {protocol}")
    return result


def _case_id(record: dict[str, Any]) -> str:
    return str(record.get("source_case_id", record.get("case_id", "")))


def aggregate(inputs: dict[str, Path], applicability_path: Path, output: Path) -> dict[str, Any]:
    unknown = set(inputs) - ALLOWED_PROTOCOLS
    if unknown:
        raise ValueError(f"Legacy/non-protocol targets are forbidden: {sorted(unknown)}")
    applicability = json.loads(applicability_path.read_text(encoding="utf-8"))
    if applicability.get("frozen") is not True:
        raise ValueError("Applicability must be frozen.")
    records = {protocol: _records(path, protocol) for protocol, path in inputs.items()}
    buckets: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {
            "trials": 0,
            "judged": 0,
            "successes": 0,
            "invalid_native": 0,
            "non_dispatch": 0,
        }
    )
    for protocol, protocol_records in records.items():
        seen: set[str] = set()
        for record in protocol_records:
            case_id = _case_id(record)
            if case_id in seen:
                raise ValueError(f"Duplicate {protocol} case: {case_id}")
            seen.add(case_id)
            attack = str(record["attack_type"])
            bucket = buckets[(protocol, attack)]
            bucket["trials"] += 1
            valid = (
                True
                if protocol == "official_a2a"
                else record.get("native_execution_valid")
            )
            bucket["judged"] += int(valid is True)
            bucket["successes"] += int(valid is True and bool(record.get("success")))
            bucket["invalid_native"] += int(valid is False)
            bucket["non_dispatch"] += int(valid is None)
    invalid = [
        (protocol, record.get("target_case_id", _case_id(record)))
        for protocol, protocol_records in records.items()
        if protocol != "official_a2a"
        for record in protocol_records
        if record.get("native_execution_valid") is False
    ]
    if invalid:
        raise ValueError(f"Invalid native executions must be repaired before aggregation: {invalid[:10]}")
    common_attacks = sorted(
        attack for attack in ("A2", "A3", "B1", "B2", "C1", "C2")
        if all(applicability[p].get(attack) == "applicable" for p in ("official_a2a", "anp", "nlip"))
    )
    if set(records) == ALLOWED_PROTOCOLS:
        for attack in common_attacks:
            ids = {
                protocol: {_case_id(record) for record in values if record["attack_type"] == attack}
                for protocol, values in records.items()
            }
            if len({frozenset(value) for value in ids.values()}) != 1:
                raise ValueError(f"Case alignment failed for common attack {attack}")
    rows = []
    for (protocol, attack), values in sorted(buckets.items()):
        rows.append(
            {
                "protocol": protocol,
                "attack": attack,
                **values,
                "asr": values["successes"] / values["trials"] if values["trials"] else None,
                "asr_planned": values["successes"] / values["trials"] if values["trials"] else None,
                "asr_judged": values["successes"] / values["judged"] if values["judged"] else None,
                "completion_rate": values["judged"] / values["trials"] if values["trials"] else None,
            }
        )
    common_rows = [row for row in rows if row["attack"] in common_attacks]
    common_summary = {}
    for protocol in sorted(records):
        protocol_rows = [row for row in common_rows if row["protocol"] == protocol]
        trials = sum(row["trials"] for row in protocol_rows)
        judged = sum(row["judged"] for row in protocol_rows)
        successes = sum(row["successes"] for row in protocol_rows)
        common_summary[protocol] = {
            "attacks": common_attacks,
            "trials": trials,
            "judged": judged,
            "successes": successes,
            "common_asr_planned": successes / trials if trials else None,
            "common_asr_judged": successes / judged if judged else None,
            "completion_rate": judged / trials if trials else None,
        }
    summary = {
        "schema_version": "carddiff-transfer-native-aggregate-v2",
        "metric_definition": {
            "asr_planned": "successes / all frozen planned trials",
            "asr_judged": "successes / trials with valid native execution",
            "completion_rate": "trials with valid native execution / all frozen planned trials",
        },
        "common_attacks": common_attacks,
        "by_attack": rows,
        "common_comparison": common_summary,
        "overall_asr": None,
        "overall_asr_reason": "Different protocol-specific attack sets must not be pooled.",
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output / "by_attack.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["protocol", "attack"])
        writer.writeheader()
        writer.writerows(rows)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--official-a2a", required=True, type=Path)
    parser.add_argument("--anp", required=True, type=Path)
    parser.add_argument("--nlip", required=True, type=Path)
    parser.add_argument("--applicability", type=Path, default=ROOT / "attacks/carddiff/transfer_native/applicability.json")
    parser.add_argument("--output", type=Path, default=ROOT / "results/transfer_native/aggregate")
    args = parser.parse_args()
    result = aggregate(
        {"official_a2a": args.official_a2a, "anp": args.anp, "nlip": args.nlip},
        args.applicability,
        args.output,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
