from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


EXPECTED_COUNTS = {"A1": 85, "A2": 90, "A3": 90, "B1": 87, "B3": 90, "C1": 89, "C2": 90}


def read_jsonl(paths: Iterable[Path]) -> dict[str, dict[str, Any]]:
    reconciled: dict[str, dict[str, Any]] = {}
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            case_id = value.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError(f"{path}:{line_number}: missing case_id")
            reconciled[case_id] = value
    return reconciled


def validate_distribution(cases: list[dict[str, Any]], strict: bool = True) -> None:
    counts = {attack: 0 for attack in EXPECTED_COUNTS}
    ids: set[str] = set()
    for case in cases:
        case_id = str(case["case_id"])
        if case_id in ids:
            raise ValueError(f"Duplicate case ID: {case_id}")
        ids.add(case_id)
        counts[str(case["attack_type"])] += 1
        sdk = case.get("sdk_evidence", {})
        if sdk and (not all(sdk.get(k) for k in ("resolver_used", "client_factory_used", "sdk_message_used", "sdk_server_used")) or sdk.get("fallback_used")):
            raise ValueError(f"SDK evidence failure: {case_id}")
    if strict and counts != EXPECTED_COUNTS:
        raise ValueError(f"Triggered distribution mismatch: expected {EXPECTED_COUNTS}, got {counts}")


def load_manifest(path: Path, strict: bool = True) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, dict) else payload
    if not isinstance(cases, list):
        raise ValueError("Downstream manifest must be a list or an object containing 'cases'.")
    validate_distribution(cases, strict=strict)
    return cases
