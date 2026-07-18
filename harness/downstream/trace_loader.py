from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ATTACKS = ("A1", "A2", "A3", "B1", "B2", "C1", "C2")
SOURCE_COUNTS = {attack: 450 for attack in ATTACKS}
EXPECTED_COUNTS = {"A1": 85, "A2": 90, "A3": 90, "B1": 87, "B2": 90, "C1": 89, "C2": 90}


def read_jsonl(paths: Iterable[Path]) -> dict[str, dict[str, Any]]:
    reconciled: dict[str, dict[str, Any]] = {}
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            case_id = value.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError(f"{path}:{line_number}: missing case_id")
            reconciled[case_id] = value
    return reconciled


def validate_distribution(
    cases: list[dict[str, Any]],
    expected_counts: dict[str, int] | None = None,
    *,
    allow_reconstructed: bool = False,
) -> None:
    counts = Counter(str(case.get("attack_type")) for case in cases)
    unknown = set(counts) - set(ATTACKS)
    if unknown:
        raise ValueError(f"Unknown downstream attacks: {sorted(unknown)}")
    ids = [str(case.get("case_id") or "") for case in cases]
    if not all(ids) or len(ids) != len(set(ids)):
        raise ValueError("Downstream manifest contains missing or duplicate case IDs.")
    reconstructed = [
        case["case_id"] for case in cases
        if case.get("decision_source") != "recorded_trace"
    ]
    if reconstructed and not allow_reconstructed:
        raise ValueError(
            "Formal downstream replay accepts recorded traces only; "
            f"found {len(reconstructed)} reconstructed decisions."
        )
    if expected_counts is not None and counts != Counter(expected_counts):
        raise ValueError(
            f"Triggered distribution mismatch: expected {expected_counts}, got {dict(counts)}"
        )


def load_manifest_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("Downstream manifest must be an object containing a cases list.")
    expected = {str(k): int(v) for k, v in payload.get("expected_counts", {}).items()}
    validate_distribution(
        payload["cases"],
        expected or None,
        allow_reconstructed=payload.get("mode") == "decision_replay",
    )
    return payload


def load_manifest(path: Path) -> list[dict[str, Any]]:
    return list(load_manifest_payload(path)["cases"])
