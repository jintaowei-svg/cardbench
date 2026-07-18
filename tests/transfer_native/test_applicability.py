from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_applicability_is_frozen_without_pending_gates() -> None:
    data = json.loads((ROOT / "attacks/carddiff/transfer_native/applicability.json").read_text(encoding="utf-8"))
    assert data["frozen"] is True
    assert "pending_native_gate" not in json.dumps(data)
    assert data["anp"]["A2"] == "applicable"
    assert data["anp"]["C2"] == "not_applicable"
    assert data["nlip"]["B2"] == "not_applicable"


def test_not_applicable_attacks_have_no_trials() -> None:
    for protocol in ("anp", "nlip"):
        applicability = json.loads((ROOT / "attacks/carddiff/transfer_native/applicability.json").read_text(encoding="utf-8"))
        manifest = json.loads((ROOT / f"attacks/carddiff/transfer_native/{protocol}_cases.json").read_text(encoding="utf-8"))
        attacks = {case["attack_type"] for case in manifest["cases"]}
        assert all(applicability[protocol][attack] == "applicable" for attack in attacks)
