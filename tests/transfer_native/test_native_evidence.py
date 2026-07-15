from __future__ import annotations

from harness.transfer_native.contracts import NativeEvent
from harness.transfer_native.evidence import required_events, validate_native_evidence


def test_evidence_validation_fails_closed() -> None:
    names = required_events("anp", "A3")
    events = [NativeEvent(name, "anp", {}) for name in names]
    assert validate_native_evidence("anp", "A3", events) == (True, [])
    valid, missing = validate_native_evidence("anp", "A3", events[:-1])
    assert valid is False and len(missing) == 1


def test_nlip_b3_requires_extra_wire_events() -> None:
    assert required_events("nlip", "B3") > required_events("nlip", "C1")
