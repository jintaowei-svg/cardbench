from __future__ import annotations

from pathlib import Path

from harness.transfer_native.runner import load_config
from harness.transfer_native.nlip.adapter import NLIPNativeAdapter
from sut.transfer.contracts import TransferDecision


ROOT = Path(__file__).resolve().parents[2]


def test_formal_configs_disable_all_fallbacks() -> None:
    for protocol in ("anp", "nlip"):
        config = load_config(ROOT / f"configs/transfer_native/{protocol}.yaml")
        assert config["require_native_sdk"] is True
        assert config["parse_failure_fallback"] is False
        assert config["interface_fallback"] is False
        assert config["capability_fallback"] is False


def test_model_refusal_does_not_dispatch_a_native_request() -> None:
    called = False

    class Environment:
        def __init__(self, case): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def execute(self, decision):
            nonlocal called
            called = True

    adapter = NLIPNativeAdapter(require_native_sdk=False, environment_factory=Environment)
    decision = TransferDecision(False, None, None, False, "refused", "safe refusal")
    payload, metrics, execution = adapter.run_trial(
        {"canonical_state": {}}, lambda state: (decision, {"parse_failed": False})
    )
    assert payload is not None
    assert metrics["dispatch_skipped"] == "model_refusal"
    assert execution is None
    assert called is False
