from __future__ import annotations

from harness.transfer_native.contracts import NativeExecution, NativeEvent
from harness.transfer_native.nlip.adapter import NLIPNativeAdapter
from harness.transfer_native.nlip.codecs import b3_gate_passes


class FakeEnvironment:
    def __init__(self, case): self.case = case
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def execute(self, decision):
        return NativeExecution("nlip", self.case["attack_type"], [NativeEvent("nlip_sdk_message_constructed", "nlip", {})], {})


def test_nlip_adapter_uses_native_environment() -> None:
    adapter = NLIPNativeAdapter(require_native_sdk=False, environment_factory=FakeEnvironment)
    execution = adapter.execute({"attack_type": "C1"}, {"should_send": True})
    assert execution.events[0].event_type == "nlip_sdk_message_constructed"


def test_nlip_b3_gate_fails_without_sdk_websocket_cbor_paths() -> None:
    assert b3_gate_passes() is False
