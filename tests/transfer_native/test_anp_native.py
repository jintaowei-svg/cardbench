from __future__ import annotations

from harness.transfer_native.anp.adapter import ANPNativeAdapter
from harness.transfer_native.contracts import NativeExecution, NativeEvent


class FakeEnvironment:
    def __init__(self, case): self.case = case
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def execute(self, decision):
        return NativeExecution("anp", self.case["attack_type"], [NativeEvent("anp_client_request_sent", "anp", {})], {})


def test_anp_adapter_uses_environment_not_transfer_host_base() -> None:
    adapter = ANPNativeAdapter(require_native_sdk=False, environment_factory=FakeEnvironment)
    execution = adapter.execute({"attack_type": "A3"}, {"should_send": True})
    assert execution.protocol == "anp"
    assert execution.events[0].event_type == "anp_client_request_sent"
