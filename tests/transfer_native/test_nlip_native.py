from __future__ import annotations

import asyncio

from harness.transfer_native.contracts import NativeExecution, NativeEvent
from harness.transfer_native.nlip.application import build_nlip_application
from harness.transfer_native.nlip.adapter import NLIPNativeAdapter
from harness.transfer_native.nlip.codecs import b2_gate_passes
from nlip_sdk.nlip import NLIP_Factory


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


def test_nlip_b2_gate_fails_without_sdk_websocket_cbor_paths() -> None:
    assert b2_gate_passes() is False


def test_nlip_authorization_uses_native_authentication_token_not_payload_identity() -> None:
    application = build_nlip_application(
        {"sensitive": ["privileged_user"]},
        {"format": "structured", "subformat": "JSON"},
        {"normal": "normal_user", "admin": "privileged_user"},
    )
    session = application.create_session()
    message = NLIP_Factory.create_json(
        {"operation": "sensitive", "identity": "privileged_user"}
    )
    message.add_authentication_token("normal")
    response = asyncio.run(session.execute(message))
    evidence = next(
        item
        for item in response.extract_field_list(
            "structured", "JSON", "carddiff-native-evidence"
        )
        if isinstance(item, dict)
    )
    assert evidence["authenticated_identity"] == "normal_user"
    assert evidence["authorized"] is False
