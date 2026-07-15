from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from harness.transfer_native.contracts import NativeEvent


ANP_REQUIRED_EVENTS = frozenset(
    {
        "anp_agent_description_fetched",
        "anp_agent_description_parsed",
        "anp_identity_resolved",
        "anp_interface_document_fetched",
        "anp_openrpc_parsed",
        "anp_jsonrpc_request_constructed",
        "anp_client_request_sent",
        "anp_server_handler_started",
        "anp_server_handler_completed",
        "anp_response_decoded",
    }
)

NLIP_REQUIRED_EVENTS = frozenset(
    {
        "nlip_session_created_or_resumed",
        "nlip_identity_bound",
        "nlip_sdk_message_constructed",
        "nlip_sdk_message_serialized",
        "nlip_client_request_sent",
        "nlip_server_message_decoded",
        "nlip_application_handler_started",
        "nlip_application_handler_completed",
        "nlip_response_serialized",
        "nlip_client_response_decoded",
        "nlip_output_policy_applied",
    }
)

NLIP_B3_REQUIRED_EVENTS = frozenset(
    {
        "nlip_binding_selected",
        "nlip_codec_selected",
        "nlip_frame_sent",
        "nlip_codec_decoded",
    }
)


@dataclass
class EvidenceRecorder:
    protocol: str
    _events: list[NativeEvent] = field(default_factory=list)

    def record(self, event_type: str, **evidence: Any) -> None:
        self._events.append(NativeEvent(event_type, self.protocol, dict(evidence)))

    @property
    def events(self) -> list[NativeEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()


def required_events(protocol: str, attack_type: str) -> frozenset[str]:
    if protocol == "anp":
        return ANP_REQUIRED_EVENTS
    if protocol == "nlip":
        required = set(NLIP_REQUIRED_EVENTS)
        if attack_type == "B3":
            required.update(NLIP_B3_REQUIRED_EVENTS)
        return frozenset(required)
    raise ValueError(f"Unsupported native transfer protocol: {protocol}")


def validate_native_evidence(
    protocol: str, attack_type: str, events: Iterable[NativeEvent | dict[str, Any]]
) -> tuple[bool, list[str]]:
    observed = {
        event.event_type if isinstance(event, NativeEvent) else str(event.get("event_type", ""))
        for event in events
    }
    missing = sorted(required_events(protocol, attack_type) - observed)
    return not missing, missing
