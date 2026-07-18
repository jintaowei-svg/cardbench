from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from harness.transfer_framework.contracts import FrameworkEvent


AUTOGEN_REQUIRED_EVENTS = frozenset(
    {
        "autogen_runtime_started",
        "autogen_agents_registered",
        "autogen_native_message_constructed",
        "autogen_message_dispatched",
        "autogen_agent_handler_started",
        "autogen_agent_handler_completed",
        "autogen_response_observed",
    }
)
AUTOGEN_ATTACK_EVENTS = {
    "A3": frozenset(
        {"autogen_state_saved", "autogen_state_loaded", "autogen_identity_rebound"}
    ),
    "B1": frozenset(
        {
            "autogen_candidate_list_built",
            "autogen_selector_applied",
            "autogen_selected_agent_observed",
        }
    ),
    "C1": frozenset(
        {"autogen_trusted_policy_loaded", "autogen_sensitive_message_sent"}
    ),
    "C2": frozenset(
        {"autogen_output_message_emitted", "autogen_output_policy_applied"}
    ),
}

LANGGRAPH_REQUIRED_EVENTS = frozenset(
    {
        "langgraph_runtime_started",
        "langgraph_graph_compiled",
        "langgraph_graph_invoked",
        "langgraph_node_started",
        "langgraph_node_completed",
    }
)
LANGGRAPH_ATTACK_EVENTS = {
    "A3": frozenset(
        {
            "langgraph_checkpoint_saved",
            "langgraph_checkpoint_resumed",
            "langgraph_identity_rebound",
        }
    ),
    "B1": frozenset(
        {
            "langgraph_conditional_route_evaluated",
            "langgraph_selected_node_observed",
        }
    ),
    "C1": frozenset(
        {
            "langgraph_sensitive_action_entered",
            "langgraph_authorization_policy_applied",
        }
    ),
    "C2": frozenset(
        {
            "langgraph_multimodal_message_emitted",
            "langgraph_output_policy_applied",
        }
    ),
}


@dataclass
class FrameworkEvidenceRecorder:
    framework: str
    _events: list[FrameworkEvent] = field(default_factory=list)

    def record(self, event_type: str, **evidence: Any) -> None:
        self._events.append(
            FrameworkEvent(event_type, "framework", self.framework, dict(evidence))
        )

    @property
    def events(self) -> list[FrameworkEvent]:
        return list(self._events)


def required_events(framework: str, attack_type: str) -> frozenset[str]:
    if framework == "autogen":
        return AUTOGEN_REQUIRED_EVENTS | AUTOGEN_ATTACK_EVENTS.get(
            attack_type, frozenset()
        )
    if framework == "langgraph":
        return LANGGRAPH_REQUIRED_EVENTS | LANGGRAPH_ATTACK_EVENTS.get(
            attack_type, frozenset()
        )
    raise ValueError(f"Unsupported framework transfer target: {framework}")


def validate_framework_evidence(
    framework: str,
    attack_type: str,
    events: Iterable[FrameworkEvent | dict[str, Any]],
) -> tuple[bool, list[str]]:
    observed = {
        event.event_type if isinstance(event, FrameworkEvent) else str(event.get("event_type", ""))
        for event in events
    }
    missing = sorted(required_events(framework, attack_type) - observed)
    return not missing, missing
