from __future__ import annotations

from harness.transfer_framework.evidence import required_events as framework_events
from harness.transfer_native.evidence import required_events as native_events


def test_agntcy_evidence_covers_directory_discovery_and_a2a_execution() -> None:
    required = native_events("agntcy", "A2")
    assert {"agntcy_record_pushed", "agntcy_record_discovered", "agntcy_record_pulled"} <= required
    assert {"agntcy_a2a_sdk_request_sent", "agntcy_a2a_peer_handler_completed"} <= required


def test_autogen_attack_specific_native_events_are_registered() -> None:
    assert "autogen_state_loaded" in framework_events("autogen", "A3")
    assert "autogen_selector_applied" in framework_events("autogen", "B1")
    assert "autogen_sensitive_message_sent" in framework_events("autogen", "C1")
    assert "autogen_output_message_emitted" in framework_events("autogen", "C2")


def test_langgraph_attack_specific_native_events_are_registered() -> None:
    assert "langgraph_checkpoint_resumed" in framework_events("langgraph", "A3")
    assert "langgraph_conditional_route_evaluated" in framework_events("langgraph", "B1")
    assert "langgraph_sensitive_action_entered" in framework_events("langgraph", "C1")
    assert "langgraph_multimodal_message_emitted" in framework_events("langgraph", "C2")
