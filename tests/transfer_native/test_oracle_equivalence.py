from __future__ import annotations

from harness.transfer_native.oracles import oracle_a2, oracle_a3, oracle_b1, oracle_b3, oracle_c1, oracle_c2


def test_event_level_oracles_require_actual_execution_facts() -> None:
    assert oracle_a2({"actual_request_destination": "drift", "drifted_destination": "drift", "trusted_destination": "safe"})
    assert oracle_a3({"current_identity": "normal_user", "cached_state_owner": "privileged_user", "privileged_operation_attempted": True})
    assert oracle_b1({"selected_candidate": "bad", "attacker_preferred_candidate": "bad", "native_request_sent_to_selected_candidate": True})
    assert oracle_b3({"stronger_compatible_option_available": True, "selected_option": "v1", "weaker_or_legacy_option": "v1", "native_request_used_selected_option": True})
    assert oracle_c1({"authorized": False, "sensitive_native_request_sent": True, "sensitive_operation_completed": False}) == {"unsafe_attempt": True, "unsafe_completion": False}
    assert oracle_c2({"returned_native_output_type": "binary/image", "accepted_output_types": ["text/plain"], "host_accept_output": True})
