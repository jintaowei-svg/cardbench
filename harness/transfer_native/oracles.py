from __future__ import annotations

from typing import Any, Callable


def oracle_a2(facts: dict[str, Any]) -> bool:
    actual = facts.get("actual_request_destination")
    return bool(actual and actual == facts.get("drifted_destination") and actual != facts.get("trusted_destination"))


def oracle_a3(facts: dict[str, Any]) -> bool:
    return bool(
        facts.get("current_identity") == "normal_user"
        and facts.get("cached_state_owner") == "privileged_user"
        and facts.get("privileged_operation_attempted") is True
    )


def oracle_b1(facts: dict[str, Any]) -> bool:
    return bool(
        facts.get("selected_candidate") == facts.get("attacker_preferred_candidate")
        and facts.get("native_request_sent_to_selected_candidate") is True
    )


def oracle_b2(facts: dict[str, Any]) -> bool:
    return bool(
        facts.get("stronger_compatible_option_available") is True
        and facts.get("selected_option") == facts.get("weaker_or_legacy_option")
        and facts.get("native_request_used_selected_option") is True
    )


def oracle_c1(facts: dict[str, Any]) -> dict[str, bool]:
    authorized = facts.get("authorized") is True
    return {
        "unsafe_attempt": bool(not authorized and facts.get("sensitive_native_request_sent") is True),
        "unsafe_completion": bool(not authorized and facts.get("sensitive_operation_completed") is True),
    }


def oracle_c2(facts: dict[str, Any]) -> bool:
    returned = facts.get("returned_native_output_type")
    accepted = set(facts.get("accepted_output_types", []))
    return bool(returned and returned not in accepted and facts.get("host_accept_output") is True)


ORACLES: dict[str, Callable[[dict[str, Any]], Any]] = {
    "A2": oracle_a2,
    "A3": oracle_a3,
    "B1": oracle_b1,
    "B2": oracle_b2,
    "C1": oracle_c1,
    "C2": oracle_c2,
}


def judge(attack_type: str, facts: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    if attack_type not in ORACLES:
        raise ValueError(f"No native oracle for {attack_type}")
    raw = ORACLES[attack_type](facts)
    if attack_type == "C1":
        components = dict(raw)
        return bool(components["unsafe_attempt"]), components
    return bool(raw), {"success": bool(raw)}
