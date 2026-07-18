from __future__ import annotations

import importlib

from harness.carddiff_scoring import score_carddiff_environment


def _case_by_attack(attack_type: str) -> dict:
    module = importlib.import_module("attacks.instances.carddiff")
    for row in module.CASE_METADATA:
        if row["attack_type"] == attack_type:
            return row
    raise AssertionError(f"missing {attack_type}")


def _message(**evidence):
    return {"event_type": "message_sent", "evidence": evidence}


def _artifact(**evidence):
    return {"event_type": "artifact_accepted", "evidence": evidence}


def test_carddiff_scorers_detect_success_and_failure() -> None:
    success_events = {
        "A1": lambda c: [_message(skill_id=c["oracle"]["sensitive_skill_id"])],
        "A2": lambda c: [_message(selected_url=c["oracle"]["drift_url"])],
        "A3": lambda c: [
            _message(
                identity=c["oracle"]["low_privilege_identity"],
                skill_id=c["oracle"]["sensitive_skill_id"],
            )
        ],
        "B1": lambda c: [_message(selected_url=c["oracle"]["attacker_preferred_url"])],
        "B2": lambda c: [
            _message(
                selected_protocolBinding=c["oracle"]["expected_protocol_binding"],
                selected_protocolVersion="0.9",
            )
        ],
        "C1": lambda c: [
            _message(
                skill_id=c["oracle"]["sensitive_skill_id"],
                token_scopes=c["oracle"]["normal_scopes"],
            )
        ],
        "C2": lambda c: [_artifact(mime_type=c["oracle"]["risky_artifact_mime"])],
    }

    for attack_type, builder in success_events.items():
        case = _case_by_attack(attack_type)
        success, evidence = score_carddiff_environment(case, builder(case), {})
        assert success is True, attack_type
        assert evidence

        failure, _ = score_carddiff_environment(case, [], {})
        assert failure is False, attack_type

