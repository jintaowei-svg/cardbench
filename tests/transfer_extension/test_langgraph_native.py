from __future__ import annotations

import json
from pathlib import Path

from harness.transfer_framework.langgraph.adapter import LangGraphFrameworkAdapter
from sut.transfer_native.common_host import NativeTransferHost


ROOT = Path(__file__).resolve().parents[2]


def _case(attack: str) -> dict:
    manifest = json.loads(
        (ROOT / "attacks/carddiff/transfer_framework/langgraph_cases.json").read_text(
            encoding="utf-8"
        )
    )
    return next(item for item in manifest["cases"] if item["attack_type"] == attack)


def _run(case: dict, capability: str):
    def decision(**_: object) -> str:
        return json.dumps(
            {
                "should_send": True,
                "capability_id": capability,
                "interface_index": 1,
                "accept_output": True,
                "final_status": "completed",
                "reason": "deterministic test",
            }
        )

    host = NativeTransferHost(
        LangGraphFrameworkAdapter(), decision_callable=decision, max_retries=0
    )
    return host.run(case)


def test_langgraph_a3_uses_two_decisions_and_real_checkpoint_resume() -> None:
    case = _case("A3")
    _, metrics, execution = _run(case, case["native"]["sensitive_capability"])
    assert metrics["llm_calls"] == 2
    assert execution.facts == {
        "current_identity": "normal_user",
        "cached_state_owner": "privileged_user",
        "privileged_operation_attempted": True,
    }


def test_langgraph_b1_routes_through_conditional_edge() -> None:
    case = _case("B1")
    _, _, execution = _run(case, case["native"]["attacker_preferred_candidate"])
    assert execution.facts["selected_candidate"] == case["native"][
        "attacker_preferred_candidate"
    ]


def test_langgraph_c1_denies_completion_after_sensitive_dispatch() -> None:
    case = _case("C1")
    _, _, execution = _run(case, case["native"]["sensitive_capability"])
    assert execution.facts["sensitive_native_request_sent"] is True
    assert execution.facts["authorized"] is False
    assert execution.facts["sensitive_operation_completed"] is False


def test_langgraph_c2_emits_native_multimodal_message() -> None:
    case = _case("C2")
    capability = case["canonical_state"]["capabilities"][0]["id"]
    _, _, execution = _run(case, capability)
    assert execution.facts["returned_native_output_type"] == "image/png"
    assert execution.response["message_type"] == "AIMessage"
