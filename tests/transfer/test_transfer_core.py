from __future__ import annotations

import json
from pathlib import Path

from attacks.instances.carddiff_perturbed import CardDiffPerturbed001
from harness.transfer.official_a2a_env import OfficialSDKCardDiffEnvironment
from sut.transfer.common_llm import to_canonical_decision_view
from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT


ROOT = Path(__file__).resolve().parents[2]


def _first_choice(**kwargs: object) -> str:
    view = json.loads(str(kwargs["user"]))
    return json.dumps({"should_send": True, "capability_id": view["capabilities"][0]["id"], "interface_index": 1, "accept_output": True, "final_status": "completed", "reason": "smoke"})


def test_balanced_manifests_are_generated() -> None:
    expected = {"official_a2a_720": 720, "anp_540": 540, "langgraph_270": 270}
    for split, count in expected.items():
        data = json.loads((ROOT / "attacks/carddiff/transfer/splits" / f"{split}.json").read_text(encoding="utf-8"))
        assert len(data["cases"]) == count
        assert len({case["case_id"] for case in data["cases"]}) == count


def test_canonical_view_cannot_include_private_case_fields() -> None:
    view = to_canonical_decision_view({"task": "x", "attack_type": "A1", "oracle": {"expected_x": "secret"}, "expected_value": "secret"})
    encoded = json.dumps(view)
    assert "attack_type" not in encoded and "oracle" not in encoded and "expected_value" not in encoded


def test_transfer_auth_context_exposes_only_granted_scopes() -> None:
    case = CardDiffPerturbed001()
    with OfficialSDKCardDiffEnvironment(case.metadata, 0, remote_agent_mode="deterministic") as env:
        encoded = json.dumps(env.public_view, sort_keys=True)
        auth_step = env.public_view["auth_sequence"][0]
        assert auth_step["identity"] == "normal_user"
        assert auth_step["token_scopes"] == ["travel.read"]
        assert "attack_type" not in encoded
        assert "oracle" not in encoded
        assert "expected_" not in encoded


def test_transfer_environment_factory_and_one_call_smoke() -> None:
    case = CardDiffPerturbed001()
    host = OfficialSDKCardDiffHostSUT(decision_callable=_first_choice)
    outcome = case.run(host, environment={"factory": "harness.transfer.official_a2a_env:OfficialSDKCardDiffEnvironment", "kwargs": {"remote_agent_mode": "deterministic"}})
    assert outcome.errors == []
    assert outcome.details["metrics"]["llm_calls"] == 1
    assert any(event["event_type"] == "a2a_sdk_message_sent" for event in outcome.details["events"])
