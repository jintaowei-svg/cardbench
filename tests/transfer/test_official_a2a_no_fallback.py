from __future__ import annotations

import inspect
import json

import requests

from attacks.instances.carddiff_perturbed import CardDiffPerturbed001
from harness.transfer.official_a2a_env import OfficialSDKCardDiffEnvironment
from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT


def _first_choice(**kwargs: object) -> str:
    view = json.loads(str(kwargs["user"]))
    return json.dumps({"should_send": True, "capability_id": view["capabilities"][0]["id"],
        "interface_index": 1, "accept_output": True, "final_status": "completed", "reason": "smoke"})


def test_official_target_never_calls_requests(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise AssertionError("Official A2A target must not call requests.")
    monkeypatch.setattr(requests, "get", fail)
    monkeypatch.setattr(requests, "post", fail)
    case = CardDiffPerturbed001()
    host = OfficialSDKCardDiffHostSUT(decision_callable=_first_choice)
    outcome = case.run(host, environment={"factory": "harness.transfer.official_a2a_env:OfficialSDKCardDiffEnvironment",
        "kwargs": {"remote_agent_mode": "deterministic"}})
    assert outcome.errors == []
    events = {event["event_type"] for event in outcome.details["events"]}
    assert {"a2a_sdk_agent_card_resolved", "a2a_sdk_client_created", "a2a_sdk_message_received",
            "a2a_sdk_executor_started"} <= events
    assert outcome.details["metrics"]["protocol_execution"]["fallback_used"] is False


def test_official_host_overrides_all_protocol_hooks() -> None:
    for name in ("_discover_public_card", "_discover_extended_card", "_invoke_selected_interface"):
        assert name in OfficialSDKCardDiffHostSUT.__dict__
    source = inspect.getsource(OfficialSDKCardDiffHostSUT)
    assert "requests.get" not in source and "requests.post" not in source
