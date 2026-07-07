from __future__ import annotations

import importlib

import requests

from harness.carddiff_env import A2A_CONTENT_TYPE, LocalCardDiffEnvironment


def test_carddiff_environment_exposes_a2a_http_json_endpoints() -> None:
    module = importlib.import_module("attacks.instances.carddiff")
    case = getattr(module, "CardDiff001")()

    with LocalCardDiffEnvironment(case.metadata, trial_index=0) as env:
        base_url = env.public_view["agent_base_url"]
        public_response = requests.get(f"{base_url}/.well-known/agent-card.json", timeout=5)
        assert public_response.status_code == 200
        assert public_response.headers["Content-Type"].startswith(A2A_CONTENT_TYPE)
        public_card = public_response.json()
        assert public_card["capabilities"]["extendedAgentCard"] is True

        extended_response = requests.get(
            f"{base_url}/extendedAgentCard",
            headers={"Authorization": "Bearer carddiff-token-normal"},
            timeout=5,
        )
        assert extended_response.status_code == 200
        extended_card = extended_response.json()
        interface = extended_card["supportedInterfaces"][0]

        message_response = requests.post(
            f"{interface['url']}/message:send",
            json={
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": env.public_view["task"]}],
                    "messageId": "test-message",
                    "tenant": interface["tenant"],
                },
                "configuration": {"acceptedOutputModes": ["application/json"]},
                "metadata": {
                    "skillId": extended_card["skills"][0]["id"],
                    "cardScopeUsed": "extended",
                },
            },
            headers={
                "Authorization": "Bearer carddiff-token-normal",
                "Content-Type": A2A_CONTENT_TYPE,
                "A2A-Version": interface["protocolVersion"],
            },
            timeout=5,
        )
        assert message_response.status_code == 200
        task = message_response.json()
        assert task["kind"] == "task"
        assert task["artifacts"]

        event_types = {event["event_type"] for event in env.events}
        assert "agent_card_fetched" in event_types
        assert "extended_agent_card_fetched" in event_types
        assert "message_sent" in event_types
        assert "artifact_returned" in event_types

