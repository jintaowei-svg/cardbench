from __future__ import annotations

from copy import deepcopy
import json

import pytest

from attacks.instances.carddiff_perturbed import CardDiffPerturbed001
from harness.transfer.official_a2a_projection import (SDKResolvedCard, build_control_extension,
    build_sdk_agent_card, resolve_control_state)
from sut.transfer.official_a2a_protocol import AgentCard


def test_projection_is_sdk_agent_card_and_preserves_control_fields() -> None:
    raw = deepcopy(CardDiffPerturbed001().metadata["agent"]["public_card"])
    raw = json.loads(json.dumps(raw).replace("{{base_url}}", "http://carddiff.a2a.local"))
    sdk = build_sdk_agent_card(raw, base_url="http://carddiff.a2a.local")
    extension = build_control_extension(raw, sdk, card_scope="public", identity=None)
    resolved = resolve_control_state(sdk, extension, expected_scope="public")
    assert isinstance(sdk, AgentCard)
    assert isinstance(resolved, SDKResolvedCard)
    assert resolved.control_state["supportedInterfaces"] == raw["supportedInterfaces"]
    assert resolved.control_state["skills"] == raw["skills"]


def test_projection_rejects_mismatched_extension_hash() -> None:
    raw = deepcopy(CardDiffPerturbed001().metadata["agent"]["public_card"])
    raw["supportedInterfaces"][0]["url"] = "http://carddiff.a2a.local/a2a/travel"
    sdk = build_sdk_agent_card(raw, base_url="http://carddiff.a2a.local")
    extension = build_control_extension(raw, sdk, card_scope="public", identity=None)
    extension["sdkCardSha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash mismatch"):
        resolve_control_state(sdk, extension)
