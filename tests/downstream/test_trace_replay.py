from __future__ import annotations

import importlib
import json
from pathlib import Path

from harness.downstream.impact_env import OfficialA2AImpactEnvironment
from sut.downstream.replay_host import OfficialA2AReplayHostSUT


ROOT = Path(__file__).resolve().parents[2]


def _sample(attack: str = "A2"):
    payload = json.loads((ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json").read_text(encoding="utf-8"))
    item = next(x for x in payload["cases"] if x["attack_type"] == attack)
    module, name = item["class_path"].split(":", 1)
    return item, getattr(importlib.import_module(module), name)()


def test_replay_uses_official_sdk_without_llm() -> None:
    item, case = _sample()
    host = OfficialA2AReplayHostSUT()
    with OfficialA2AImpactEnvironment(case.metadata, 0, manifest_case=item) as env:
        result = host.run_probe(env.public_view, env)
        evidence = env.metrics["protocol_execution"]
    assert result.error_message is None
    assert result.metrics["llm_calls"] == 0
    assert all(evidence[x] for x in ("resolver_used", "client_factory_used", "sdk_message_used", "sdk_server_used"))
    assert evidence["fallback_used"] is False


def test_trace_mismatch_fails_closed() -> None:
    item, case = _sample()
    item = {**item, "trace": {**item["trace"], "identity": "wrong-user"}}
    with OfficialA2AImpactEnvironment(case.metadata, 0, manifest_case=item) as env:
        result = OfficialA2AReplayHostSUT().run_probe(env.public_view, env)
        event_types = {x["event_type"] for x in env.impact_events}
    assert "trace_replay_mismatch" in event_types
    assert "trace_replay_mismatch" in str(result.error_message)


def test_interface_trace_mismatch_fails_closed() -> None:
    item, case = _sample()
    item = {**item, "trace": {**item["trace"], "selected_protocol_version": "unexpected"}}
    with OfficialA2AImpactEnvironment(case.metadata, 0, manifest_case=item) as env:
        result = OfficialA2AReplayHostSUT().run_probe(env.public_view, env)
    assert "selected_protocol_version" in str(result.error_message)
