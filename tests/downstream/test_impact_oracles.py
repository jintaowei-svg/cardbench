from __future__ import annotations

import importlib
import json
from pathlib import Path

from harness.downstream.impact_env import OfficialA2AImpactEnvironment
from harness.downstream.impact_oracles import judge_impact
from sut.downstream.replay_host import OfficialA2AReplayHostSUT


ROOT = Path(__file__).resolve().parents[2]


def test_all_attack_oracles_require_deterministic_impact_events() -> None:
    payload = json.loads((ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json").read_text(encoding="utf-8"))
    host = OfficialA2AReplayHostSUT()
    for attack in ("A1", "A2", "A3", "B1", "B3", "C1", "C2"):
        item = next(x for x in payload["cases"] if x["attack_type"] == attack)
        module, name = item["class_path"].split(":", 1)
        case = getattr(importlib.import_module(module), name)()
        with OfficialA2AImpactEnvironment(case.metadata, 0, manifest_case=item) as env:
            result = host.run_probe(env.public_view, env)
            env.complete()
            events = env.impact_events
        assert result.error_message is None
        assert judge_impact(attack, events, item)
        assert not judge_impact(attack, [x for x in events if x["event_type"] in {"impact_trial_started", "impact_trial_completed"}], item)


def test_a2_canary_must_reach_the_sdk_server() -> None:
    payload = json.loads((ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json").read_text(encoding="utf-8"))
    item = next(x for x in payload["cases"] if x["attack_type"] == "A2")
    module, name = item["class_path"].split(":", 1)
    case = getattr(importlib.import_module(module), name)()
    item = {**item, "replay_task": "task with no downstream impact canary"}
    with OfficialA2AImpactEnvironment(case.metadata, 0, manifest_case=item) as env:
        result = OfficialA2AReplayHostSUT().run_probe(env.public_view, env)
        events = env.impact_events
    assert result.error_message is None
    assert not any(x["event_type"] == "canary_observed" for x in events)
    assert not judge_impact("A2", events, item)
