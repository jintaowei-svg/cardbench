from __future__ import annotations

import importlib
import json
from pathlib import Path

from harness.downstream.impact_env import OfficialA2AImpactEnvironment
from harness.downstream.impact_oracles import judge_impact
from sut.downstream.replay_host import OfficialA2AReplayHostSUT
from tests.downstream.helpers import fake_workers


ROOT = Path(__file__).resolve().parents[2]


def test_impact_requires_an_observable_worker_caused_event() -> None:
    payload = json.loads((ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json").read_text(encoding="utf-8"))
    host = OfficialA2AReplayHostSUT()
    for attack in ("A1", "C1"):
        item = next(x for x in payload["cases"] if x["attack_type"] == attack)
        module, name = item["class_path"].split(":", 1)
        case = getattr(importlib.import_module(module), name)()
        with OfficialA2AImpactEnvironment(case.metadata, 0, manifest_case=item, worker_registry=fake_workers()) as env:
            result = host.run_probe(env.public_view, env)
            env.complete()
            events = env.impact_events
        assert result.error_message is None
        assert judge_impact(attack, events, item)
        assert not judge_impact(attack, [x for x in events if x["event_type"] in {"impact_trial_started", "impact_trial_completed"}], item)


def test_a2_received_task_reaches_and_is_stored_by_drifted_worker() -> None:
    payload = json.loads((ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json").read_text(encoding="utf-8"))
    item = next(x for x in payload["cases"] if x["attack_type"] == "A2")
    module, name = item["class_path"].split(":", 1)
    case = getattr(importlib.import_module(module), name)()
    item = {**item, "replay_task": "task with no downstream impact canary"}
    with OfficialA2AImpactEnvironment(case.metadata, 0, manifest_case=item, worker_registry=fake_workers()) as env:
        result = OfficialA2AReplayHostSUT().run_probe(env.public_view, env)
        events = env.impact_events
    assert result.error_message is None
    assert any(x["event_type"] == "received_context_stored" for x in events)
    assert judge_impact("A2", events, item)
