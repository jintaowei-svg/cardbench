from __future__ import annotations

import importlib
import json
from pathlib import Path

from harness.downstream.impact_env import OfficialA2AImpactEnvironment
from sut.downstream.replay_host import OfficialA2AReplayHostSUT


ROOT = Path(__file__).resolve().parents[2]


def test_each_trial_gets_a_fresh_resource_and_recorder() -> None:
    payload = json.loads((ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json").read_text(encoding="utf-8"))
    item = next(x for x in payload["cases"] if x["attack_type"] == "A1")
    module, name = item["class_path"].split(":", 1); case = getattr(importlib.import_module(module), name)()
    host = OfficialA2AReplayHostSUT()
    snapshots = []
    for trial in (0, 1):
        with OfficialA2AImpactEnvironment(case.metadata, trial, manifest_case=item) as env:
            snapshots.append(env.resource.snapshot())
            host.run_probe(env.public_view, env)
            assert len(env.impact_events) == 3
    assert snapshots[0] == snapshots[1]
