from __future__ import annotations

import importlib
import json
import socket
from pathlib import Path

from harness.downstream.impact_env import OfficialA2AImpactEnvironment
from sut.downstream.replay_host import OfficialA2AReplayHostSUT


ROOT = Path(__file__).resolve().parents[2]


def test_replay_does_not_open_network_sockets(monkeypatch) -> None:
    def reject(*args, **kwargs):
        raise AssertionError("external network access is forbidden")
    monkeypatch.setattr(socket, "create_connection", reject)
    payload = json.loads((ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json").read_text(encoding="utf-8"))
    item = next(x for x in payload["cases"] if x["attack_type"] == "B1")
    module, name = item["class_path"].split(":", 1); case = getattr(importlib.import_module(module), name)()
    with OfficialA2AImpactEnvironment(case.metadata, 0, manifest_case=item, external_network=False) as env:
        result = OfficialA2AReplayHostSUT().run_probe(env.public_view, env)
    assert result.error_message is None
