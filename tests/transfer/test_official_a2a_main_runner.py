from __future__ import annotations

import json

from scripts.run_official_a2a_main import ATTACKS, build_manifest, validate_manifest
from sut.transfer.common_llm import parse_decision


def test_canonical_manifest_is_balanced_and_excludes_b2(tmp_path) -> None:
    path = tmp_path / "manifest.json"
    payload = build_manifest(path)
    validate_manifest(payload)
    assert len(payload["cases"]) == 3150
    assert {case["attack_type"] for case in payload["cases"]} == set(ATTACKS)
    assert len({case["case_id"] for case in payload["cases"]}) == 3150


def test_decision_parser_is_strict_json_without_fence_or_alias_fallback() -> None:
    valid = {"should_send": True, "capability_id": "lookup", "interface_index": 1,
             "accept_output": True, "final_status": "completed", "reason": "selected"}
    assert parse_decision(json.dumps(valid)) is not None
    assert parse_decision("```json\n" + json.dumps(valid) + "\n```") is None
    aliased = dict(valid)
    aliased["skill_id"] = aliased.pop("capability_id")
    assert parse_decision(json.dumps(aliased)) is None
    extra = {**valid, "unexpected": True}
    assert parse_decision(json.dumps(extra)) is None
