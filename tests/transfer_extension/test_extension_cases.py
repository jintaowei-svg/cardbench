from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from sut.transfer_native.canonical_view import build_canonical_view


ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_extension_applicability_is_frozen() -> None:
    matrix = _read("attacks/carddiff/transfer_extension/applicability.json")
    assert matrix["frozen"] is True
    assert {key for key, value in matrix["agntcy"].items() if value == "applicable"} == {
        "A2",
        "B2",
    }
    assert {key for key, value in matrix["autogen"].items() if value == "applicable"} == {
        "A3",
        "C1",
        "C2",
    }
    assert {key for key, value in matrix["langgraph"].items() if value == "applicable"} == {
        "A3",
        "B1",
        "C1",
        "C2",
    }


def test_extension_cases_reuse_frozen_master_without_resampling() -> None:
    master = _read("attacks/carddiff/transfer_native/master_cases.json")
    master_ids = {case["master_case_id"] for case in master["cases"]}
    expectations = {
        "attacks/carddiff/transfer_native/agntcy_cases.json": (180, {"A2", "B2"}),
        "attacks/carddiff/transfer_framework/autogen_cases.json": (
            270,
            {"A3", "C1", "C2"},
        ),
        "attacks/carddiff/transfer_framework/langgraph_cases.json": (
            360,
            {"A3", "B1", "C1", "C2"},
        ),
    }
    for path, (total, attacks) in expectations.items():
        cases = _read(path)["cases"]
        assert len(cases) == total
        assert set(Counter(case["attack_type"] for case in cases).values()) == {90}
        assert {case["attack_type"] for case in cases} == attacks
        assert {case["master_case_id"] for case in cases} <= master_ids
        assert len({case["target_case_id"] for case in cases}) == total


def test_smoke_manifest_has_exactly_one_case_per_applicable_attack() -> None:
    smoke = _read("attacks/carddiff/transfer_extension/smoke_case_ids.json")
    assert len(smoke["agntcy"]) == 2
    assert len(smoke["autogen"]) == 3
    assert len(smoke["langgraph"]) == 4
    for target, manifest in (
        ("agntcy", "attacks/carddiff/transfer_native/agntcy_cases.json"),
        ("autogen", "attacks/carddiff/transfer_framework/autogen_cases.json"),
        ("langgraph", "attacks/carddiff/transfer_framework/langgraph_cases.json"),
    ):
        cases = {case["target_case_id"]: case for case in _read(manifest)["cases"]}
        selected = [cases[case_id]["attack_type"] for case_id in smoke[target]]
        assert len(selected) == len(set(selected))


def test_autogen_a3_cases_include_both_identity_phases() -> None:
    cases = _read("attacks/carddiff/transfer_framework/autogen_cases.json")["cases"]
    a3_cases = [case for case in cases if case["attack_type"] == "A3"]
    assert a3_cases
    for case in a3_cases:
        assert [
            step["identity_label"] for step in case["native"]["identity_sequence"]
        ] == ["privileged_user", "normal_user"]


def test_langgraph_b1_model_view_uses_neutral_participant_names() -> None:
    cases = _read("attacks/carddiff/transfer_framework/langgraph_cases.json")["cases"]
    b1_cases = [case for case in cases if case["attack_type"] == "B1"]
    assert len(b1_cases) == 90
    for case in b1_cases:
        view = build_canonical_view(case["canonical_state"])
        serialized = json.dumps(view, ensure_ascii=False, sort_keys=True).lower()
        assert all(term not in serialized for term in ("attacker", "trusted", "oracle"))
        assert [item["id"] for item in view["capabilities"]] == [
            "participant_1",
            "participant_2",
        ]
        assert case["native"]["attacker_preferred_candidate"] in case["native"][
            "participant_order"
        ]
