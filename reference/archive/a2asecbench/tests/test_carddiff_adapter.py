from __future__ import annotations

import json
from pathlib import Path

from attacks.carddiff.adapter import generate_cases, generate_perturbed_cases, load_perturbations


def test_carddiff_adapter_generates_24_stable_cases() -> None:
    cases = generate_cases()
    assert len(cases) == 24

    coverage = {(case["attack_type"], case["scenario"]) for case in cases}
    expected = {
        (attack_type, scenario)
        for attack_type in {"A1", "A2", "A3", "B1", "B2", "B3", "C1", "C2"}
        for scenario in {"travel", "healthcare", "finance"}
    }
    assert coverage == expected

    generated = [json.dumps(case, sort_keys=True, ensure_ascii=False) for case in cases]
    frozen = [
        line
        for line in Path("attacks/carddiff/cases.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert generated == frozen


def test_carddiff_cases_use_a2a_1_control_plane_fields() -> None:
    for case in generate_cases():
        card = case["agent"]["public_card"]
        assert card["capabilities"]["extendedAgentCard"] is True
        assert "supportsAuthenticatedExtendedCard" not in json.dumps(case)
        assert "securityRequirements" not in json.dumps(case)
        assert card["supportedInterfaces"]
        assert card["securitySchemes"]
        assert card["security"]


def test_carddiff_b2_has_independent_request_tenant() -> None:
    b2_cases = [case for case in generate_cases() if case["attack_type"] == "B2"]
    assert b2_cases
    for case in b2_cases:
        assert case["public"]["request_tenant"] == case["oracle"]["normal_tenant"]
        first_interface = case["agent"]["public_card"]["supportedInterfaces"][0]
        assert first_interface["tenant"] == case["oracle"]["privileged_tenant"]
        assert case["public"]["request_tenant"] != first_interface["tenant"]


def test_carddiff_protocol_state_perturbations_cover_all_cells() -> None:
    cases = generate_perturbed_cases()
    expected_variants = {variant["variant_id"] for variant in load_perturbations()}
    assert len(cases) == 24 * len(expected_variants)
    variants = {case["perturbation"]["variant_id"] for case in cases}
    assert variants == expected_variants
    coverage = {
        (case["attack_type"], case["scenario"], case["perturbation"]["variant_id"])
        for case in cases
    }
    expected = {
        (attack_type, scenario, variant)
        for attack_type in {"A1", "A2", "A3", "B1", "B2", "B3", "C1", "C2"}
        for scenario in {"travel", "healthcare", "finance"}
        for variant in expected_variants
    }
    assert coverage == expected
