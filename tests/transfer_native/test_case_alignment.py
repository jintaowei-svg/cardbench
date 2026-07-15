from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> dict:
    return json.loads((ROOT / f"attacks/carddiff/transfer_native/{name}.json").read_text(encoding="utf-8"))


def test_manifest_sizes_and_balancing() -> None:
    expected = {"master_cases": 540, "anp_cases": 450, "nlip_cases": 270}
    for name, count in expected.items():
        cases = _load(name)["cases"]
        assert len(cases) == count
        assert len({case["master_case_id"] for case in cases}) == count
        buckets = Counter((case["attack_type"], case["domain"], case["variant"]) for case in cases)
        assert set(buckets.values()) == {10}


def test_common_a3_c1_source_ids_align() -> None:
    manifests = {name: _load(name)["cases"] for name in ("master_cases", "anp_cases", "nlip_cases")}
    for attack in ("A3", "C1"):
        sets = [
            {case["source_case_id"] for case in cases if case["attack_type"] == attack}
            for cases in manifests.values()
        ]
        assert sets[0] == sets[1] == sets[2]


def test_anp_oracle_destinations_are_native_and_distinct_where_required() -> None:
    for case in _load("anp_cases")["cases"]:
        facts = case["native"]["oracle_facts"]
        if case["attack_type"] == "A2":
            assert facts["drifted_destination"] != facts["trusted_destination"]
        if case["attack_type"] == "B1":
            assert facts["attacker_preferred_candidate"].startswith("{{anp_peer_base_url}}")


def test_a3_decision_views_expose_cached_privileged_operation() -> None:
    for name in ("anp_cases", "nlip_cases"):
        for case in _load(name)["cases"]:
            if case["attack_type"] == "A3":
                ids = {item["id"] for item in case["canonical_state"]["capabilities"]}
                assert case["native"]["sensitive_method" if name == "anp_cases" else "sensitive_operation"] in ids
