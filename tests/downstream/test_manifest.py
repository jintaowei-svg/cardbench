from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from harness.downstream.trace_loader import EXPECTED_COUNTS, load_manifest


ROOT = Path(__file__).resolve().parents[2]


def test_checked_in_manifest_has_exact_triggered_distribution() -> None:
    cases = load_manifest(ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json")
    assert len(cases) == 621
    assert Counter(x["attack_type"] for x in cases) == EXPECTED_COUNTS
    assert len({x["case_id"] for x in cases}) == 621
    assert all(x["decision_source"] in {"recorded_trace", "trigger_oracle_reconstruction"} for x in cases)


def test_manifest_contains_no_llm_prompt_or_response() -> None:
    text = (ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json").read_text(encoding="utf-8")
    assert "llm_calls" not in text
    assert "raw_response" not in text
