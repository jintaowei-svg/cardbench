from __future__ import annotations

import asyncio
import json
from pathlib import Path

from attacks.instances.carddiff_perturbed import CardDiffPerturbed136
from defense.nemo.aggregate_results import aggregate
from defense.nemo.gateway import NemoGateway, build_security_context
from defense.nemo.run_nemo_defense import _balanced_sample_cases, _manifest_cases, _load_case


ROOT = Path(__file__).resolve().parents[2]


def test_official_a2a_defense_split_is_frozen_630() -> None:
    payload, cases, manifest_hash = _manifest_cases(
        ROOT / "attacks/carddiff/transfer/splits/official_a2a_720.json"
    )
    assert payload["split_id"] == "official_a2a_720"
    assert len(cases) == 630
    assert manifest_hash == "6adee51fc98113d27dfa361b1375317d898b17c94a932a59817daa21f8c8a8b8"


def test_balanced_sample_selects_uniform_50_cases() -> None:
    _, cases, _ = _manifest_cases(
        ROOT / "attacks/carddiff/transfer/splits/official_a2a_720.json"
    )
    sample = _balanced_sample_cases(cases, 50)
    counts: dict[tuple[str, str], int] = {}
    for item in sample:
        case = _load_case(item["class_path"])
        key = (case.attack_type, case.scenario)
        counts[key] = counts.get(key, 0) + 1

    assert len(sample) == 50
    assert len(counts) == 21
    assert min(counts.values()) == 2
    assert max(counts.values()) == 3


def test_security_context_contains_host_state_but_not_private_oracle() -> None:
    metadata = CardDiffPerturbed136().metadata
    context = build_security_context(metadata)
    assert "[USER TASK]" in context
    assert "[PUBLIC AGENT CARD]" in context
    assert "wire_transfer" in context
    assert "normal_user" in context
    assert "finance.read" in context
    assert '"admin"' not in context
    assert "finance.transfer" not in context
    assert "required_event" not in context
    assert "sensitive_skill_id" not in context
    assert "oracle" not in context.lower()
    assert metadata["attack_type"] not in context


def test_gateway_parses_yes_no_and_retries_unparseable_output() -> None:
    outputs = iter(["maybe", "No"])
    gateway = NemoGateway("unused", checker=lambda _: next(outputs), max_retries=1)
    result = asyncio.run(gateway.check_with_nemo("context"))
    assert result.allow is True
    assert result.raw_output == "No"
    assert result.retry_count == 1
    assert result.error is None


def test_gateway_error_is_not_a_block() -> None:
    def fail(_: str) -> str:
        raise TimeoutError("model timeout")

    result = asyncio.run(NemoGateway("unused", checker=fail).check_with_nemo("context"))
    assert result.allow is None
    assert result.error and "TimeoutError" in result.error


def test_partial_aggregation_keeps_errors_out_of_completed_denominator(tmp_path) -> None:
    records = [
        {
            "split_id": "frozen", "manifest_hash": "abc", "case_id": "one",
            "attack_id": "A1", "domain": "travel", "judgment_status": "completed",
            "error_category": None, "guardrail_blocked": True, "attack_success": False,
        },
        {
            "split_id": "frozen", "manifest_hash": "abc", "case_id": "two",
            "attack_id": "A1", "domain": "travel", "judgment_status": "non_judgment",
            "error_category": "guardrail_error", "guardrail_blocked": False,
            "attack_success": False,
        },
        {
            "split_id": "frozen", "manifest_hash": "abc", "case_id": "three",
            "attack_id": "A1", "domain": "travel", "judgment_status": "completed",
            "error_category": None, "guardrail_blocked": False, "attack_success": True,
        },
    ]
    source = tmp_path / "raw.jsonl"
    source.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"reconciled_excluding_b2": {
        "successes": 621, "planned_cases": 630,
    }}), encoding="utf-8")
    summary = aggregate(
        source, tmp_path / "summary.json", baseline_results=baseline, allow_partial=True
    )
    assert summary["overall"]["planned"] == 3
    assert summary["overall"]["completed"] == 2
    assert summary["overall"]["errors"] == 1
    assert summary["overall"]["planned_case_asr"] == 1 / 3
    assert summary["overall"]["completed_case_asr"] == 1 / 2
    assert summary["overall"]["block_rate"] == 1 / 3
