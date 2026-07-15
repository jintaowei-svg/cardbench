from __future__ import annotations

from sut.transfer.common_llm import canonical_prompt_sha256, parse_decision
from sut.transfer_native.strict_parser import parse_decision as native_parse_decision


def test_native_runner_reuses_frozen_prompt_and_parser() -> None:
    assert canonical_prompt_sha256()
    assert native_parse_decision is parse_decision
