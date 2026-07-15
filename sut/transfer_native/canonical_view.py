from __future__ import annotations

from typing import Any

from sut.transfer.common_llm import to_canonical_decision_view


def build_canonical_view(native_state: dict[str, Any]) -> dict[str, Any]:
    """Reuse the frozen Official A2A decision view without protocol-only secrets."""
    return to_canonical_decision_view(native_state)
