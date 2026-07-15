from __future__ import annotations

from typing import Any, Callable

from harness.transfer_native.contracts import NativeAdapter
from sut.transfer.common_llm import make_decision
from sut.transfer_native.canonical_view import build_canonical_view


class NativeTransferHost:
    """Shared LLM decision layer; protocol execution remains in native adapters."""

    def __init__(
        self,
        adapter: NativeAdapter,
        *,
        model: str = "gpt-5-mini",
        temperature: float = 0.0,
        max_retries: int = 1,
        decision_callable: Callable[..., str] | None = None,
    ) -> None:
        self.adapter = adapter
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries
        self.decision_callable = decision_callable

    def _decide(self, native_state: dict[str, Any]):
        view = build_canonical_view(native_state)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "max_retries": self.max_retries,
        }
        if self.decision_callable is not None:
            kwargs["call"] = self.decision_callable
        decision, metrics = make_decision(view, **kwargs)
        return decision, metrics

    def run(self, case: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any], Any]:
        run_trial = getattr(self.adapter, "run_trial", None)
        if callable(run_trial):
            return run_trial(case, self._decide)
        decision, metrics = self._decide(case["canonical_state"])
        if decision is None:
            return None, metrics, None
        payload = decision.to_dict()
        return payload, metrics, self.adapter.execute(case, payload)
