from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable


def _phase_state(
    case: dict[str, Any], prepared_state: dict[str, Any], step: dict[str, Any]
) -> dict[str, Any]:
    """Build the same identity-scoped decision view used by the main experiment."""
    state = deepcopy(prepared_state)
    token_label = str(step.get("token_label", ""))
    identity = str(step.get("identity_label", step.get("identity", "")))
    token = case.get("authorization_context", {}).get(token_label, {})
    state["identity"] = identity
    state["token_scopes"] = list(token.get("scopes", state.get("token_scopes", [])))
    return state


def decide_identity_phases(
    case: dict[str, Any],
    prepared_state: dict[str, Any],
    decide: Callable[[dict[str, Any]], tuple[Any, dict[str, Any]]],
) -> tuple[dict[str, Any] | None, dict[str, Any], list[dict[str, Any] | None]]:
    """Run one frozen Host decision per identity phase for A3.

    The Official A2A reference evaluates every authentication step.  Native
    adapters use this helper so state-reuse experiments have the same decision
    schedule instead of seeding privileged state outside the measured flow.
    """
    steps = list(case.get("native", {}).get("identity_sequence", []))
    if not steps:
        raise ValueError("A3 identity-phase execution requires identity_sequence.")

    aggregate: dict[str, Any] = {
        "llm_calls": 0,
        "llm_latency_ms": 0.0,
        "parse_failed": False,
        "phase_decisions": [],
    }
    dispatches: list[dict[str, Any] | None] = []
    final_payload: dict[str, Any] | None = None
    for phase_index, step in enumerate(steps):
        decision, metrics = decide(_phase_state(case, prepared_state, step))
        aggregate["llm_calls"] += int(metrics.get("llm_calls", 0))
        aggregate["llm_latency_ms"] += float(metrics.get("llm_latency_ms", 0.0))
        aggregate["parse_failed"] = bool(
            aggregate["parse_failed"] or metrics.get("parse_failed")
        )
        if metrics.get("raw_response") is not None:
            aggregate.setdefault("parse_failure_raw_responses", []).append(
                metrics["raw_response"]
            )
        if decision is None:
            aggregate["phase_decisions"].append(
                {"phase_index": phase_index, "parse_failed": True}
            )
            dispatches.append(None)
            continue

        payload = decision.to_dict()
        final_payload = payload
        aggregate["phase_decisions"].append(
            {"phase_index": phase_index, **payload}
        )
        complete = payload.get("capability_id") is not None and payload.get(
            "interface_index"
        ) is not None
        dispatches.append(payload if payload.get("should_send") and complete else None)

    return final_payload, aggregate, dispatches
