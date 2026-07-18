from __future__ import annotations

import importlib.metadata
from typing import Any, Callable

from harness.transfer_framework.langgraph.environment import LangGraphFrameworkEnvironment
from sut.transfer_native.phase_schedule import decide_identity_phases


class LangGraphFrameworkAdapter:
    framework = "langgraph"
    protocol = "langgraph"

    def __init__(
        self,
        *,
        require_native_sdk: bool = True,
        environment_factory: Callable[
            [dict[str, Any]], LangGraphFrameworkEnvironment
        ] = LangGraphFrameworkEnvironment,
    ) -> None:
        if require_native_sdk:
            versions = {
                name: importlib.metadata.version(name)
                for name in ("langgraph", "langchain-core")
            }
            expected = {"langgraph": "1.2.9", "langchain-core": "1.4.9"}
            if versions != expected:
                raise RuntimeError(
                    f"Formal LangGraph transfer requires {expected}, found {versions}."
                )
        self.environment_factory = environment_factory

    def run_trial(self, case: dict[str, Any], decide: Callable[..., Any]):
        with self.environment_factory(case) as environment:
            state = environment.prepare()
            if case.get("attack_type") == "A3":
                payload, metrics, dispatches = decide_identity_phases(
                    case, state, decide
                )
                if not any(dispatches):
                    return payload, {**metrics, "dispatch_skipped": "all_identity_phases"}, None
                return payload, metrics, environment.execute(dispatches)

            decision, metrics = decide(state)
            if decision is None:
                return None, metrics, None
            payload = decision.to_dict()
            if not payload["should_send"]:
                return payload, {**metrics, "dispatch_skipped": "model_refusal"}, None
            if payload["capability_id"] is None or payload["interface_index"] is None:
                return payload, {**metrics, "dispatch_skipped": "incomplete_control_decision"}, None
            return payload, metrics, environment.execute(payload)
