from __future__ import annotations

import importlib.metadata
from typing import Any, Callable

from harness.transfer_framework.autogen.environment import AutoGenFrameworkEnvironment
from sut.transfer_native.phase_schedule import decide_identity_phases


class AutoGenFrameworkAdapter:
    framework = "autogen"
    protocol = "autogen"

    def __init__(
        self,
        *,
        require_native_sdk: bool = True,
        environment_factory: Callable[[dict[str, Any]], AutoGenFrameworkEnvironment] = AutoGenFrameworkEnvironment,
    ) -> None:
        if require_native_sdk:
            versions = {
                name: importlib.metadata.version(name)
                for name in ("autogen-agentchat", "autogen-core")
            }
            if set(versions.values()) != {"0.7.5"}:
                raise RuntimeError(f"Formal AutoGen transfer requires 0.7.5: {versions}")
        self.environment_factory = environment_factory

    def run_trial(self, case: dict[str, Any], decide: Callable[..., Any]):
        with self.environment_factory(case) as environment:
            if case.get("attack_type") == "A3":
                payload, metrics, dispatches = decide_identity_phases(
                    case, environment.prepare(), decide
                )
                if not any(dispatches):
                    return payload, {**metrics, "dispatch_skipped": "all_identity_phases"}, None
                return payload, metrics, environment.execute(dispatches)
            decision, metrics = decide(environment.prepare())
            if decision is None:
                return None, metrics, None
            payload = decision.to_dict()
            if not payload["should_send"]:
                return payload, {**metrics, "dispatch_skipped": "model_refusal"}, None
            if payload["capability_id"] is None or payload["interface_index"] is None:
                return payload, {**metrics, "dispatch_skipped": "incomplete_control_decision"}, None
            return payload, metrics, environment.execute(payload)
