from __future__ import annotations

import importlib.util
from typing import Any, Callable

from harness.transfer_native.anp.environment import ANPNativeEnvironment
from harness.transfer_native.contracts import NativeExecution
from sut.transfer_native.phase_schedule import decide_identity_phases


class ANPNativeAdapter:
    protocol = "anp"

    def __init__(
        self,
        *,
        require_native_sdk: bool = True,
        environment_factory: Callable[[dict[str, Any]], ANPNativeEnvironment] = ANPNativeEnvironment,
    ) -> None:
        if require_native_sdk and importlib.util.find_spec("anp") is None:
            raise RuntimeError("Formal ANP transfer requires anp[api]==0.8.8.")
        self.environment_factory = environment_factory

    def execute(self, case: dict[str, Any], decision: dict[str, Any]) -> NativeExecution:
        with self.environment_factory(case) as environment:
            return environment.execute(decision)

    def run_trial(self, case: dict[str, Any], decide: Callable[[dict[str, Any]], tuple[Any, dict[str, Any]]]):
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


class ANPLegacyRerunAdapter(ANPNativeAdapter):
    """Frozen single-decision schedule for replacing pre-revision infra failures."""

    def run_trial(
        self,
        case: dict[str, Any],
        decide: Callable[[dict[str, Any]], tuple[Any, dict[str, Any]]],
    ):
        with self.environment_factory(case) as environment:
            state = environment.prepare()
            decision, metrics = decide(state)
            if decision is None:
                return None, metrics, None
            payload = decision.to_dict()
            if not payload["should_send"]:
                return payload, {**metrics, "dispatch_skipped": "model_refusal"}, None
            if payload["capability_id"] is None or payload["interface_index"] is None:
                return payload, {**metrics, "dispatch_skipped": "incomplete_control_decision"}, None
            metrics["decision_schedule"] = "legacy_single_decision_repair_only"
            return payload, metrics, environment.execute(payload)
