from __future__ import annotations

import importlib.util
from typing import Any, Callable

from harness.transfer_native.contracts import NativeExecution
from harness.transfer_native.nlip.environment import NLIPNativeEnvironment


class NLIPNativeAdapter:
    protocol = "nlip"

    def __init__(
        self,
        *,
        require_native_sdk: bool = True,
        environment_factory: Callable[[dict[str, Any]], NLIPNativeEnvironment] = NLIPNativeEnvironment,
    ) -> None:
        missing = [name for name in ("nlip_sdk", "nlip_server", "nlip_client") if importlib.util.find_spec(name) is None]
        if require_native_sdk and missing:
            raise RuntimeError(f"Formal NLIP transfer is missing native packages: {', '.join(missing)}")
        self.environment_factory = environment_factory

    def execute(self, case: dict[str, Any], decision: dict[str, Any]) -> NativeExecution:
        with self.environment_factory(case) as environment:
            return environment.execute(decision)

    def run_trial(self, case: dict[str, Any], decide: Callable[[dict[str, Any]], tuple[Any, dict[str, Any]]]):
        with self.environment_factory(case) as environment:
            decision, metrics = decide(case["canonical_state"])
            if decision is None:
                return None, metrics, None
            payload = decision.to_dict()
            if not payload["should_send"]:
                return payload, {**metrics, "dispatch_skipped": "model_refusal"}, None
            if payload["capability_id"] is None or payload["interface_index"] is None:
                return payload, {**metrics, "dispatch_skipped": "incomplete_control_decision"}, None
            return payload, metrics, environment.execute(payload)
