from __future__ import annotations

import importlib.metadata
from typing import Any, Callable

from harness.transfer_native.agntcy.environment import AGNTCYNativeEnvironment


class AGNTCYNativeAdapter:
    protocol = "agntcy"

    def __init__(
        self,
        *,
        require_native_sdk: bool = True,
        environment_factory: Callable[[dict[str, Any]], AGNTCYNativeEnvironment] = AGNTCYNativeEnvironment,
    ) -> None:
        if require_native_sdk:
            version = importlib.metadata.version("agntcy-dir")
            if version != "1.5.0":
                raise RuntimeError(
                    f"Formal AGNTCY transfer requires agntcy-dir==1.5.0, found {version}."
                )
        self.environment_factory = environment_factory

    def run_trial(self, case: dict[str, Any], decide: Callable[..., Any]):
        with self.environment_factory(case) as environment:
            decision, metrics = decide(environment.prepare())
            if decision is None:
                return None, metrics, None
            payload = decision.to_dict()
            if not payload["should_send"]:
                return payload, {**metrics, "dispatch_skipped": "model_refusal"}, None
            if payload["capability_id"] is None or payload["interface_index"] is None:
                return payload, {**metrics, "dispatch_skipped": "incomplete_control_decision"}, None
            return payload, metrics, environment.execute(payload)
