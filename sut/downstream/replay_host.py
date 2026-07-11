from __future__ import annotations

import json
import time
from typing import Any

from sut.base import A2AProbeResult
from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT


class OfficialA2AReplayHostSUT(OfficialSDKCardDiffHostSUT):
    """Replay a frozen control-plane decision through Official A2A SDK."""

    def run_probe(self, case: dict[str, Any], env: Any | None = None) -> A2AProbeResult:
        if env is None:
            return A2AProbeResult(error_message="Downstream environment is required.")
        frozen = env.manifest_case
        metrics = {"llm_calls": 0, "protocol_latency_ms": 0.0, "parse_failed": False}
        errors: list[str] = []
        responses: list[dict[str, Any]] = []
        started = time.perf_counter()
        cache: Any = None
        try:
            for step_index, step in enumerate(case.get("auth_sequence", [])):
                label, identity = str(step.get("token_label", "")), str(step.get("identity", ""))
                public = self._discover_public_card(env=env, base_url=case["agent_base_url"], token_label=label, metrics=metrics)
                state = self._control_state(public)
                active, scope = public, "public"
                if state.get("capabilities", {}).get("extendedAgentCard") is True:
                    if cache is None:
                        cache = self._discover_extended_card(env=env, base_url=case["agent_base_url"], token_label=label, identity=identity, public_card=public, metrics=metrics)
                        scope = "extended"
                    else:
                        active, scope = cache, "extended-cache"
                    active = cache
                if step_index != int(frozen.get("replay_step_index", len(case.get("auth_sequence", [])) - 1)):
                    continue
                trace = frozen["trace"]
                scopes = list(step.get("token_scopes", []))
                mismatch = []
                if identity != trace.get("identity"): mismatch.append("identity")
                if scopes != trace.get("token_scopes"): mismatch.append("token_scopes")
                if scope != trace.get("card_scope_used"): mismatch.append("card_scope")
                decision = frozen["decision"]
                active_state = self._control_state(active)
                skill = self._find_capability(active_state, decision.get("capability_id"))
                interface = self._find_interface(active_state, decision.get("interface_index"))
                if skill is None: mismatch.append("selected_skill")
                if interface is None: mismatch.append("selected_interface")
                if interface is not None:
                    if interface.get("url") != trace.get("selected_url"):
                        mismatch.append("selected_url")
                    if interface.get("protocolBinding") != trace.get("selected_protocol_binding"):
                        mismatch.append("selected_protocol_binding")
                    if interface.get("protocolVersion") != trace.get("selected_protocol_version"):
                        mismatch.append("selected_protocol_version")
                if mismatch:
                    env.impact_recorder.record("trace_replay_mismatch", "carddiff-host", fields=mismatch)
                    raise RuntimeError("trace_replay_mismatch: " + ", ".join(mismatch))
                if decision.get("should_send"):
                    response = self._invoke_selected_interface(env=env, resolved_card=active, interface=interface,
                        interface_index=int(decision["interface_index"]), skill=skill, task=frozen["replay_task"],
                        token_label=label, identity=identity, token_scopes=scopes, card_scope_used=scope,
                        accepted_output_modes=list(trace.get("accepted_output_modes", [])), request_tenant=case.get("request_tenant"), metrics=metrics)
                    responses.append(response)
                    if decision.get("accept_output"):
                        self._accept_outputs(env, response, list(trace.get("accepted_output_modes", [])))
        except Exception as exc:
            errors.append(str(exc))
        metrics["total_latency_ms"] = (time.perf_counter() - started) * 1000
        metrics["framework_version"] = self.framework_version
        return A2AProbeResult(response_text=json.dumps({"responses": responses, "errors": errors}, sort_keys=True),
                              blocked=bool(errors), error_message="; ".join(errors) or None, metrics=metrics)
