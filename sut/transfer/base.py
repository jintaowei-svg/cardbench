from __future__ import annotations

import json
import time
from abc import ABC
from typing import Any, Callable
from uuid import uuid4

import requests

from sut.base import A2AProbeResult, CardDiffHostSUTBase
from sut.transfer.common_llm import make_decision, to_canonical_decision_view


class TransferHostBase(CardDiffHostSUTBase, ABC):
    """Independent protocol-neutral implementation of the transfer Host flow."""

    transfer_target = "unknown"
    framework_version: str | None = None

    def __init__(self, timeout_s: float = 15.0, max_retries: int = 1, model: str | None = None, temperature: float | None = 0, decision_callable: Callable[..., str] | None = None) -> None:
        self.timeout_s = float(timeout_s)
        self.max_retries = int(max_retries)
        self.model = model
        self.temperature = temperature
        self.decision_callable = decision_callable

    def run_probe(self, case: dict[str, Any], env: Any | None = None) -> A2AProbeResult:
        if env is None:
            return A2AProbeResult(error_message="Transfer environment is required.")
        responses: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        errors: list[str] = []
        metrics = {"llm_calls": 0, "input_tokens": None, "output_tokens": None, "llm_latency_ms": 0.0, "protocol_latency_ms": 0.0, "parse_failed": False, "parse_failure_raw_responses": []}
        total_started = time.perf_counter()
        base_url = str(case["agent_base_url"]).rstrip("/")
        extended_cache: dict[str, Any] = {}

        for step_index, auth_step in enumerate(case.get("auth_sequence", [])):
            token_label = str(auth_step.get("token_label", ""))
            try:
                public_card = self._discover_public_card(env=env, base_url=base_url, token_label=token_label, metrics=metrics)
                public_state = self._control_state(public_card)
                card_scope_used, active_card = "public", public_card
                if public_state.get("capabilities", {}).get("extendedAgentCard") is True:
                    if base_url in extended_cache:
                        active_card, card_scope_used = extended_cache[base_url], "extended-cache"
                    else:
                        active_card = self._discover_extended_card(env=env, base_url=base_url, token_label=token_label, identity=str(auth_step.get("identity", "")), public_card=public_card, metrics=metrics)
                        extended_cache[base_url] = active_card
                        card_scope_used = "extended"
                self._record_discovery(env, step_index, card_scope_used)
                token_scopes = auth_step.get("token_scopes", [])
                if not isinstance(token_scopes, list) or not all(
                    isinstance(scope, str) for scope in token_scopes
                ):
                    raise TypeError("auth_step.token_scopes must be a list of strings.")
                active_state = self._control_state(active_card)
                raw_state = {
                    "task": case.get("task", ""), "identity": auth_step.get("identity", ""),
                    "token_scopes": list(token_scopes), "capabilities": active_state.get("skills", []),
                    "interfaces": active_state.get("supportedInterfaces", []),
                    "request_tenant": case.get("request_tenant"),
                    "accepted_output_modes": case.get("accepted_output_modes", []),
                }
                view = to_canonical_decision_view(raw_state)
                kwargs = {"model": self.model, "temperature": self.temperature, "max_retries": self.max_retries}
                if self.decision_callable is not None:
                    kwargs["call"] = self.decision_callable
                decision, decision_metrics = make_decision(view, **kwargs)
                for key in ("llm_calls", "llm_latency_ms"):
                    metrics[key] += decision_metrics.get(key, 0)
                if decision_metrics.get("parse_failed"):
                    metrics["parse_failed"] = True
                    metrics["parse_failure_raw_responses"].append(decision_metrics.get("raw_response", ""))
                    errors.append("LLM decision parsing failed after the allowed retry.")
                    decisions.append({"step_index": step_index, "parse_failed": True})
                    continue
                assert decision is not None
                decisions.append({"step_index": step_index, **decision.to_dict()})
                if not decision.should_send:
                    continue
                skill = self._find_capability(active_state, decision.capability_id)
                interface = self._find_interface(active_state, decision.interface_index)
                if skill is None or interface is None:
                    raise RuntimeError("LLM selected a capability or interface absent from the discovered view.")
                response = self._invoke_selected_interface(
                    env=env, resolved_card=active_card, interface=interface,
                    interface_index=int(decision.interface_index), skill=skill,
                    task=str(case.get("task", "")), token_label=token_label,
                    identity=str(auth_step.get("identity", "")), token_scopes=list(token_scopes), card_scope_used=card_scope_used,
                    accepted_output_modes=list(case.get("accepted_output_modes", [])),
                    request_tenant=case.get("request_tenant"), metrics=metrics,
                )
                responses.append(response)
                self._record_native_call(env, interface, skill, step_index)
                if decision.accept_output:
                    self._accept_outputs(env, response, list(case.get("accepted_output_modes", [])))
            except Exception as exc:
                errors.append(str(exc))

        metrics["total_latency_ms"] = (time.perf_counter() - total_started) * 1000
        metrics["framework_version"] = self.framework_version
        metrics["transfer_target"] = self.transfer_target
        return A2AProbeResult(
            response_text=json.dumps({"responses": responses, "decisions": decisions, "errors": errors}, ensure_ascii=False, sort_keys=True),
            blocked=bool(errors), error_message="; ".join(errors) if errors else None,
            metrics=metrics, meta={"decisions": decisions, "canonical_view_fields": list(to_canonical_decision_view({}).keys())},
        )

    @staticmethod
    def _control_state(card: Any) -> dict[str, Any]:
        state = getattr(card, "control_state", card)
        if not isinstance(state, dict):
            raise TypeError("Discovered control state must be a mapping.")
        return state

    def _discover_public_card(self, *, env: Any, base_url: str, token_label: str, metrics: dict[str, Any]) -> Any:
        return self._fetch_json(f"{base_url}/.well-known/agent-card.json", token_label, metrics)

    def _discover_extended_card(self, *, env: Any, base_url: str, token_label: str, identity: str, public_card: Any, metrics: dict[str, Any]) -> Any:
        return self._fetch_json(f"{base_url}/extendedAgentCard", token_label, metrics)

    def _invoke_selected_interface(self, *, env: Any, resolved_card: Any, interface: dict[str, Any], interface_index: int, skill: dict[str, Any], task: str, token_label: str, identity: str, token_scopes: list[str], card_scope_used: str, accepted_output_modes: list[str], request_tenant: Any, metrics: dict[str, Any]) -> dict[str, Any]:
        return self._invoke(interface=interface, task=task, token_label=token_label, skill_id=str(skill.get("id", "")), card_scope_used=card_scope_used, accepted_output_modes=accepted_output_modes, request_tenant=request_tenant, metrics=metrics)

    def _fetch_json(self, url: str, token_label: str, metrics: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        response = requests.get(url, headers={"Authorization": self._auth_header(token_label)}, timeout=self.timeout_s)
        metrics["protocol_latency_ms"] += (time.perf_counter() - started) * 1000
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise RuntimeError("Discovery response was not a JSON object.")
        return result

    def _invoke(self, *, interface: dict[str, Any], task: str, token_label: str, skill_id: str, card_scope_used: str, accepted_output_modes: list[str], request_tenant: Any, metrics: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(interface["url"]).rstrip("/") + "/message:send"
        body = {"message": {"role": "user", "parts": [{"kind": "text", "text": task}], "messageId": str(uuid4()), "tenant": request_tenant if request_tenant is not None else interface.get("tenant")}, "configuration": {"acceptedOutputModes": accepted_output_modes}, "metadata": {"skillId": skill_id, "cardScopeUsed": card_scope_used}}
        started = time.perf_counter()
        response = requests.post(endpoint, json=body, headers={"Authorization": self._auth_header(token_label), "Content-Type": "application/a2a+json", "Accept": "application/a2a+json", "A2A-Version": str(interface.get("protocolVersion", ""))}, timeout=self.timeout_s)
        metrics["protocol_latency_ms"] += (time.perf_counter() - started) * 1000
        try:
            result = response.json()
        except ValueError:
            result = {"raw": response.text}
        if not isinstance(result, dict):
            result = {"value": result}
        result["_status_code"] = response.status_code
        return result

    @staticmethod
    def _auth_header(token_label: str) -> str:
        return f"Bearer carddiff-token-{token_label}"

    @staticmethod
    def _find_capability(card: dict[str, Any], capability_id: str | None) -> dict[str, Any] | None:
        return next((dict(item) for item in card.get("skills", []) if item.get("id") == capability_id), None)

    @staticmethod
    def _find_interface(card: dict[str, Any], index: int | None) -> dict[str, Any] | None:
        interfaces = card.get("supportedInterfaces", [])
        return dict(interfaces[index - 1]) if isinstance(index, int) and 1 <= index <= len(interfaces) else None

    def _record_discovery(self, env: Any, step_index: int, card_scope_used: str) -> None:
        if hasattr(env, "record_native_event"):
            env.record_native_event(f"{self.transfer_target}_discovery", {"step_index": step_index, "card_scope_used": card_scope_used})

    def _record_native_call(self, env: Any, interface: dict[str, Any], skill: dict[str, Any], step_index: int) -> None:
        if hasattr(env, "record_native_event"):
            env.record_native_event(f"{self.transfer_target}_call", {"step_index": step_index, "url": interface.get("url"), "capability_id": skill.get("id")})

    @staticmethod
    def _accept_outputs(env: Any, response: dict[str, Any], accepted_output_modes: list[str]) -> None:
        if int(response.get("_status_code", 0)) >= 400:
            return
        for artifact in response.get("artifacts", []):
            for part in artifact.get("parts", []):
                metadata = part.get("metadata", {}) if isinstance(part, dict) else {}
                mime_type = metadata.get("mimeType") if isinstance(metadata, dict) else None
                if mime_type:
                    env.record_artifact_accepted(artifact_id=str(artifact.get("artifactId", "")), mime_type=str(mime_type), accepted_output_modes=accepted_output_modes)
