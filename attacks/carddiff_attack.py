from __future__ import annotations

from copy import deepcopy
import importlib
from typing import Any

from attacks.base import AttackCase, TrialOutcome
from harness.carddiff_scoring import score_carddiff_environment
from sut.base import A2AProbeResult, CardDiffHostSUTBase


CARDDIFF_ATTACK_ID = "CARDDIFF"


class CardDiffCase(AttackCase):
    attack_id = CARDDIFF_ATTACK_ID

    def __init__(self, metadata: dict[str, Any]) -> None:
        self.metadata = deepcopy(metadata)
        self.case_id = str(self.metadata["case_id"])
        self.attack_type = str(self.metadata["attack_type"])
        self.attack_name = str(self.metadata.get("attack_name", self.attack_type))
        self.scenario = str(self.metadata["scenario"])
        self.taxonomy = str(self.metadata.get("taxonomy", "carddiff"))
        self.difficulty = str(self.metadata.get("difficulty", "medium"))

    def get_ground_truth(self) -> dict[str, Any]:
        return deepcopy(self.metadata["oracle"])

    def get_sut_payload(self) -> dict[str, Any]:
        return deepcopy(self.metadata["public"])

    def run(self, sut: CardDiffHostSUTBase, **kwargs) -> TrialOutcome:
        if not isinstance(sut, CardDiffHostSUTBase):
            raise TypeError(
                f"CardDiffCase.run expected CardDiffHostSUTBase, got {type(sut).__name__}."
            )

        trial_index = int(kwargs.get("trial_index", 0))
        environment_cfg = kwargs.get("environment") or {}
        if not isinstance(environment_cfg, dict):
            raise TypeError("CardDiffCase.run expected environment to be a mapping.")
        errors: list[str] = []
        factory_path = str(environment_cfg.get("factory", "harness.carddiff_env:LocalCardDiffEnvironment"))
        env_cls = _load_environment_factory(factory_path)
        env_kwargs = dict(environment_cfg.get("kwargs") or {})
        # Legacy configs put the remote agent configuration directly under
        # ``environment``. Keep that stable while allowing transfer factories.
        if "remote_agent" in environment_cfg and "remote_agent" not in env_kwargs:
            env_kwargs["remote_agent"] = environment_cfg["remote_agent"]
        with env_cls(self.metadata, trial_index, **env_kwargs) as env:
            try:
                result = sut.run_probe(env.public_view, env)
            except Exception as exc:
                result = A2AProbeResult(error_message=str(exc), blocked=False)
            if result.error_message:
                errors.append(result.error_message)

            success, evidence = score_carddiff_environment(env.metadata, env.events, env.metrics)
            details = {
                "attack_type": self.attack_type,
                "attack_name": self.attack_name,
                "taxonomy": self.taxonomy,
                "scenario": self.scenario,
                "difficulty": self.difficulty,
                "attack_success": success,
                "success_evidence": evidence,
                "oracle": self.get_ground_truth(),
                "events": env.events,
                "metrics": {**env.metrics, **result.metrics},
                "response": result.response_text,
                "sut_meta": result.meta,
                **_extract_trace_fields(env.events),
            }

        return TrialOutcome(
            attack_id=self.attack_id,
            case_id=self.case_id,
            trial_index=trial_index,
            success=success,
            details=details,
            errors=errors,
        )


def _load_environment_factory(path: str):
    if ":" not in path:
        raise ValueError("environment.factory must use 'module:ClassName' syntax.")
    module_name, class_name = path.split(":", 1)
    module = importlib.import_module(module_name)
    try:
        factory = getattr(module, class_name)
    except AttributeError as exc:
        raise AttributeError(f"Environment factory '{path}' was not found.") from exc
    if not callable(factory):
        raise TypeError(f"Environment factory '{path}' is not callable.")
    return factory


def _extract_trace_fields(events: list[dict[str, Any]]) -> dict[str, Any]:
    message = next((event for event in events if event.get("event_type") == "message_sent"), None)
    artifact = next((event for event in events if event.get("event_type") == "artifact_accepted"), None)
    evidence = message.get("evidence", {}) if message else {}
    artifact_evidence = artifact.get("evidence", {}) if artifact else {}
    return {
        "selected_agent": "carddiff-local-agent",
        "selected_skill": evidence.get("skill_id"),
        "selected_interface": evidence.get("selected_url"),
        "selected_url": evidence.get("selected_url"),
        "selected_tenant": evidence.get("selected_tenant"),
        "request_tenant": evidence.get("request_tenant"),
        "selected_protocolBinding": evidence.get("selected_protocolBinding"),
        "actual_protocolBinding": evidence.get("selected_protocolBinding"),
        "selected_protocolVersion": evidence.get("selected_protocolVersion"),
        "actual_protocolVersion": evidence.get("selected_protocolVersion"),
        "auth_identity": evidence.get("identity"),
        "card_scope_used": evidence.get("card_scope_used"),
        "artifact_mime_type": artifact_evidence.get("mime_type"),
    }
