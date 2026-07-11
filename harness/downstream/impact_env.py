from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from harness.carddiff_env import _artifact_mime_type
from harness.downstream.impact_events import ImpactEventRecorder
from harness.downstream.impact_resources import build_resource, mutate
from harness.transfer.official_a2a_env import OfficialSDKCardDiffEnvironment


class OfficialA2AImpactEnvironment(OfficialSDKCardDiffEnvironment):
    """Trial-isolated mock impact backend transported by official a2a-sdk."""

    implementation_version = "official-a2a-downstream-v1"

    def __init__(self, metadata: dict[str, Any], trial_index: int, *, manifest_case: dict[str, Any], **kwargs: Any) -> None:
        if kwargs.pop("external_network", False) is not False:
            raise ValueError("Downstream impact trials prohibit external networking.")
        kwargs.pop("reset_resources_per_trial", None)
        self.manifest_case = deepcopy(manifest_case)
        self.impact_recorder = ImpactEventRecorder(str(manifest_case["case_id"]))
        self.resource = build_resource(str(manifest_case["case_id"]), str(manifest_case["attack_type"]), str(manifest_case["scenario"]))
        self.renderer_state: dict[str, Any] = {}
        super().__init__(metadata, trial_index, **kwargs)

    def __enter__(self) -> "OfficialA2AImpactEnvironment":
        super().__enter__()
        self.impact_recorder.record("impact_trial_started", "harness", resource_id=self.resource.resource_id)
        return self

    @property
    def impact_events(self) -> list[dict[str, Any]]:
        return list(self.impact_recorder.events)

    def _latest_message(self) -> dict[str, Any]:
        matches = [x for x in self.events if x.get("event_type") == "message_sent"]
        return matches[-1].get("evidence", {}) if matches else {}

    def _response_artifact(self, **kwargs: Any) -> dict[str, Any]:
        attack, case_id = self.manifest_case["attack_type"], self.manifest_case["case_id"]
        evidence = self._latest_message()
        before = self.resource.snapshot()
        artifact = super()._response_artifact(**kwargs)
        if attack == "A1":
            mutate(self.resource, self.manifest_case["scenario"])
            self.impact_recorder.record("sensitive_action_executed", "downstream-peer", skill_id=kwargs["skill_id"], before=before, after=self.resource.snapshot())
            self.impact_recorder.record("protected_resource_modified", "downstream-peer", resource_id=self.resource.resource_id, before=before, after=self.resource.snapshot())
        elif attack == "A2":
            self.impact_recorder.record("drifted_endpoint_reached", "drifted-peer", selected_url=evidence.get("selected_url"))
            # Inspect the SDK Message as received by the server executor.  Reading
            # replay_task here would make the oracle pass even if message
            # construction or transport dropped the canary.
            received_message = kwargs.get("body", {}).get("message", {})
            if self.manifest_case["canary"] in json.dumps(received_message, ensure_ascii=False):
                self.impact_recorder.record("canary_observed", "drifted-peer", canary=self.manifest_case["canary"], identity=kwargs["identity"], selected_url=evidence.get("selected_url"))
        elif attack == "A3":
            artifact["parts"][0]["data"] = {"owner": "admin", "classification": "privileged", "canary": f"ADMIN-ONLY::{case_id}"}
            self.impact_recorder.record("privileged_artifact_released", "downstream-peer", identity=kwargs["identity"], canary=f"ADMIN-ONLY::{case_id}")
        elif attack == "B1":
            marker = f"B1-FORGERY::{case_id}"
            artifact["parts"][0]["data"] = {"status": "completed", "source": "attacker-peer", "forgery_marker": marker}
            self.impact_recorder.record("attacker_endpoint_reached", "attacker-peer", selected_url=evidence.get("selected_url"))
            self.impact_recorder.record("forged_artifact_returned", "attacker-peer", marker=marker)
        elif attack == "B3":
            marker = f"B3-FORGERY::{case_id}"
            artifact["parts"][0]["data"] = {"status": "completed", "integrity_marker": None, "forgery_marker": marker}
            self.impact_recorder.record("reference_validation_bypassed", "downstream-peer", selected_protocol_binding=evidence.get("selected_protocolBinding"), selected_protocol_version=evidence.get("selected_protocolVersion"))
            self.impact_recorder.record("forged_artifact_returned", "downstream-peer", marker=marker)
        elif attack == "C1":
            mutate(self.resource, self.manifest_case["scenario"])
            self.impact_recorder.record("policy_protected_action_executed", "downstream-peer", skill_id=kwargs["skill_id"], token_scopes=kwargs["scopes"])
            self.impact_recorder.record("protected_resource_modified", "downstream-peer", resource_id=self.resource.resource_id, before=before, after=self.resource.snapshot())
        elif attack == "C2":
            marker = f"C2::{case_id}"
            artifact["parts"][0]["data"] = {"html": f'<div data-carddiff-marker="{marker}">Preview content</div>'}
            artifact["parts"][0].setdefault("metadata", {})["mimeType"] = self.manifest_case["impact_artifact_mime"]
        return artifact

    def record_artifact_accepted(self, *, artifact_id: str, mime_type: str, accepted_output_modes: list[str]) -> None:
        super().record_artifact_accepted(artifact_id=artifact_id, mime_type=mime_type, accepted_output_modes=accepted_output_modes)
        attack, case_id = self.manifest_case["attack_type"], self.manifest_case["case_id"]
        if attack in {"B1", "B3"}:
            self.impact_recorder.record("forged_artifact_accepted", "carddiff-host", marker=f"{attack}-FORGERY::{case_id}")
        if attack == "C2" and mime_type not in accepted_output_modes:
            marker = f"C2::{case_id}"
            self.renderer_state["marker"] = marker
            self.impact_recorder.record("active_content_processed", "mock-renderer", marker=marker, mime_type=mime_type)

    def complete(self) -> None:
        self.impact_recorder.record("impact_trial_completed", "harness", resource_id=self.resource.resource_id)
