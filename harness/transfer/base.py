from __future__ import annotations

from abc import ABC
from copy import deepcopy
from typing import Any

from harness.carddiff_env import LocalCardDiffEnvironment


class TransferEnvironmentBase(LocalCardDiffEnvironment, ABC):
    """Trial-scoped environment contract shared by transfer targets.

    The existing local peer remains the deterministic peer implementation.  Each
    concrete target selects its own public protocol projection and adds native
    telemetry, while keeping the canonical event recorder used by CardDiff
    scoring intact.
    """

    transfer_target = "unknown"
    transport = "in_process"
    implementation_version = "transfer-v1"

    def __init__(self, metadata: dict[str, Any], trial_index: int, **kwargs: Any) -> None:
        remote_agent = kwargs.pop("remote_agent", None)
        remote_mode = kwargs.pop("remote_agent_mode", None)
        if remote_agent is None and remote_mode is not None:
            remote_agent = {"mode": remote_mode}
        self.transfer_kwargs = dict(kwargs)
        super().__init__(metadata, trial_index, remote_agent=remote_agent)

    @property
    def public_view(self) -> dict[str, Any]:
        """Expose the authenticated principal context, not private case data.

        A real protocol stack obtains granted scopes while validating the bearer
        token/DID.  The local deterministic peer performs that validation in the
        harness, so it projects only the resulting identity and granted scopes
        into each auth step.  Attack labels, oracles and expected values never
        cross this boundary.
        """
        view = super().public_view
        token_profiles = self.metadata.get("agent", {}).get("tokens", {})
        auth_sequence: list[dict[str, Any]] = []
        for raw_step in view.get("auth_sequence", []):
            step = deepcopy(raw_step)
            token_label = str(step.get("token_label", ""))
            profile = token_profiles.get(token_label, {})
            profile_identity = profile.get("identity")
            if profile_identity and step.get("identity") != profile_identity:
                raise ValueError(
                    f"Authenticated identity mismatch for token {token_label!r}."
                )
            scopes = profile.get("scopes", [])
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                raise TypeError(f"Token scopes for {token_label!r} must be a list of strings.")
            step["token_scopes"] = list(scopes)
            auth_sequence.append(step)
        view["auth_sequence"] = auth_sequence
        return view

    @property
    def metrics(self) -> dict[str, Any]:
        return {
            **super().metrics,
            "transfer_target": self.transfer_target,
            "transport": self.transport,
            "implementation_version": self.implementation_version,
        }

    def record_native_event(self, event_type: str, evidence: dict[str, Any]) -> None:
        self.recorder.record(event_type, self.transfer_target, actor_id="sut", evidence=evidence)
