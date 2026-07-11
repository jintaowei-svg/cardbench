from __future__ import annotations

from copy import deepcopy
from typing import Any

import httpx
from httpx import ASGITransport

from harness.carddiff_env import CardDiffRuntime, _replace_placeholder
from harness.transfer.base import TransferEnvironmentBase
from harness.transfer.official_a2a_peer import build_peer_app
from harness.transfer.official_a2a_projection import SDKResolvedCard, resolve_control_state
from sut.transfer.official_a2a_protocol import A2ACardResolver, AgentCard, SDK_VERSION, run_async


class OfficialSDKCardDiffEnvironment(TransferEnvironmentBase):
    transfer_target = "official_a2a"
    transport = "httpx-asgi"
    implementation_version = "official-a2a-l3"

    def __init__(self, metadata: dict[str, Any], trial_index: int, **kwargs: Any) -> None:
        if kwargs.pop("require_sdk", True) is not True:
            raise ValueError("Official A2A experiments must require the SDK.")
        super().__init__(metadata, trial_index, **kwargs)
        self.httpx_client: httpx.AsyncClient | None = None
        self.app: Any | None = None

    def __enter__(self) -> "OfficialSDKCardDiffEnvironment":
        base_url = "http://carddiff.a2a.local"
        self.metadata = _replace_placeholder(self.original_metadata, base_url)
        self.runtime = CardDiffRuntime(base_url=base_url,
            public_card=deepcopy(self.metadata["agent"]["public_card"]),
            extended_cards=deepcopy(self.metadata["agent"]["extended_cards"]))
        self.app = build_peer_app(self)
        self.httpx_client = httpx.AsyncClient(transport=ASGITransport(app=self.app), base_url=base_url)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.httpx_client is not None:
            run_async(self.httpx_client.aclose())

    async def sdk_resolve_public_card(self, *, token_label: str) -> SDKResolvedCard:
        assert self.httpx_client is not None
        resolver = A2ACardResolver(self.httpx_client, self._runtime().base_url,
                                   agent_card_path="/.well-known/agent-card.json")
        card = await resolver.get_agent_card()
        extension_response = await self.httpx_client.get("/.well-known/carddiff-control-plane.json")
        extension_response.raise_for_status()
        resolved = resolve_control_state(card, extension_response.json(), expected_scope="public")
        evidence = self.protocol_evidence({"cardHash": resolved.card_hash})
        self.record_native_event("a2a_sdk_agent_card_resolved", evidence)
        self.recorder.record("agent_card_fetched", "carddiff_server", actor_id="sut", evidence=evidence)
        return resolved

    async def sdk_resolve_extended_card(self, *, token_label: str, identity: str) -> SDKResolvedCard:
        assert self.httpx_client is not None
        response = await self.httpx_client.get("/extendedAgentCard",
            headers={"Authorization": f"Bearer carddiff-token-{token_label}"})
        response.raise_for_status(); payload = response.json()
        card = AgentCard.model_validate(payload["agentCard"])
        resolved = resolve_control_state(card, payload["extension"], expected_scope="extended")
        self.record_native_event("a2a_sdk_extended_card_validated", self.protocol_evidence({"cardHash": resolved.card_hash}))
        return resolved

    def httpx_client_for(self, token_label: str) -> httpx.AsyncClient:
        if self.app is None:
            raise RuntimeError("Official A2A peer has not been started.")
        return httpx.AsyncClient(transport=ASGITransport(app=self.app), base_url=self._runtime().base_url,
            headers={"Authorization": f"Bearer carddiff-token-{token_label}"})

    def protocol_evidence(self, metadata: dict[str, Any]) -> dict[str, Any]:
        return {"sdk_version": SDK_VERSION, "sdk_class": "a2a-sdk",
            "card_hash": metadata.get("cardHash"), "interface_index": metadata.get("selectedInterfaceIndex"),
            "selected_url": metadata.get("selectedUrl"), "selected_tenant": metadata.get("selectedTenant"),
            "protocol_binding": metadata.get("selectedProtocolBinding"),
            "protocol_version": metadata.get("selectedProtocolVersion")}

    @property
    def metrics(self) -> dict[str, Any]:
        client_used = any(x["event_type"] == "a2a_sdk_client_created" for x in self.events)
        server_used = any(x["event_type"] == "a2a_sdk_executor_started" for x in self.events)
        execution = {"target": "official_a2a", "backend": "a2a-sdk", "sdk_version": SDK_VERSION,
            "transport": "httpx-asgi", "resolver_used": any(x["event_type"] == "a2a_sdk_agent_card_resolved" for x in self.events),
            "client_factory_used": client_used, "sdk_message_used": any(x["event_type"] == "a2a_sdk_message_constructed" for x in self.events),
            "sdk_server_used": server_used, "executor_used": server_used, "fallback_used": False}
        return {**super().metrics, "protocol_backend": "official-a2a-sdk", "sdk_version": SDK_VERSION,
            "sdk_client_used": client_used, "sdk_server_used": server_used, "protocol_execution": execution}
