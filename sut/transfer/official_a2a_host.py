from __future__ import annotations

import time
from typing import Any

from harness.transfer.official_a2a_projection import SDKResolvedCard, project_selected_interface
from sut.transfer.base import TransferHostBase
from sut.transfer.official_a2a_protocol import (ClientConfig, ClientFactory, SDK_VERSION,
    build_message, normalize_sdk_result, run_async)


class OfficialSDKCardDiffHostSUT(TransferHostBase):
    """CardDiff Host control plane transported end-to-end by a2a-sdk."""

    transfer_target = "official_a2a"
    framework_version = SDK_VERSION

    def __init__(self, *args: Any, require_sdk: bool = True, **kwargs: Any) -> None:
        if require_sdk is not True:
            raise ValueError("Official A2A experiments must require the SDK.")
        super().__init__(*args, **kwargs)

    def _discover_public_card(self, *, env: Any, base_url: str, token_label: str,
                              metrics: dict[str, Any]) -> SDKResolvedCard:
        started = time.perf_counter()
        result = run_async(env.sdk_resolve_public_card(token_label=token_label))
        metrics["protocol_latency_ms"] += (time.perf_counter() - started) * 1000
        return result

    def _discover_extended_card(self, *, env: Any, base_url: str, token_label: str,
                                identity: str, public_card: Any,
                                metrics: dict[str, Any]) -> SDKResolvedCard:
        started = time.perf_counter()
        result = run_async(env.sdk_resolve_extended_card(token_label=token_label, identity=identity))
        metrics["protocol_latency_ms"] += (time.perf_counter() - started) * 1000
        return result

    def _invoke_selected_interface(self, *, env: Any, resolved_card: SDKResolvedCard,
            interface: dict[str, Any], interface_index: int, skill: dict[str, Any], task: str,
            token_label: str, identity: str, token_scopes: list[str], card_scope_used: str,
            accepted_output_modes: list[str], request_tenant: Any,
            metrics: dict[str, Any]) -> dict[str, Any]:
        invocation_card = project_selected_interface(resolved_card, interface, base_url=env._runtime().base_url)
        evidence = {"cardHash": resolved_card.card_hash, "selectedInterfaceIndex": interface_index,
            "selectedUrl": interface.get("url"), "selectedTenant": interface.get("tenant"),
            "selectedProtocolBinding": interface.get("protocolBinding"),
            "selectedProtocolVersion": interface.get("protocolVersion")}
        transport_client = env.httpx_client_for(token_label)
        client = ClientFactory(ClientConfig(httpx_client=transport_client, streaming=False)).create(invocation_card)
        env.record_native_event("a2a_sdk_client_created", env.protocol_evidence(evidence))
        metadata = {"skillId": str(skill.get("id", "")), "cardScopeUsed": card_scope_used,
            "selectedInterfaceIndex": interface_index, "selectedTenant": interface.get("tenant"),
            "requestTenant": request_tenant, "selectedProtocolBinding": interface.get("protocolBinding"),
            "selectedProtocolVersion": interface.get("protocolVersion"),
            "acceptedOutputModes": accepted_output_modes,
            "identity": identity, "tokenScopes": token_scopes, "cardHash": resolved_card.card_hash,
            "selectedUrl": interface.get("url")}
        message = build_message(task, metadata)
        env.record_native_event("a2a_sdk_message_constructed", env.protocol_evidence(evidence))

        async def send() -> Any:
            async for event in client.send_message(message):
                return event[0] if isinstance(event, tuple) else event
            return None

        started = time.perf_counter()
        try:
            result = run_async(send())
        finally:
            run_async(transport_client.aclose())
        metrics["protocol_latency_ms"] += (time.perf_counter() - started) * 1000
        env.record_native_event("a2a_sdk_message_sent", env.protocol_evidence(evidence))
        env.record_native_event("a2a_sdk_response_received", env.protocol_evidence(evidence))
        return normalize_sdk_result(result)
