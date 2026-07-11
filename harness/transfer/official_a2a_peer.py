from __future__ import annotations

from copy import deepcopy
from contextvars import ContextVar
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.middleware.base import BaseHTTPMiddleware

from harness.carddiff_env import _artifact_mime_type, _skill_required_scopes
from harness.transfer.official_a2a_projection import build_control_extension, build_sdk_agent_card
from sut.transfer.official_a2a_protocol import (A2AStarletteApplication, AgentExecutor,
    DataPart, DefaultRequestHandler, EventQueue, InMemoryTaskStore, Message, Part,
    RequestContext, Role, TextPart)


def _token_label(value: str) -> str:
    prefix = "Bearer carddiff-token-"
    return value[len(prefix):] if value.startswith(prefix) else ""


def _mount_path_for_interface_url(url: str, base_url: str) -> str | None:
    endpoint, base = urlsplit(url), urlsplit(base_url)
    if endpoint.scheme != base.scheme or endpoint.netloc != base.netloc:
        return None
    return endpoint.path.rstrip("/") or "/"


_AUTH_TOKEN_LABEL: ContextVar[str] = ContextVar("carddiff_auth_token_label", default="")


class AuthContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = _AUTH_TOKEN_LABEL.set(_token_label(request.headers.get("authorization", "")))
        try:
            return await call_next(request)
        finally:
            _AUTH_TOKEN_LABEL.reset(token)


class CardDiffAgentExecutor(AgentExecutor):
    def __init__(self, env: Any) -> None:
        self.env = env

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = context.message
        metadata = dict(getattr(message, "metadata", None) or {})
        token_label = _AUTH_TOKEN_LABEL.get()
        token = self.env.metadata["agent"]["tokens"].get(token_label, {})
        identity, scopes = str(token.get("identity", "anonymous")), list(token.get("scopes", []))
        skill_id = str(metadata.get("skillId", ""))
        selected_tenant, request_tenant = metadata.get("selectedTenant"), metadata.get("requestTenant")
        evidence = self.env.protocol_evidence(metadata)
        self.env.record_native_event("a2a_sdk_message_received", evidence)
        self.env.record_native_event("a2a_sdk_executor_started", evidence)
        self.env.recorder.record("message_sent", "carddiff_server", actor_id="sut", evidence={
            **evidence, "identity": identity, "token_label": token_label, "token_scopes": scopes,
            "skill_id": skill_id, "request_tenant": request_tenant, "selected_tenant": selected_tenant,
            "selected_protocolBinding": metadata.get("selectedProtocolBinding"),
            "selected_protocolVersion": metadata.get("selectedProtocolVersion"),
            "accepted_output_modes": list(metadata.get("acceptedOutputModes", [])),
            "card_scope_used": metadata.get("cardScopeUsed")}, private_tags={"identity": identity, "token_label": token_label})
        self.env.recorder.record("tenant_bound", "carddiff_server", actor_id="sut",
            evidence={"request_tenant": request_tenant, "selected_tenant": selected_tenant})
        required = _skill_required_scopes(self.env.metadata, skill_id)
        self.env.recorder.record("security_scope_used", "carddiff_server", actor_id="sut",
            evidence={"identity": identity, "token_scopes": scopes, "skill_id": skill_id, "required_scopes": required})
        if set(required) - set(scopes):
            payload = {"kind": "task", "status": {"state": "failed"}, "error": "insufficient_scope", "artifacts": []}
        else:
            body = {"message": message.model_dump(mode="json", by_alias=True), "metadata": metadata}
            artifact = self.env._response_artifact(body=body, identity=identity, scopes=scopes,
                skill_id=skill_id, selected_tenant=selected_tenant, request_tenant=request_tenant,
                accepted_modes=list(metadata.get("acceptedOutputModes", [])))
            payload = {"kind": "task", "id": f"task-{self.env.trial_id}",
                "contextId": f"context-{self.env.trial_id}", "status": {"state": "completed"}, "artifacts": [artifact]}
            self.env.recorder.record("artifact_returned", "carddiff_server", actor_id="remote-agent",
                evidence={"artifact_id": artifact.get("artifactId"), "mime_type": _artifact_mime_type(artifact), "skill_id": skill_id})
        response = Message(role=Role.agent, message_id=str(uuid4()), parts=[Part(root=DataPart(data=payload))])
        await event_queue.enqueue_event(response)
        self.env.record_native_event("a2a_sdk_executor_completed", evidence)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        await event_queue.enqueue_event(Message(role=Role.agent, message_id=str(uuid4()),
            parts=[Part(root=TextPart(text="Cancellation is not supported."))]))


def build_peer_app(env: Any) -> Starlette:
    runtime = env._runtime()
    public_sdk = build_sdk_agent_card(runtime.public_card, base_url=runtime.base_url)
    public_ext = build_control_extension(runtime.public_card, public_sdk, card_scope="public", identity=None)

    async def public_extension(request: Request) -> JSONResponse:
        return JSONResponse(public_ext)

    async def extended(request: Request) -> JSONResponse:
        label = _token_label(request.headers.get("authorization", ""))
        token = env.metadata["agent"]["tokens"].get(label, {})
        identity = str(token.get("identity", "anonymous"))
        raw = runtime.extended_cards.get(identity) or runtime.extended_cards.get("normal_user")
        if raw is None:
            return JSONResponse({"error": "no extended card for identity"}, status_code=401)
        sdk = build_sdk_agent_card(raw, base_url=runtime.base_url)
        ext = build_control_extension(raw, sdk, card_scope="extended", identity=identity)
        env.recorder.record("extended_agent_card_fetched", "carddiff_server", actor_id="sut",
            evidence={"endpoint": "/extendedAgentCard", "identity": identity, "token_label": label,
                      "scopes": list(token.get("scopes", [])), "card_scope": "extended"},
            private_tags={"identity": identity})
        return JSONResponse({"agentCard": sdk.model_dump(mode="json", by_alias=True), "extension": ext})

    handler = DefaultRequestHandler(agent_executor=CardDiffAgentExecutor(env), task_store=InMemoryTaskStore())
    sdk_app = A2AStarletteApplication(agent_card=public_sdk, http_handler=handler).build(
        agent_card_url="/.well-known/agent-card.json")
    paths = {"/"}
    for card in [runtime.public_card, *runtime.extended_cards.values()]:
        for interface in card.get("supportedInterfaces", []):
            path = _mount_path_for_interface_url(str(interface.get("url", "")), runtime.base_url)
            if path is not None:
                paths.add(path)
    routes = [Route("/.well-known/carddiff-control-plane.json", public_extension),
              Route("/extendedAgentCard", extended)]
    routes.extend(Mount(path, app=sdk_app) for path in sorted(paths, key=len, reverse=True) if path != "/")
    routes.append(Mount("/", app=sdk_app))
    app = Starlette(routes=routes)
    app.add_middleware(AuthContextMiddleware)
    return app
