from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from harness.carddiff_events import EventRecorder


A2A_CONTENT_TYPE = "application/a2a+json"


@dataclass
class CardDiffRuntime:
    base_url: str
    public_card: dict[str, Any]
    extended_cards: dict[str, dict[str, Any]]


class LocalCardDiffEnvironment:
    """Trial-scoped A2A HTTP environment for CardDiff cases."""

    def __init__(self, metadata: dict[str, Any], trial_index: int) -> None:
        self.original_metadata = deepcopy(metadata)
        self.metadata: dict[str, Any] = {}
        self.trial_index = trial_index
        self.trial_id = f"{trial_index:04d}"
        self.recorder = EventRecorder(str(metadata["case_id"]), self.trial_id)
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.runtime: CardDiffRuntime | None = None

    def __enter__(self) -> "LocalCardDiffEnvironment":
        env = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                env._handle_get(self)

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
                env._handle_post(self)

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        host, port = self.server.server_address
        base_url = f"http://{host}:{port}"
        self.metadata = _replace_placeholder(self.original_metadata, base_url)
        self.runtime = CardDiffRuntime(
            base_url=base_url,
            public_card=deepcopy(self.metadata["agent"]["public_card"]),
            extended_cards=deepcopy(self.metadata["agent"]["extended_cards"]),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2.0)

    @property
    def public_view(self) -> dict[str, Any]:
        runtime = self._runtime()
        public = self.metadata["public"]
        public_case_id = public.get(
            "public_case_id",
            "workflow-" + hashlib.sha256(self.metadata["case_id"].encode("utf-8")).hexdigest()[:10],
        )
        return {
            "case_id": public_case_id,
            "task": public["task"],
            "agent_base_url": runtime.base_url,
            "auth_sequence": deepcopy(public["auth_sequence"]),
            "accepted_output_modes": list(public["accepted_output_modes"]),
            "request_tenant": public.get("request_tenant"),
        }

    @property
    def events(self) -> list[dict[str, Any]]:
        return self.recorder.to_dicts(include_private=True)

    @property
    def metrics(self) -> dict[str, Any]:
        events = self.events
        return {
            "agent_card_fetches": _count(events, "agent_card_fetched"),
            "extended_agent_card_fetches": _count(events, "extended_agent_card_fetched"),
            "message_sends": _count(events, "message_sent"),
            "artifact_returns": _count(events, "artifact_returned"),
            "artifact_accepts": _count(events, "artifact_accepted"),
            "protocol_backend": "a2a-http-json",
            "base_url": self._runtime().base_url,
        }

    def record_artifact_accepted(
        self,
        *,
        artifact_id: str,
        mime_type: str,
        accepted_output_modes: list[str],
    ) -> None:
        self.recorder.record(
            "artifact_accepted",
            "carddiff_host",
            actor_id="sut",
            evidence={
                "artifact_id": artifact_id,
                "mime_type": mime_type,
                "accepted_output_modes": list(accepted_output_modes),
            },
        )

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        runtime = self._runtime()
        if handler.path == "/.well-known/agent-card.json":
            self.recorder.record(
                "agent_card_fetched",
                "carddiff_server",
                actor_id="sut",
                evidence={
                    "endpoint": handler.path,
                    "url": f"{runtime.base_url}{handler.path}",
                },
            )
            _send_json(handler, 200, runtime.public_card)
            return

        if handler.path == "/extendedAgentCard":
            token_label = _extract_token_label(handler.headers.get("Authorization", ""))
            token = self.metadata["agent"]["tokens"].get(token_label, {})
            identity = str(token.get("identity", "anonymous"))
            card = runtime.extended_cards.get(identity) or runtime.extended_cards.get("normal_user")
            if card is None:
                _send_json(handler, 401, {"error": "no extended card for identity"})
                return
            self.recorder.record(
                "extended_agent_card_fetched",
                "carddiff_server",
                actor_id="sut",
                evidence={
                    "endpoint": handler.path,
                    "url": f"{runtime.base_url}{handler.path}",
                    "identity": identity,
                    "token_label": token_label,
                    "scopes": list(token.get("scopes", [])),
                    "card_scope": card.get("metadata", {}).get("cardScope"),
                },
                private_tags={"identity": identity},
            )
            _send_json(handler, 200, card)
            return

        _send_json(handler, 404, {"error": f"unknown endpoint {handler.path}"})

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        if not handler.path.endswith("/message:send"):
            _send_json(handler, 404, {"error": f"unknown endpoint {handler.path}"})
            return

        runtime = self._runtime()
        length = int(handler.headers.get("Content-Length", "0"))
        raw_body = handler.rfile.read(length).decode("utf-8")
        try:
            body = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            body = {}
        token_label = _extract_token_label(handler.headers.get("Authorization", ""))
        token = self.metadata["agent"]["tokens"].get(token_label, {})
        identity = str(token.get("identity", "anonymous"))
        scopes = list(token.get("scopes", []))
        selected_url = _selected_interface_url(runtime.base_url, handler.path)
        selected_interface = _find_interface(self.metadata, selected_url, handler.headers)
        selected_tenant = selected_interface.get("tenant") if selected_interface else None
        message = body.get("message", {}) if isinstance(body, dict) else {}
        metadata = body.get("metadata", {}) if isinstance(body, dict) else {}
        configuration = body.get("configuration", {}) if isinstance(body, dict) else {}
        skill_id = str(metadata.get("skillId", ""))
        request_tenant = message.get("tenant")
        accepted_modes = list(configuration.get("acceptedOutputModes", []))
        binding = selected_interface.get("protocolBinding") if selected_interface else "HTTP+JSON"
        version = handler.headers.get("A2A-Version") or (
            selected_interface.get("protocolVersion") if selected_interface else None
        )

        self.recorder.record(
            "message_sent",
            "carddiff_server",
            actor_id="sut",
            evidence={
                "endpoint": handler.path,
                "url": f"{runtime.base_url}{handler.path}",
                "selected_url": selected_url,
                "content_type": handler.headers.get("Content-Type"),
                "identity": identity,
                "token_label": token_label,
                "token_scopes": scopes,
                "skill_id": skill_id,
                "request_tenant": request_tenant,
                "selected_tenant": selected_tenant,
                "selected_protocolBinding": binding,
                "selected_protocolVersion": version,
                "accepted_output_modes": accepted_modes,
                "card_scope_used": metadata.get("cardScopeUsed"),
            },
            private_tags={"identity": identity, "token_label": token_label},
        )
        self.recorder.record(
            "tenant_bound",
            "carddiff_server",
            actor_id="sut",
            evidence={
                "request_tenant": request_tenant,
                "selected_tenant": selected_tenant,
            },
        )
        self.recorder.record(
            "security_scope_used",
            "carddiff_server",
            actor_id="sut",
            evidence={
                "identity": identity,
                "token_scopes": scopes,
                "skill_id": skill_id,
                "required_scopes": _skill_required_scopes(self.metadata, skill_id),
            },
        )

        required_scopes = set(_skill_required_scopes(self.metadata, skill_id))
        if required_scopes and not required_scopes.issubset(set(scopes)):
            _send_json(
                handler,
                403,
                {
                    "error": "insufficient_scope",
                    "requiredScopes": sorted(required_scopes),
                },
            )
            return

        artifact = deepcopy(self.metadata["agent"]["response"]["artifact"])
        mime_type = _artifact_mime_type(artifact)
        task = {
            "id": f"task-{self.trial_id}",
            "contextId": f"context-{self.trial_id}",
            "status": {"state": "completed"},
            "artifacts": [artifact],
            "kind": "task",
        }
        self.recorder.record(
            "artifact_returned",
            "carddiff_server",
            actor_id="remote-agent",
            evidence={
                "artifact_id": artifact.get("artifactId"),
                "mime_type": mime_type,
                "skill_id": skill_id,
            },
        )
        _send_json(handler, 200, task)

    def _runtime(self) -> CardDiffRuntime:
        if self.runtime is None:
            raise RuntimeError("CardDiff environment has not been started.")
        return self.runtime


def _replace_placeholder(value: Any, base_url: str) -> Any:
    if isinstance(value, str):
        return value.replace("{{base_url}}", base_url)
    if isinstance(value, list):
        return [_replace_placeholder(item, base_url) for item in value]
    if isinstance(value, dict):
        return {key: _replace_placeholder(item, base_url) for key, item in value.items()}
    return value


def _send_json(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", A2A_CONTENT_TYPE)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _extract_token_label(header_value: str) -> str:
    prefix = "Bearer carddiff-token-"
    if header_value.startswith(prefix):
        return header_value[len(prefix):]
    return ""


def _selected_interface_url(base_url: str, message_path: str) -> str:
    suffix = "/message:send"
    interface_path = message_path[: -len(suffix)] if message_path.endswith(suffix) else message_path
    return f"{base_url}{interface_path}"


def _find_interface(
    metadata: dict[str, Any],
    selected_url: str,
    headers: Any,
) -> dict[str, Any]:
    version = headers.get("A2A-Version")
    candidates: list[dict[str, Any]] = []
    cards = [metadata["agent"]["public_card"], *metadata["agent"]["extended_cards"].values()]
    for card in cards:
        for interface in card.get("supportedInterfaces", []):
            if interface.get("url") == selected_url:
                candidates.append(interface)
    if not candidates:
        return {}
    if version:
        for interface in candidates:
            if interface.get("protocolVersion") == version:
                return dict(interface)
    return dict(candidates[0])


def _skill_required_scopes(metadata: dict[str, Any], skill_id: str) -> list[str]:
    cards = [metadata["agent"]["public_card"], *metadata["agent"]["extended_cards"].values()]
    for card in cards:
        for skill in card.get("skills", []):
            if skill.get("id") == skill_id:
                return _scopes_from_security(skill.get("security", []))
    return []


def _scopes_from_security(security: list[Any]) -> list[str]:
    scopes: list[str] = []
    for item in security:
        if isinstance(item, dict):
            for value in item.values():
                if isinstance(value, list):
                    scopes.extend(str(scope) for scope in value)
    return scopes


def _artifact_mime_type(artifact: dict[str, Any]) -> str:
    for part in artifact.get("parts", []):
        metadata = part.get("metadata", {})
        if isinstance(metadata, dict) and metadata.get("mimeType"):
            return str(metadata["mimeType"])
    return ""


def _count(events: list[dict[str, Any]], event_type: str) -> int:
    return sum(1 for event in events if event.get("event_type") == event_type)
