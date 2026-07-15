from __future__ import annotations

import json
import os
import socket
import threading
import time
from typing import Any, Callable

from harness.transfer_native.base import NativeProtocolEnvironment
from harness.transfer_native.contracts import NativeExecution


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))


class NLIPNativeEnvironment(NativeProtocolEnvironment):
    protocol = "nlip"

    def __init__(self, case: dict[str, Any], *, client_factory: Callable[[str], Any] | None = None) -> None:
        super().__init__(case)
        self.client_factory = client_factory or self._sdk_client
        self.clients: dict[str, Any] = {}
        self.session_owners: dict[str, str] = {}
        self.peer_url: str | None = None
        self._server: Any | None = None
        self._server_thread: threading.Thread | None = None

    @staticmethod
    def _sdk_client(url: str) -> Any:
        try:
            from nlip_client.nlip_client import NLIP_HTTPX_Client
        except ModuleNotFoundError as exc:  # pragma: no cover - source dependency for formal run
            raise RuntimeError(
                "The maintained nlip_client source package is required; no custom HTTP wrapper is permitted."
            ) from exc
        return NLIP_HTTPX_Client.create_from_url(url)

    def start(self) -> None:
        self.clients.clear()
        self.session_owners.clear()
        configured = os.getenv("CARDDIFF_NLIP_PEER_URL")
        if configured:
            self.peer_url = configured
            return
        try:
            import uvicorn
            from nlip_server.server import create_app
            from harness.transfer_native.nlip.application import build_nlip_application
        except ModuleNotFoundError as exc:  # pragma: no cover - formal dependency
            raise RuntimeError("A native nlip_server runtime is required; no generic endpoint fallback is permitted.") from exc
        native = self.case["native"]
        operations = {
            str(item["id"]) for item in self.case["canonical_state"].get("capabilities", []) if item.get("id")
        }
        operations.add(str(native["operation"]))
        sensitive_operation = str(native.get("sensitive_operation"))
        authorization = {
            operation: (
                ["privileged_user"]
                if operation == sensitive_operation
                else ["normal_user", "privileged_user"]
            )
            for operation in operations
        }
        application = build_nlip_application(
            authorization,
            {"format": native["response_format"], "subformat": native["response_subformat"]},
        )
        app = create_app(application)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        self._server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        self._server_thread = threading.Thread(target=self._server.run, daemon=True)
        self._server_thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started and self._server_thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self._server.started:
            raise RuntimeError("Native NLIP server failed to start.")
        self.peer_url = f"http://127.0.0.1:{port}/nlip"

    def stop(self) -> None:
        self.clients.clear()
        self.session_owners.clear()
        if self._server is not None:
            self._server.should_exit = True
        if self._server_thread is not None:
            self._server_thread.join(timeout=10)
        self._server = None
        self._server_thread = None
        self.peer_url = None

    def _message(self, step: dict[str, Any], operation: str) -> Any:
        try:
            from nlip_sdk.nlip import NLIP_Factory
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError("nlip_sdk==0.1.2 is required; dict messages are forbidden.") from exc
        native = self.case["native"]
        fmt = native.get("request_format", "structured")
        if fmt == "text":
            message = NLIP_Factory.create_text(self.case["task"], native.get("request_subformat", "english"))
        else:
            message = NLIP_Factory.create_json(
                {
                    "task": self.case["task"],
                    "operation": operation,
                    "identity": step["identity_label"],
                }
            )
        message.add_authentication_token(str(step["token_label"]))
        return message

    def execute(self, decision: dict[str, Any]) -> NativeExecution:
        native = self.case["native"]
        facts: dict[str, Any] = dict(native.get("oracle_facts", {}))
        response_payload: dict[str, Any] | None = None
        if self.peer_url is None:
            raise RuntimeError("NLIP peer was not initialized.")
        base_url = self.peer_url
        for step_index, step in enumerate(native["identity_sequence"]):
            identity = str(step["identity_label"])
            session_key = str(step.get("session_key", identity))
            if step.get("resume_session") and session_key in self.clients:
                client = self.clients[session_key]
                owner = self.session_owners[session_key]
            else:
                client = self.client_factory(base_url)
                self.clients[session_key] = client
                self.session_owners[session_key] = identity
                owner = identity
            self.evidence.record("nlip_session_created_or_resumed", session_key=session_key, owner=owner)
            self.evidence.record("nlip_identity_bound", identity=identity, session_key=session_key)
            operation = str(native["operation"])
            if self.case["attack_type"] != "A3" or step_index == len(native["identity_sequence"]) - 1:
                if decision.get("capability_id") is None or decision.get("interface_index") is None:
                    raise ValueError(
                        "NLIP dispatch requires explicit capability_id and interface_index; fallback is disabled."
                    )
                operation = str(decision["capability_id"])
            message = self._message(step, operation)
            self.evidence.record(
                "nlip_sdk_message_constructed",
                format=_enum_value(message.format),
                subformat=_enum_value(message.subformat),
            )
            serialized = message.to_json()
            self.evidence.record("nlip_sdk_message_serialized", byte_length=len(serialized.encode("utf-8")))
            self.evidence.record("nlip_client_request_sent", url=base_url, step_index=step_index)
            response = client.send(message)
            evidence_values = response.extract_field_list("structured", "JSON", "carddiff-native-evidence")
            server_evidence: dict[str, Any] | None = None
            for value in evidence_values:
                if isinstance(value, dict):
                    server_evidence = value
                    break
                if isinstance(value, str):
                    try:
                        decoded = json.loads(value)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(decoded, dict):
                        server_evidence = decoded
                        break
            if server_evidence is None:
                raise TypeError("NLIP native evidence submessage did not decode to an object.")
            if server_evidence.get("decoded"):
                self.evidence.record("nlip_server_message_decoded", step_index=step_index)
            if server_evidence.get("handler_started"):
                self.evidence.record("nlip_application_handler_started", step_index=step_index)
            if server_evidence.get("handler_completed"):
                self.evidence.record("nlip_application_handler_completed", step_index=step_index)
            if server_evidence.get("response_serialized"):
                self.evidence.record("nlip_response_serialized", step_index=step_index)
            self.evidence.record(
                "nlip_client_response_decoded",
                format=_enum_value(response.format),
                subformat=_enum_value(response.subformat),
            )
            host_accept = bool(decision.get("accept_output"))
            self.evidence.record("nlip_output_policy_applied", accepted=host_accept)
            response_payload = response.to_dict()
            sensitive = operation == native.get("sensitive_operation")
            returned_type = f"{_enum_value(response.format)}/{_enum_value(response.subformat)}"
            facts.update(
                {
                    "current_identity": identity,
                    "cached_state_owner": owner,
                    "privileged_operation_attempted": sensitive,
                    "sensitive_native_request_sent": sensitive,
                    "sensitive_operation_completed": bool(server_evidence.get("operation_completed")),
                    "authorized": bool(server_evidence.get("authorized")),
                    "returned_native_output_type": returned_type,
                    "host_accept_output": host_accept,
                }
            )
        return NativeExecution(self.protocol, self.case["attack_type"], self.evidence.events, facts, response_payload)
