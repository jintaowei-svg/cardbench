from __future__ import annotations

import os
import socket
import threading
import time
from typing import Any, Callable

from harness.transfer_native.anp.discovery import DiscoveredANPAgent, discover_agent, invoke
from harness.transfer_native.anp.identity import ANPIdentityResolver
from harness.transfer_native.base import NativeProtocolEnvironment
from harness.transfer_native.contracts import NativeExecution


class ANPNativeEnvironment(NativeProtocolEnvironment):
    protocol = "anp"

    def __init__(
        self,
        case: dict[str, Any],
        *,
        resolver: ANPIdentityResolver | None = None,
        discover: Callable[[str, Any], DiscoveredANPAgent] = discover_agent,
        caller: Callable[..., Any] = invoke,
    ) -> None:
        super().__init__(case)
        self.resolver = resolver or ANPIdentityResolver()
        self.discover = discover
        self.caller = caller
        self.cache: dict[str, tuple[str, DiscoveredANPAgent]] = {}
        self.prepared_cache_keys: set[str] = set()
        self.peer_base_url: str | None = None
        self._server: Any | None = None
        self._server_thread: threading.Thread | None = None

    def start(self) -> None:
        self.cache.clear()
        self.prepared_cache_keys.clear()
        configured = os.getenv("CARDDIFF_ANP_PEER_BASE_URL")
        if configured:
            self.peer_base_url = configured.rstrip("/")
            return
        try:
            import uvicorn
            from harness.transfer_native.anp.peer import build_openanp_application
        except ModuleNotFoundError as exc:  # pragma: no cover - formal dependency
            raise RuntimeError("A native OpenANP server runtime is required; no HTTP fallback is permitted.") from exc
        app = build_openanp_application(self.case)
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
            raise RuntimeError("Native OpenANP server failed to start.")
        self.peer_base_url = f"http://127.0.0.1:{port}"

    def stop(self) -> None:
        self.cache.clear()
        self.prepared_cache_keys.clear()
        if self._server is not None:
            self._server.should_exit = True
        if self._server_thread is not None:
            self._server_thread.join(timeout=10)
        self._server = None
        self._server_thread = None
        self.peer_base_url = None

    def _url(self, value: str) -> str:
        base = self.peer_base_url or os.getenv("CARDDIFF_ANP_PEER_BASE_URL", "").rstrip("/")
        if not base:
            raise RuntimeError("ANP peer base URL is unavailable.")
        return value.replace("{{anp_peer_base_url}}", base)

    def _discover_for(self, step: dict[str, Any]) -> tuple[str, DiscoveredANPAgent]:
        label = str(step["identity_label"])
        did = str(step["did"])
        identity = self.resolver.resolve(label, did)
        self.evidence.record("anp_identity_resolved", identity=label, did=did)
        ad_url = self._url(str(step["agent_description_url"]))
        self.evidence.record("anp_agent_description_fetched", url=ad_url)
        discovered = self.discover(ad_url, identity.build_auth())
        self.evidence.record("anp_agent_description_parsed", url=ad_url)
        interface_urls = sorted({method.rpc_url for method in discovered.methods})
        self.evidence.record("anp_interface_document_fetched", urls=interface_urls)
        self.evidence.record("anp_openrpc_parsed", method_names=[m.name for m in discovered.methods])
        return label, discovered

    def prepare(self) -> dict[str, Any]:
        """Discover native ANP documents before constructing the LLM view."""
        native = self.case["native"]
        first_step = native["identity_sequence"][0]
        cache_key = str(first_step.get("cache_key", native["agent_id"]))
        owner, discovered = self._discover_for(first_step)
        self.cache[cache_key] = (owner, discovered)
        self.prepared_cache_keys.add(cache_key)

        configured = self.case["canonical_state"]
        capability_metadata = {
            str(item.get("id")): item for item in configured.get("capabilities", []) if isinstance(item, dict)
        }
        capabilities = []
        seen_methods: set[str] = set()
        for method in discovered.methods:
            if method.name in seen_methods:
                continue
            seen_methods.add(method.name)
            metadata = capability_metadata.get(method.name, {})
            capabilities.append(
                {
                    "id": method.name,
                    "name": metadata.get("name", method.name),
                    "description": method.description,
                    "required_scopes": metadata.get("required_scopes", metadata.get("security", [])),
                    "output_modes": metadata.get("output_modes", metadata.get("outputModes", [])),
                }
            )
        configured_interfaces = [item for item in configured.get("interfaces", []) if isinstance(item, dict)]
        interfaces = []
        seen_urls: set[str] = set()
        for method in discovered.methods:
            url = str(method.rpc_url)
            if url in seen_urls:
                continue
            seen_urls.add(url)
            metadata = configured_interfaces[len(interfaces)] if len(interfaces) < len(configured_interfaces) else {}
            interfaces.append(
                {
                    "url": url,
                    "tenant": metadata.get("tenant"),
                    "protocol": "openrpc-jsonrpc",
                    "version": metadata.get("version", "1.3.2"),
                }
            )
        return {**configured, "capabilities": capabilities, "interfaces": interfaces}

    def execute(self, decision: dict[str, Any] | list[dict[str, Any] | None]) -> NativeExecution:
        native = self.case["native"]
        attack = self.case["attack_type"]
        steps = native["identity_sequence"]
        facts: dict[str, Any] = {
            key: self._url(value) if isinstance(value, str) else value
            for key, value in native.get("oracle_facts", {}).items()
        }
        response: dict[str, Any] | None = None
        for step_index, step in enumerate(steps):
            phase_decision = (
                decision[step_index]
                if isinstance(decision, list) and step_index < len(decision)
                else decision
            )
            cache_key = str(step.get("cache_key", native["agent_id"]))
            label = str(step["identity_label"])
            prepared = cache_key in self.prepared_cache_keys and step_index == 0
            if (prepared or step.get("reuse_cached_discovery")) and cache_key in self.cache:
                cached_owner, discovered = self.cache[cache_key]
                if step.get("reuse_cached_discovery"):
                    facts["cached_state_owner"] = cached_owner
            else:
                cached_owner, discovered = self._discover_for(step)
                self.cache[cache_key] = (cached_owner, discovered)
            if (
                attack == "A3"
                and not isinstance(decision, list)
                and step_index < len(steps) - 1
            ):
                # Compatibility path used only for exact replacement of the
                # frozen pre-revision run. New formal runs pass a decision list.
                continue
            if phase_decision is None:
                continue
            if phase_decision.get("capability_id") is None or phase_decision.get("interface_index") is None:
                raise ValueError("ANP dispatch requires explicit capability_id and interface_index; fallback is disabled.")
            method = str(phase_decision["capability_id"])
            candidates = [item for item in discovered.methods if item.name == method]
            if not candidates:
                raise RuntimeError(f"Decision selected undiscovered ANP method {method!r}.")
            interface_urls = list(dict.fromkeys(str(item.rpc_url) for item in discovered.methods))
            selected_index = int(phase_decision["interface_index"])
            if selected_index < 1 or selected_index > len(interface_urls):
                raise RuntimeError(f"Decision selected ANP interface index {selected_index} outside discovery.")
            selected_url = interface_urls[selected_index - 1]
            selected_method = next((item for item in candidates if str(item.rpc_url) == selected_url), None)
            if selected_method is None:
                raise RuntimeError(f"ANP method {method!r} is unavailable at selected interface {selected_url!r}.")
            destination = str(selected_method.rpc_url)
            sdk_agent = discovered.sdk_agent
            selected_sdk_agent = type(sdk_agent)(
                url=sdk_agent.url,
                name=sdk_agent.name,
                description=sdk_agent.description,
                methods=(selected_method,),
                _auth=sdk_agent._auth,
            )
            selected_discovered = DiscoveredANPAgent(selected_sdk_agent, discovered.ad_url, (selected_method,))
            self.evidence.record(
                "anp_jsonrpc_request_constructed", method=method, destination=destination, step_index=step_index
            )
            self.evidence.record(
                "anp_client_request_sent", method=method, destination=destination, step_index=step_index
            )
            result = self.caller(
                selected_discovered,
                method,
                task=self.case["task"],
                identity=label,
                token_label=step["token_label"],
            )
            if not isinstance(result, dict):
                result = {"result": result}
            server_events = set(result.pop("_carddiff_native_events", []))
            if "handler_started" in server_events:
                self.evidence.record("anp_server_handler_started", method=method, step_index=step_index)
            if "handler_completed" in server_events:
                self.evidence.record("anp_server_handler_completed", method=method, step_index=step_index)
            self.evidence.record("anp_response_decoded", method=method, step_index=step_index)
            response = result
            facts.update(
                {
                    "actual_request_destination": destination,
                    "selected_candidate": destination,
                    "native_request_sent_to_selected_candidate": True,
                    "selected_option": destination,
                    "native_request_used_selected_option": True,
                    "current_identity": label,
                    "privileged_operation_attempted": method == native.get("sensitive_method"),
                    "sensitive_native_request_sent": method == native.get("sensitive_method"),
                    "sensitive_operation_completed": bool(result.get("completed")),
                    "authorized": bool(result.get("authorized")),
                }
            )
        return NativeExecution(self.protocol, attack, self.evidence.events, facts, response)
