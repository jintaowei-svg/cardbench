from __future__ import annotations

import hashlib
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from agntcy.dir_sdk.client import Client, Config
from agntcy.dir_sdk.models import core_v1, routing_v1, search_v1
from google.protobuf.json_format import MessageToDict

from harness.carddiff_env import _replace_placeholder
from harness.transfer.official_a2a_env import OfficialSDKCardDiffEnvironment
from harness.transfer.official_a2a_projection import (
    build_control_extension,
    build_sdk_agent_card,
    project_selected_interface,
    resolve_control_state,
)
from harness.transfer_native.base import NativeProtocolEnvironment
from harness.transfer_native.contracts import NativeExecution
from sut.transfer.official_a2a_protocol import (
    ClientConfig,
    ClientFactory,
    build_message,
    normalize_sdk_result,
    run_async,
)


ROOT = Path(__file__).resolve().parents[3]


def _option(interface: dict[str, Any]) -> str:
    return "|".join(
        str(interface.get(key, ""))
        for key in ("protocolBinding", "protocolVersion", "url")
    )


class AGNTCYNativeEnvironment(NativeProtocolEnvironment):
    """Directory Store/Search/Pull discovery followed by official A2A execution."""

    protocol = "agntcy"

    def __init__(self, case: dict[str, Any]) -> None:
        super().__init__(case)
        self.client: Client | None = None
        self.refs: list[Any] = []
        self.pulled_card: dict[str, Any] | None = None
        self.a2a_env: OfficialSDKCardDiffEnvironment | None = None

    def start(self) -> None:
        source = deepcopy(self.case["source"])
        source["attack_type"] = self.case["attack_type"]
        self.a2a_env = OfficialSDKCardDiffEnvironment(source, 0)
        self.a2a_env.__enter__()
        address = os.getenv("CARDDIFF_AGNTCY_DIRECTORY_ADDRESS", "127.0.0.1:8888")
        dirctl = os.getenv(
            "CARDDIFF_AGNTCY_DIRCTL_PATH",
            str(
                ROOT
                / ".codex_work"
                / "agntcy-dir-v1.5.0"
                / "dirctl-windows-amd64.exe"
            ),
        )
        self.client = Client(Config(server_address=address, dirctl_path=dirctl))
        self.evidence.record("agntcy_directory_connected", address=address)

    def stop(self) -> None:
        if self.client is not None and self.refs:
            record_refs = routing_v1.RecordRefs(refs=self.refs)
            try:
                self.client.unpublish(
                    routing_v1.UnpublishRequest(record_refs=record_refs)
                )
            finally:
                self.client.delete(self.refs)
        self.refs = []
        self.client = None
        if self.a2a_env is not None:
            self.a2a_env.__exit__(None, None, None)
        self.a2a_env = None

    def _record(self, card: dict[str, Any]) -> Any:
        suffix = hashlib.sha256(
            self.case["target_case_id"].encode("utf-8")
        ).hexdigest()[:16]
        annotation = f"carddiff_{suffix}"
        self.case["native"]["runtime_annotation"] = annotation
        return core_v1.Record(
            data={
                "name": annotation,
                "schema_version": "1.0.0",
                "version": "1.0.0",
                "description": "CardDiffBench AGNTCY discovery trial",
                "authors": ["CardDiffBench"],
                "created_at": "2026-07-16T00:00:00Z",
                "skills": [
                    {
                        "name": "natural_language_processing/natural_language_understanding/contextual_comprehension",
                        "id": 10101,
                    }
                ],
                "locators": [
                    {
                        "type": "source_code",
                        "urls": ["https://example.invalid/carddiffbench"],
                    }
                ],
                "annotations": {"carddiff_case": annotation},
                "modules": [
                    {
                        "name": "integration/a2a",
                        "data": {
                            "card_data": card,
                            "card_schema_version": "v1.0.0",
                        },
                    }
                ],
            }
        )

    def prepare(self) -> dict[str, Any]:
        if self.client is None or self.a2a_env is None:
            raise RuntimeError("AGNTCY environment is not started.")
        base_url = self.a2a_env._runtime().base_url
        runtime_card = _replace_placeholder(
            deepcopy(self.case["native"]["runtime_card"]), base_url
        )
        record = self._record(runtime_card)
        self.refs = self.client.push([record])
        if len(self.refs) != 1:
            raise RuntimeError("AGNTCY Store.push did not return exactly one CID.")
        cid = str(self.refs[0].cid)
        self.evidence.record("agntcy_record_pushed", cid=cid, schema_version="1.0.0")
        record_refs = routing_v1.RecordRefs(refs=self.refs)
        self.client.publish(routing_v1.PublishRequest(record_refs=record_refs))
        self.evidence.record("agntcy_record_published", cid=cid)
        annotation = self.case["native"]["runtime_annotation"]
        query = search_v1.RecordQuery(
            type=search_v1.RECORD_QUERY_TYPE_ANNOTATION,
            value=f"carddiff_case:{annotation}",
        )
        results = list(
            self.client.search_cids(
                search_v1.SearchCIDsRequest(queries=[query], limit=10)
            )
        )
        discovered = [str(item.record_cid) for item in results]
        if cid not in discovered:
            raise RuntimeError("AGNTCY Search did not return the pushed record CID.")
        self.evidence.record(
            "agntcy_record_discovered", cid=cid, query=f"carddiff_case:{annotation}"
        )
        pulled = self.client.pull(self.refs)
        if len(pulled) != 1:
            raise RuntimeError("AGNTCY Store.pull did not return exactly one record.")
        payload = MessageToDict(pulled[0], preserving_proto_field_name=True)
        modules = payload["data"]["modules"]
        module = next(item for item in modules if item["name"] == "integration/a2a")
        self.pulled_card = module["data"]["card_data"]
        self.evidence.record("agntcy_record_pulled", cid=cid)
        state = deepcopy(self.case["canonical_state"])
        state["capabilities"] = deepcopy(self.pulled_card.get("skills", []))
        state["interfaces"] = deepcopy(
            self.pulled_card.get("supportedInterfaces", [])
        )
        return state

    def execute(self, decision: dict[str, Any]) -> NativeExecution:
        if self.pulled_card is None or self.a2a_env is None:
            raise RuntimeError("AGNTCY record must be discovered before execution.")
        capability_id = str(decision["capability_id"])
        skills = [
            item
            for item in self.pulled_card.get("skills", [])
            if str(item.get("id")) == capability_id
        ]
        if not skills:
            raise RuntimeError(f"Decision selected undiscovered skill {capability_id!r}.")
        interfaces = self.pulled_card.get("supportedInterfaces", [])
        index = int(decision["interface_index"])
        if index < 1 or index > len(interfaces):
            raise RuntimeError("Decision selected an interface outside the pulled AGNTCY card.")
        interface = interfaces[index - 1]
        sdk_card = build_sdk_agent_card(
            self.pulled_card, base_url=self.a2a_env._runtime().base_url
        )
        extension = build_control_extension(
            self.pulled_card,
            sdk_card,
            card_scope="agntcy-directory",
            identity=self.case["canonical_state"].get("identity"),
        )
        resolved = resolve_control_state(sdk_card, extension)
        invocation_card = project_selected_interface(
            resolved, interface, base_url=self.a2a_env._runtime().base_url
        )
        self.evidence.record(
            "agntcy_a2a_card_projected", interface_index=index, url=interface.get("url")
        )
        auth = self.case["source"]["public"]["auth_sequence"][-1]
        token_label = str(auth["token_label"])
        transport_client = self.a2a_env.httpx_client_for(token_label)
        client = ClientFactory(
            ClientConfig(httpx_client=transport_client, streaming=False)
        ).create(invocation_card)
        metadata = {
            "skillId": capability_id,
            "cardScopeUsed": "agntcy-directory",
            "selectedInterfaceIndex": index,
            "selectedTenant": interface.get("tenant"),
            "requestTenant": self.case["canonical_state"].get("request_tenant"),
            "selectedProtocolBinding": interface.get("protocolBinding"),
            "selectedProtocolVersion": interface.get("protocolVersion"),
            "acceptedOutputModes": self.case["canonical_state"].get(
                "accepted_output_modes", []
            ),
            "identity": auth["identity"],
            "tokenScopes": self.case["canonical_state"].get("token_scopes", []),
            "selectedUrl": interface.get("url"),
        }
        message = build_message(self.case["task"], metadata)
        self.evidence.record(
            "agntcy_a2a_sdk_message_constructed", capability_id=capability_id
        )

        async def send() -> Any:
            async for event in client.send_message(message):
                return event[0] if isinstance(event, tuple) else event
            return None

        self.evidence.record(
            "agntcy_a2a_sdk_request_sent", url=interface.get("url")
        )
        try:
            result = run_async(send())
        finally:
            run_async(transport_client.aclose())
        peer_events = {item["event_type"] for item in self.a2a_env.events}
        if "a2a_sdk_executor_started" not in peer_events:
            raise RuntimeError("Official A2A peer handler did not start.")
        self.evidence.record("agntcy_a2a_peer_handler_started")
        if "a2a_sdk_executor_completed" not in peer_events:
            raise RuntimeError("Official A2A peer handler did not complete.")
        self.evidence.record("agntcy_a2a_peer_handler_completed")
        response = normalize_sdk_result(result)
        self.evidence.record("agntcy_a2a_sdk_response_decoded")
        base_url = self.a2a_env._runtime().base_url
        facts = _replace_placeholder(
            deepcopy(self.case["native"].get("oracle_facts", {})), base_url
        )
        facts.update(
            {
                "actual_request_destination": interface.get("url"),
                "selected_option": _option(interface),
                "native_request_used_selected_option": True,
            }
        )
        if self.case["attack_type"] == "A2":
            self.evidence.record(
                "agntcy_discovered_destination_selected", url=interface.get("url")
            )
        if self.case["attack_type"] == "B2":
            self.evidence.record(
                "agntcy_binding_option_selected",
                binding=interface.get("protocolBinding"),
                version=interface.get("protocolVersion"),
            )
        return NativeExecution(
            self.protocol,
            self.case["attack_type"],
            self.evidence.events,
            facts,
            response,
        )
