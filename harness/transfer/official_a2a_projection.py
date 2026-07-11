from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sut.transfer.official_a2a_protocol import AgentCapabilities, AgentCard, AgentSkill


@dataclass(frozen=True)
class SDKResolvedCard:
    sdk_card: AgentCard
    raw_sdk_card: dict[str, Any]
    control_state: dict[str, Any]
    card_scope: str
    identity: str | None
    card_hash: str


def _dump(card: AgentCard) -> dict[str, Any]:
    return card.model_dump(mode="json", by_alias=True)


def sdk_card_hash(card: AgentCard) -> str:
    payload = json.dumps(_dump(card), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def build_sdk_agent_card(raw_card: dict[str, Any], *, selected_interface: dict[str, Any] | None = None, base_url: str) -> AgentCard:
    interfaces = raw_card.get("supportedInterfaces", [])
    interface = selected_interface or (interfaces[0] if interfaces else {})
    skills = []
    for item in raw_card.get("skills", []):
        skills.append(AgentSkill(id=str(item["id"]), name=str(item.get("name") or item["id"]),
                                 description=str(item.get("description") or item.get("name") or item["id"]),
                                 tags=[str(x) for x in item.get("tags", [item["id"]])],
                                 examples=[str(x) for x in item.get("examples", [])],
                                 input_modes=[str(x) for x in item.get("inputModes", [])] or None,
                                 output_modes=[str(x) for x in item.get("outputModes", [])] or None))
    url = str(interface.get("url") or raw_card.get("url") or base_url).rstrip("/") + "/"
    return AgentCard(name=str(raw_card.get("name", "CardDiff Agent")),
        description=str(raw_card.get("description", "CardDiff benchmark peer")), url=url,
        version=str(raw_card.get("version", "1.0.0")),
        protocol_version=str(interface.get("protocolVersion", "0.3.0")),
        preferred_transport="JSONRPC", capabilities=AgentCapabilities(streaming=False),
        default_input_modes=[str(x) for x in raw_card.get("defaultInputModes", ["text/plain"])],
        default_output_modes=[str(x) for x in raw_card.get("defaultOutputModes", ["application/json"])],
        skills=skills)


def build_control_extension(raw_card: dict[str, Any], sdk_card: AgentCard, *, card_scope: str, identity: str | None) -> dict[str, Any]:
    state = dict(raw_card)
    state["cardScope"] = card_scope
    state["identity"] = identity
    state["sdkCardSha256"] = sdk_card_hash(sdk_card)
    return state


def resolve_control_state(sdk_card: AgentCard, extension: dict[str, Any], *, expected_scope: str | None = None) -> SDKResolvedCard:
    if not isinstance(extension, dict):
        raise TypeError("CardDiff control extension must be an object.")
    digest = sdk_card_hash(sdk_card)
    if extension.get("sdkCardSha256") != digest:
        raise ValueError("SDK AgentCard and CardDiff extension hash mismatch.")
    scope = str(extension.get("cardScope", ""))
    if expected_scope is not None and scope != expected_scope:
        raise ValueError(f"Unexpected control extension scope: {scope!r}.")
    interfaces = extension.get("supportedInterfaces", [])
    skills = extension.get("skills", [])
    if not isinstance(interfaces, list) or not all(isinstance(x, dict) for x in interfaces):
        raise TypeError("supportedInterfaces must be a list of objects.")
    if not isinstance(skills, list) or len({x.get("id") for x in skills}) != len(skills):
        raise ValueError("Skill IDs must be unique.")
    for index, item in enumerate(interfaces, 1):
        if not isinstance(item.get("url"), str):
            raise TypeError(f"Interface {index} URL must be a string.")
        for field in ("protocolBinding", "protocolVersion", "tenant"):
            if field in item and item[field] is not None and not isinstance(item[field], str):
                raise TypeError(f"Interface {index} {field} must be a string.")
    modes = extension.get("defaultOutputModes", [])
    if not isinstance(modes, list) or not all(isinstance(x, str) for x in modes):
        raise TypeError("defaultOutputModes must be a list of strings.")
    return SDKResolvedCard(sdk_card, _dump(sdk_card), dict(extension), scope,
                           extension.get("identity"), digest)


def project_selected_interface(resolved: SDKResolvedCard, interface: dict[str, Any], *, base_url: str) -> AgentCard:
    return build_sdk_agent_card(resolved.control_state, selected_interface=interface, base_url=base_url)
