from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MASTER = ROOT / "attacks/carddiff/transfer_native/master_cases.json"
SOURCE = ROOT / "attacks/carddiff/perturbed_cases.jsonl"
APPLICABILITY = ROOT / "attacks/carddiff/transfer_extension/applicability.json"
AGNTCY_OUTPUT = ROOT / "attacks/carddiff/transfer_native/agntcy_cases.json"
AUTOGEN_OUTPUT = ROOT / "attacks/carddiff/transfer_framework/autogen_cases.json"
LANGGRAPH_OUTPUT = ROOT / "attacks/carddiff/transfer_framework/langgraph_cases.json"
SMOKE_OUTPUT = ROOT / "attacks/carddiff/transfer_extension/smoke_case_ids.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _active_card(case: dict[str, Any]) -> dict[str, Any]:
    cards = case["agent"]["extended_cards"]
    if case["attack_type"] == "A3":
        return deepcopy(cards.get("admin") or case["agent"]["public_card"])
    return deepcopy(cards.get("normal_user") or case["agent"]["public_card"])


def _scopes(case: dict[str, Any]) -> list[str]:
    auth = case["public"]["auth_sequence"][-1]
    return list(case["agent"]["tokens"].get(auth["token_label"], {}).get("scopes", []))


def _canonical_from_card(case: dict[str, Any], card: dict[str, Any]) -> dict[str, Any]:
    auth = case["public"]["auth_sequence"][-1]
    return {
        "task": case["public"]["task"],
        "identity": auth["identity"],
        "token_scopes": _scopes(case),
        "capabilities": deepcopy(card.get("skills", [])),
        "interfaces": deepcopy(card.get("supportedInterfaces", [])),
        "request_tenant": case["public"].get("request_tenant"),
        "accepted_output_modes": list(case["public"].get("accepted_output_modes", [])),
    }


def _option(interface: dict[str, Any]) -> str:
    return "|".join(
        str(interface.get(key, "")) for key in ("protocolBinding", "protocolVersion", "url")
    )


def _agntcy_case(master: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    public_card = deepcopy(source["agent"]["public_card"])
    runtime_card = _active_card(source)
    interfaces = runtime_card.get("supportedInterfaces", [])
    expected_binding = source["oracle"].get("expected_protocol_binding")
    expected_version = source["oracle"].get("expected_protocol_version")
    stronger = next(
        (
            item
            for item in interfaces
            if item.get("protocolBinding") == expected_binding
            and item.get("protocolVersion") == expected_version
        ),
        interfaces[-1] if interfaces else {},
    )
    weaker = interfaces[0] if interfaces else {}
    native = {
        "directory_annotation": f"carddiff:{master['source_case_id']}",
        "trusted_card": public_card,
        "runtime_card": runtime_card,
        "oracle_facts": {
            "trusted_destination": (public_card.get("supportedInterfaces") or [{}])[0].get("url"),
            "drifted_destination": (interfaces or [{}])[0].get("url"),
            "stronger_compatible_option_available": len(interfaces) > 1,
            "weaker_or_legacy_option": _option(weaker),
            "stronger_option": _option(stronger),
        },
    }
    return {
        **master,
        "target_case_id": f"AGNTCY-{master['source_case_id']}",
        "canonical_state": _canonical_from_card(source, runtime_card),
        "native": native,
        "source": {
            "case_id": source["case_id"],
            "public": deepcopy(source["public"]),
            "agent": deepcopy(source["agent"]),
            "oracle": deepcopy(source["oracle"]),
        },
    }


def _autogen_b1_state(source: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    return _participant_state(source, scheme="autogen", protocol="autogen-agentchat", version="0.7.5")


def _participant_state(
    source: dict[str, Any], *, scheme: str, protocol: str, version: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    card = _active_card(source)
    interfaces = card.get("supportedInterfaces", [])
    attacker_url = source["oracle"].get("attacker_preferred_url")
    order: list[str] = []
    mapped_interfaces: list[dict[str, Any]] = []
    attacker_candidate: str | None = None
    for index, item in enumerate(interfaces):
        name = f"participant_{index + 1}"
        if item.get("url") == attacker_url:
            attacker_candidate = name
        order.append(name)
        mapped_interfaces.append(
            {
                "url": f"{scheme}://{name}",
                "tenant": item.get("tenant"),
                "protocol": protocol,
                "version": version,
            }
        )
    capabilities = [
        {
            "id": name,
            "name": name.replace("_", " ").title(),
            "description": f"Registered {protocol} participant for the unchanged workflow.",
            "required_scopes": [],
            "output_modes": ["text/plain"],
        }
        for name in order
    ]
    if attacker_candidate is None:
        raise ValueError("B1 source case does not contain the private attacker-preferred URL.")
    auth = source["public"]["auth_sequence"][-1]
    state = {
        "task": source["public"]["task"],
        "identity": auth["identity"],
        "token_scopes": _scopes(source),
        "capabilities": capabilities,
        "interfaces": mapped_interfaces,
        "request_tenant": source["public"].get("request_tenant"),
        "accepted_output_modes": list(source["public"].get("accepted_output_modes", [])),
    }
    return state, {
        "participant_order": order,
        "attacker_preferred_candidate": attacker_candidate,
    }


def _autogen_case(master: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    attack = source["attack_type"]
    card = _active_card(source)
    state = _canonical_from_card(source, card)
    native: dict[str, Any] = {}
    if attack == "B1":
        state, native = _autogen_b1_state(source)
    elif attack == "A3":
        native = {
            "identity_sequence": [
                {
                    "identity_label": (
                        "privileged_user"
                        if step["identity"] in {"admin", "privileged_user"}
                        else "normal_user"
                    ),
                    "token_label": step["token_label"],
                }
                for step in source["public"]["auth_sequence"]
            ],
            "cached_state_owner": "privileged_user",
            "current_identity": "normal_user",
            "sensitive_capability": source["oracle"].get("sensitive_skill_id"),
        }
    elif attack == "C1":
        native = {
            "sensitive_capability": source["oracle"].get("sensitive_skill_id"),
            "required_scope": source["oracle"].get("required_scope"),
        }
    elif attack == "C2":
        # AutoGen's native multimodal carrier is exercised with an actual image.
        # Keep the oracle fact tied to the emitted message instead of copying a
        # source-only MIME label that the framework never returned.
        native = {"returned_output_type": "image/png"}
    return {
        **master,
        "target_case_id": f"AUTOGEN-{master['source_case_id']}",
        "canonical_state": state,
        "native": native,
    }


def _langgraph_case(master: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    attack = source["attack_type"]
    state = _canonical_from_card(source, _active_card(source))
    native: dict[str, Any] = {}
    if attack == "B1":
        state, native = _participant_state(
            source,
            scheme="langgraph",
            protocol="langgraph-stategraph",
            version="1.2.9",
        )
    elif attack == "A3":
        native = {
            "identity_sequence": [
                {
                    "identity_label": (
                        "privileged_user"
                        if step["identity"] in {"admin", "privileged_user"}
                        else "normal_user"
                    ),
                    "token_label": step["token_label"],
                }
                for step in source["public"]["auth_sequence"]
            ],
            "sensitive_capability": source["oracle"].get("sensitive_skill_id"),
        }
    elif attack == "C1":
        native = {
            "sensitive_capability": source["oracle"].get("sensitive_skill_id"),
            "required_scope": source["oracle"].get("required_scope"),
        }
    elif attack == "C2":
        native = {"returned_output_type": "image/png"}
    return {
        **master,
        "target_case_id": f"LANGGRAPH-{master['source_case_id']}",
        "canonical_state": state,
        "native": native,
    }


def build() -> dict[str, int]:
    applicability = json.loads(APPLICABILITY.read_text(encoding="utf-8"))
    if applicability.get("frozen") is not True:
        raise RuntimeError("Freeze extension applicability before building cases.")
    master = json.loads(MASTER.read_text(encoding="utf-8"))
    masters = master["cases"]
    if len(masters) != 540:
        raise RuntimeError(f"Expected the frozen 540-case master, found {len(masters)}")
    source_cases = {
        item["case_id"]: item
        for line in SOURCE.read_text(encoding="utf-8").splitlines()
        if line.strip()
        for item in [json.loads(line)]
    }
    agntcy: list[dict[str, Any]] = []
    autogen: list[dict[str, Any]] = []
    langgraph: list[dict[str, Any]] = []
    for item in masters:
        source = source_cases[item["source_case_id"]]
        attack = item["attack_type"]
        if applicability["agntcy"].get(attack) == "applicable":
            agntcy.append(_agntcy_case(item, source))
        if applicability["autogen"].get(attack) == "applicable":
            autogen.append(_autogen_case(item, source))
        if applicability["langgraph"].get(attack) == "applicable":
            langgraph.append(_langgraph_case(item, source))
    for target, cases in (
        ("agntcy", agntcy),
        ("autogen", autogen),
        ("langgraph", langgraph),
    ):
        expected = 90 * sum(
            status == "applicable" for status in applicability[target].values()
        )
        if len(cases) != expected:
            raise RuntimeError(f"Expected {expected} {target} cases, found {len(cases)}")
        for attack in sorted({case["attack_type"] for case in cases}):
            count = sum(case["attack_type"] == attack for case in cases)
            if count != 90:
                raise RuntimeError(f"Expected 90 {target} {attack} cases, found {count}")
    AGNTCY_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    AUTOGEN_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    LANGGRAPH_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    AGNTCY_OUTPUT.write_text(
        json.dumps(
            {
                "schema_version": "carddiff-transfer-native-cases-v1",
                "protocol": "agntcy",
                "source_master_sha256": _sha(MASTER),
                "cases": agntcy,
            },
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    AUTOGEN_OUTPUT.write_text(
        json.dumps(
            {
                "schema_version": "carddiff-transfer-framework-cases-v1",
                "target_kind": "framework",
                "framework": "autogen",
                "source_master_sha256": _sha(MASTER),
                "cases": autogen,
            },
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    LANGGRAPH_OUTPUT.write_text(
        json.dumps(
            {
                "schema_version": "carddiff-transfer-framework-cases-v1",
                "target_kind": "framework",
                "framework": "langgraph",
                "source_master_sha256": _sha(MASTER),
                "cases": langgraph,
            },
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    smoke: dict[str, list[str]] = {}
    for target, cases in (
        ("agntcy", agntcy),
        ("autogen", autogen),
        ("langgraph", langgraph),
    ):
        smoke[target] = [
            next(case["target_case_id"] for case in cases if case["attack_type"] == attack)
            for attack in sorted({case["attack_type"] for case in cases})
        ]
    SMOKE_OUTPUT.write_text(
        json.dumps(
            {"schema_version": "carddiff-transfer-extension-smoke-v1", **smoke},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "agntcy": len(agntcy),
        "autogen": len(autogen),
        "langgraph": len(langgraph),
    }


if __name__ == "__main__":
    print(json.dumps(build(), indent=2))
