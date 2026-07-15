from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "attacks" / "carddiff" / "perturbed_cases.jsonl"
OUTPUT = ROOT / "attacks" / "carddiff" / "transfer_native"
APPLICABILITY = OUTPUT / "applicability.json"
UNION_ATTACKS = ("A2", "A3", "B1", "B3", "C1", "C2")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _variant(case: dict[str, Any]) -> str:
    return str(case["perturbation"]["variant_id"])


def _domain(case: dict[str, Any]) -> str:
    return str(case.get("scenario", case.get("public", {}).get("scenario")))


def _scopes(case: dict[str, Any], token_label: str) -> list[str]:
    return list(case["agent"]["tokens"].get(token_label, {}).get("scopes", []))


def _canonical_state(case: dict[str, Any], *, protocol: str) -> dict[str, Any]:
    public = case["public"]
    auth = public["auth_sequence"][-1]
    cards = case["agent"]["extended_cards"]
    active = cards.get("admin") if case["attack_type"] == "A3" else cards.get("normal_user")
    active = active or case["agent"]["public_card"]
    skills = active.get("skills", [])
    interfaces = active.get("supportedInterfaces", [])
    if protocol == "nlip":
        # These are local NLIP application operations and its configured binding,
        # not AgentCard discovery fields.
        skills = [
            {
                "id": item["id"],
                "name": item.get("name", item["id"]),
                "description": item.get("description", "NLIP application operation"),
                "required_scopes": item.get("security", []),
                "output_modes": [],
            }
            for item in skills
        ]
        interfaces = [
            {
                "url": "{{nlip_peer_url}}",
                "tenant": public.get("request_tenant"),
                "protocol": "NLIP-over-HTTP",
                "version": "ECMA-431",
            }
        ]
    elif protocol == "anp":
        interfaces = [
            {
                "url": f"{{{{anp_peer_base_url}}}}/{_domain(case)}/candidate-{index}/rpc",
                "tenant": item.get("tenant"),
                "protocol": "openrpc-jsonrpc",
                "version": item.get("protocolVersion", "1.0"),
            }
            for index, item in enumerate(interfaces, start=1)
        ]
    return {
        "task": public["task"],
        "identity": auth["identity"],
        "token_scopes": _scopes(case, auth["token_label"]),
        "capabilities": skills,
        "interfaces": interfaces,
        "request_tenant": public.get("request_tenant"),
        "accepted_output_modes": public.get("accepted_output_modes", []),
    }


def _identity_sequence(case: dict[str, Any], protocol: str) -> list[dict[str, Any]]:
    result = []
    for index, step in enumerate(case["public"]["auth_sequence"]):
        raw_identity = str(step["identity"])
        label = "privileged_user" if raw_identity in {"admin", "privileged_user"} else "normal_user"
        item = {
            "identity_label": label,
            "token_label": step["token_label"],
        }
        if protocol == "anp":
            item.update(
                {
                    "did": f"did:wba:localhost:{_domain(case)}:{label}",
                    "agent_description_url": f"{{{{anp_peer_base_url}}}}/{_domain(case)}/ad.json",
                    "default_method": case["oracle"]["normal_skill_id"],
                    "cache_key": f"{_domain(case)}-agent",
                    "reuse_cached_discovery": index > 0 and case["attack_type"] == "A3",
                }
            )
        else:
            item.update(
                {
                    "session_key": f"{_domain(case)}-session" if case["attack_type"] == "A3" else f"{label}-session",
                    "resume_session": index > 0 and case["attack_type"] == "A3",
                }
            )
        result.append(item)
    return result


def _anp_native(case: dict[str, Any]) -> dict[str, Any]:
    oracle = case["oracle"]
    normal = case["agent"]["extended_cards"].get("normal_user", case["agent"]["public_card"])
    source_interfaces = normal.get("supportedInterfaces", [])
    count = len(source_interfaces)
    urls = [f"{{{{anp_peer_base_url}}}}/{_domain(case)}/candidate-{index}/rpc" for index in range(1, count + 1)]
    trusted_destination = urls[-1] if urls else None
    drifted_destination = urls[0] if urls else None
    if case["attack_type"] == "A2" and urls:
        # Authenticated discovery exposes the drifted interface while the
        # trusted chain remains the event-oracle comparison destination.
        trusted_destination = f"{{{{anp_peer_base_url}}}}/{_domain(case)}/trusted/rpc"
    attacker_preferred = None
    source_attacker_url = oracle.get("attacker_preferred_url")
    for index, interface in enumerate(source_interfaces, start=1):
        if interface.get("url") == source_attacker_url:
            attacker_preferred = f"{{{{anp_peer_base_url}}}}/{_domain(case)}/candidate-{index}/rpc"
            break
    return {
        "agent_id": f"anp-{_domain(case)}",
        "identity_sequence": _identity_sequence(case, "anp"),
        "sensitive_method": oracle.get("sensitive_skill_id"),
        "oracle_facts": {
            "trusted_destination": trusted_destination,
            "drifted_destination": drifted_destination,
            "attacker_preferred_candidate": attacker_preferred,
            "stronger_compatible_option_available": len(urls) > 1,
            "weaker_or_legacy_option": urls[0] if urls else None,
        },
    }


def _nlip_native(case: dict[str, Any]) -> dict[str, Any]:
    oracle = case["oracle"]
    normal_skill = oracle.get("normal_skill_id")
    sensitive = oracle.get("sensitive_skill_id")
    operation = sensitive if case["attack_type"] == "C1" else normal_skill
    returned_format = "structured"
    returned_subformat = "JSON"
    if case["attack_type"] == "C2":
        returned_format, returned_subformat = "binary", "image/png;base64"
    accepted = [f"{mode.split('/', 1)[0]}/{mode.split('/', 1)[-1]}" for mode in case["public"].get("accepted_output_modes", [])]
    return {
        "peer_url": "{{nlip_peer_url}}",
        "identity_sequence": _identity_sequence(case, "nlip"),
        "operation": operation,
        "sensitive_operation": sensitive,
        "request_format": "structured",
        "request_subformat": "JSON",
        "response_format": returned_format,
        "response_subformat": returned_subformat,
        "oracle_facts": {"accepted_output_types": accepted},
    }


def _master(case: dict[str, Any], ordinal: int) -> dict[str, Any]:
    attack = case["attack_type"]
    domain = _domain(case)
    variant = _variant(case)
    master_id = f"TRANSFER-{attack}-{domain.upper()}-{variant}-{ordinal:04d}"
    return {
        "master_case_id": master_id,
        "source_case_id": case["case_id"],
        "attack_type": attack,
        "domain": domain,
        "variant": variant,
        "task": case["public"]["task"],
        "identity_sequence": case["public"]["auth_sequence"],
        "authorization_context": case["agent"]["tokens"],
        "expected_security_invariant": case["attack_name"],
        "target_case_ids": {
            "official_a2a": f"A2A-{case['case_id']}",
            "anp": f"ANP-{case['case_id']}",
            "nlip": f"NLIP-{case['case_id']}",
        },
    }


def build() -> dict[str, int]:
    applicability = json.loads(APPLICABILITY.read_text(encoding="utf-8"))
    if applicability.get("frozen") is not True:
        raise RuntimeError("Freeze applicability before building native transfer cases.")
    cases = [json.loads(line) for line in SOURCE.read_text(encoding="utf-8").splitlines() if line.strip()]
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        if case["attack_type"] in UNION_ATTACKS and _variant(case) in {"001", "002", "003"}:
            grouped[(case["attack_type"], _domain(case), _variant(case))].append(case)
    selected: list[dict[str, Any]] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda item: item["case_id"])
        if len(group) < 10:
            raise RuntimeError(f"Need 10 cases for {key}, found {len(group)}")
        selected.extend(group[:10])
    if len(selected) != 540:
        raise RuntimeError(f"Expected 540 master cases, found {len(selected)}")
    masters = [_master(case, index) for index, case in enumerate(selected, start=1)]
    master_by_source = {item["source_case_id"]: item for item in masters}
    protocol_cases: dict[str, list[dict[str, Any]]] = {"anp": [], "nlip": []}
    mapping = []
    for case in selected:
        master = master_by_source[case["case_id"]]
        mapping.append({"master_case_id": master["master_case_id"], "source_case_id": case["case_id"], **master["target_case_ids"]})
        for protocol in ("anp", "nlip"):
            if applicability[protocol][case["attack_type"]] != "applicable":
                continue
            protocol_cases[protocol].append(
                {
                    **master,
                    "target_case_id": master["target_case_ids"][protocol],
                    "canonical_state": _canonical_state(case, protocol=protocol),
                    "native": _anp_native(case) if protocol == "anp" else _nlip_native(case),
                }
            )
    common = sorted(
        attack for attack in UNION_ATTACKS
        if all(applicability[protocol].get(attack) == "applicable" for protocol in ("official_a2a", "anp", "nlip"))
    )
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "master_cases.json").write_text(json.dumps({"schema_version": "carddiff-transfer-master-v1", "source_sha256": _sha(SOURCE), "sampling": "case_id_ascending_first_10_per_attack_domain_variant", "cases": masters}, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    (OUTPUT / "case_mapping.json").write_text(json.dumps({"schema_version": "carddiff-transfer-mapping-v1", "cases": mapping}, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    for protocol, items in protocol_cases.items():
        (OUTPUT / f"{protocol}_cases.json").write_text(json.dumps({"schema_version": "carddiff-transfer-native-cases-v1", "protocol": protocol, "common_attacks": common, "cases": items}, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return {"master": len(masters), **{key: len(value) for key, value in protocol_cases.items()}}


if __name__ == "__main__":
    print(json.dumps(build(), indent=2))
