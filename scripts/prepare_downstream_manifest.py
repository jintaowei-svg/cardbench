from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.carddiff_env import _artifact_mime_type
from harness.downstream.trace_loader import EXPECTED_COUNTS, read_jsonl, validate_distribution


BASE_URL = "http://carddiff.a2a.local"


def _case(path: str) -> Any:
    module, name = path.split(":", 1)
    return getattr(importlib.import_module(module), name)()


def _url(value: Any) -> Any:
    return value.replace("{{base_url}}", BASE_URL) if isinstance(value, str) else value


def _index_for(interfaces: list[dict[str, Any]], predicate: Any) -> int:
    for index, interface in enumerate(interfaces, 1):
        if predicate(interface):
            return index
    raise ValueError("Successful trigger has no matching interface in case metadata.")


def _from_record(record: dict[str, Any]) -> dict[str, Any]:
    instance = _case(str(record["class_path"]))
    metadata, attack = instance.metadata, str(record["attack_type"])
    oracle = metadata["oracle"]
    steps = metadata["public"]["auth_sequence"]
    replay_step = len(steps) - 1 if attack == "A3" else 0
    step = steps[replay_step]
    identity = str(step["identity"])
    token_label = str(step["token_label"])
    token_scopes = list(metadata["agent"]["tokens"][token_label]["scopes"])
    card_identity = str(steps[0]["identity"]) if attack == "A3" else identity
    card = metadata["agent"]["extended_cards"].get(card_identity) or metadata["agent"]["extended_cards"]["normal_user"]
    interfaces = list(card["supportedInterfaces"])
    skills = list(card["skills"])
    capability = None
    if attack in {"A1", "A3", "C1"}:
        capability = oracle["sensitive_skill_id"]
    details = record.get("details", {})
    trace_event = details.get("success_evidence", {}).get("matched_event", {}).get("evidence", {})
    capability = trace_event.get("skill_id") or details.get("selected_skill") or capability or skills[0]["id"]
    selected_url = trace_event.get("selected_url") or details.get("selected_url")
    if not selected_url:
        if attack == "A2": selected_url = oracle["drift_url"]
        elif attack == "B1": selected_url = oracle["attacker_preferred_url"]
    if selected_url:
        interface_index = _index_for(interfaces, lambda x: _url(x.get("url")) == _url(selected_url))
    elif attack == "B3":
        interface_index = _index_for(interfaces, lambda x: x.get("protocolVersion") != oracle["expected_protocol_version"] or x.get("protocolBinding") != oracle["expected_protocol_binding"])
    else:
        interface_index = 1
    interface = interfaces[interface_index - 1]
    card_scope = trace_event.get("card_scope_used") or details.get("card_scope_used") or ("extended-cache" if attack == "A3" else "extended")
    accepted = list(metadata["public"]["accepted_output_modes"])
    canary = f"CARDDIFF::{attack}::{metadata['scenario'].upper()}::{metadata['case_id']}"
    task = str(metadata["public"]["task"])
    if attack == "A2": task += f"\nImpact canary: {canary}"
    artifact_mime = _artifact_mime_type(metadata["agent"]["response"]["artifact"])
    source = "recorded_trace" if trace_event else "trigger_oracle_reconstruction"
    return {"case_id": metadata["case_id"], "class_path": record["class_path"], "attack_type": attack,
            "scenario": metadata["scenario"], "variant": record.get("variant", metadata.get("variant")),
            "decision_source": source, "replay_step_index": replay_step, "replay_task": task, "canary": canary,
            "decision": {"should_send": True, "capability_id": capability, "interface_index": interface_index,
                         "accept_output": True},
            "trace": {"identity": identity, "token_scopes": token_scopes, "card_scope_used": card_scope,
                      "selected_url": _url(interface["url"]), "selected_protocol_binding": interface.get("protocolBinding"),
                      "selected_protocol_version": interface.get("protocolVersion"), "accepted_output_modes": accepted},
            "oracle": oracle, "impact_artifact_mime": artifact_mime or "text/html",
            "sdk_evidence": {"resolver_used": bool(record.get("resolver_used", details.get("metrics", {}).get("protocol_execution", {}).get("resolver_used"))),
                "client_factory_used": bool(record.get("sdk_client_used", details.get("metrics", {}).get("protocol_execution", {}).get("client_factory_used"))),
                "sdk_message_used": bool(record.get("sdk_message_used", details.get("metrics", {}).get("protocol_execution", {}).get("sdk_message_used"))),
                "sdk_server_used": bool(record.get("sdk_server_used", details.get("metrics", {}).get("protocol_execution", {}).get("sdk_server_used"))),
                "fallback_used": bool(record.get("fallback_used", details.get("metrics", {}).get("protocol_execution", {}).get("fallback_used", False)))}}


def prepare(paths: list[Path], out: Path, exclude: set[str], strict: bool = True) -> dict[str, Any]:
    records = read_jsonl(paths)
    cases = []
    for record in records.values():
        attack = str(record.get("attack_type") or record.get("details", {}).get("attack_type", ""))
        success = bool(record.get("attack_success", record.get("success", False)))
        if attack in exclude or not success:
            continue
        record = dict(record, attack_type=attack)
        cases.append(_from_record(record))
    cases.sort(key=lambda x: x["case_id"])
    validate_distribution(cases, strict=strict)
    payload = {"experiment_id": "official_a2a_downstream_rqd1", "mode": "decision_replay",
               "source_files": [str(x) for x in paths], "expected_counts": EXPECTED_COUNTS, "cases": cases}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--details", action="append", required=True, type=Path,
                        help="JSONL source; repeat in chronological order to reconcile reruns.")
    parser.add_argument("--exclude-attack", action="append", default=[])
    parser.add_argument("--require-attack-success", action="store_true")
    parser.add_argument("--require-sdk-evidence", action="store_true")
    parser.add_argument("--allow-nonstandard-counts", action="store_true")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    payload = prepare(args.details, args.out, set(args.exclude_attack), not args.allow_nonstandard_counts)
    print(json.dumps({"cases": len(payload["cases"]), "distribution": Counter(x["attack_type"] for x in payload["cases"])}, default=dict))


if __name__ == "__main__":
    main()
