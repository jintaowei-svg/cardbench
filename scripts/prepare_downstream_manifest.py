from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.carddiff_env import _artifact_mime_type
from harness.downstream.trace_loader import ATTACKS, SOURCE_COUNTS, read_jsonl, validate_distribution


def _case(path: str) -> Any:
    module, name = path.split(":", 1)
    return getattr(importlib.import_module(module), name)()


def _manifest_index(path: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, dict) else payload
    if not isinstance(cases, list):
        raise ValueError("Official A2A manifest must contain a cases list.")
    return {str(case["case_id"]): case for case in cases}


def _message_event(record: dict[str, Any]) -> dict[str, Any]:
    matched = record.get("oracle_evidence", {}).get("matched_event", {})
    if matched.get("event_type") == "message_sent":
        return matched
    messages = [event for event in record.get("events", []) if event.get("event_type") == "message_sent"]
    if record.get("attack_type") == "A3":
        cached = [
            event for event in messages
            if event.get("evidence", {}).get("card_scope_used") == "extended-cache"
        ]
        if cached:
            return cached[-1]
    selected_skill = record.get("selected_skill")
    selected_url = record.get("selected_interface")
    matching = [
        event for event in messages
        if event.get("evidence", {}).get("skill_id") == selected_skill
        and event.get("evidence", {}).get("selected_url") == selected_url
    ]
    if matching:
        return matching[-1]
    if messages:
        return messages[-1]
    raise ValueError(f"Successful case {record.get('case_id')} has no recorded message_sent event.")


def _decision(record: dict[str, Any], message: dict[str, Any]) -> dict[str, Any]:
    evidence = message["evidence"]
    decisions = [
        decision for decision in record.get("decision_trace", [])
        if decision.get("should_send")
        and decision.get("capability_id") == evidence.get("skill_id")
    ]
    if record.get("attack_type") == "A3" and decisions:
        return decisions[-1]
    if decisions:
        return decisions[0]
    raise ValueError(f"Successful case {record.get('case_id')} has no matching recorded decision.")


def _private_token(case_id: str) -> str:
    return "SEC-" + hashlib.sha256(("downstream-v3:" + case_id).encode()).hexdigest()[:24]


def _from_record(record: dict[str, Any], source_case: dict[str, Any]) -> dict[str, Any]:
    instance = _case(str(source_case["class_path"]))
    metadata = instance.metadata
    attack = str(record["attack_type"])
    message = _message_event(record)
    evidence = dict(message["evidence"])
    decision = _decision(record, message)
    replay_step = int(decision.get("step_index", 0))
    canary = _private_token(str(record["case_id"]))
    task = str(metadata["public"]["task"])
    if attack in {"A2", "B1"}:
        task += f"\nPrivate request context: {canary}"
    accepted = list(evidence.get("accepted_output_modes") or metadata["public"]["accepted_output_modes"])
    sdk = dict(record.get("official_a2a_sdk_evidence") or {})
    artifact_mime = _artifact_mime_type(metadata["agent"]["response"]["artifact"])
    return {
        "case_id": str(record["case_id"]),
        "class_path": str(source_case["class_path"]),
        "attack_type": attack,
        "scenario": str(record.get("domain") or metadata["scenario"]),
        "variant": str(record.get("variant") or source_case.get("variant")),
        "base_task_id": str(source_case.get("base_task_id") or ""),
        "decision_source": "recorded_trace",
        "source_success": True,
        "source_case_sha256": str(record.get("case_sha256") or source_case.get("case_sha256") or ""),
        "replay_step_index": replay_step,
        "replay_task": task,
        "private_context_token": canary,
        "decision": {
            "should_send": True,
            "capability_id": str(evidence["skill_id"]),
            "interface_index": int(evidence["interface_index"]),
            "accept_output": bool(decision.get("accept_output", record.get("artifact_acceptance", True))),
        },
        "trace": {
            "identity": str(evidence["identity"]),
            "token_scopes": list(evidence.get("token_scopes") or []),
            "card_scope_used": str(evidence["card_scope_used"]),
            "selected_url": str(evidence["selected_url"]),
            "selected_protocol_binding": str(
                evidence.get("selected_protocolBinding") or evidence.get("protocol_binding") or ""
            ),
            "selected_protocol_version": str(
                evidence.get("selected_protocolVersion") or evidence.get("protocol_version") or ""
            ),
            "accepted_output_modes": accepted,
        },
        "oracle": metadata["oracle"],
        "impact_artifact_mime": artifact_mime or "text/html",
        "sdk_evidence": {
            "resolver_used": bool(sdk.get("resolver_used")),
            "client_factory_used": bool(sdk.get("client_factory_used")),
            "sdk_message_used": bool(sdk.get("sdk_message_used")),
            "sdk_server_used": bool(sdk.get("sdk_server_used")),
            "fallback_used": bool(sdk.get("fallback_used", False)),
        },
    }


def _balanced_sample(cases: list[dict[str, Any]], per_attack: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for attack in ATTACKS:
        buckets: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)
        for case in sorted(
            (case for case in cases if case["attack_type"] == attack),
            key=lambda item: item["case_id"],
        ):
            buckets[(case["scenario"], case["variant"])].append(case)
        keys = sorted(buckets)
        attack_rows: list[dict[str, Any]] = []
        while len(attack_rows) < per_attack:
            progressed = False
            for key in keys:
                if buckets[key] and len(attack_rows) < per_attack:
                    attack_rows.append(buckets[key].popleft())
                    progressed = True
            if not progressed:
                break
        if len(attack_rows) != per_attack:
            raise ValueError(f"Could select only {len(attack_rows)} {attack} cases; need {per_attack}.")
        selected.extend(attack_rows)
    return sorted(selected, key=lambda item: item["case_id"])


def _payload(cases: list[dict[str, Any]], source: Path, source_manifest: Path, *, phase: str) -> dict[str, Any]:
    expected = dict(Counter(case["attack_type"] for case in cases))
    validate_distribution(cases, expected)
    return {
        "experiment_id": f"official_a2a_llm_downstream_recorded_v3_{phase}",
        "mode": "recorded_trace_capability_scoped_llm",
        "source_results": str(source),
        "source_manifest": str(source_manifest),
        "source_counts": SOURCE_COUNTS,
        "expected_counts": expected,
        "cases": cases,
    }


def prepare(
    details: Path,
    source_manifest: Path,
    out: Path,
    *,
    smoke_out: Path | None = None,
    smoke_per_attack: int = 20,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    records = read_jsonl([details])
    source = _manifest_index(source_manifest)
    cases: list[dict[str, Any]] = []
    for case_id, record in records.items():
        attack = str(record.get("attack_type") or "")
        if attack not in ATTACKS or not bool(record.get("success", False)):
            continue
        if case_id not in source:
            raise ValueError(f"Source manifest is missing {case_id}.")
        cases.append(_from_record(record, source[case_id]))
    cases.sort(key=lambda item: item["case_id"])
    full = _payload(cases, details, source_manifest, phase="full")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(full, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    smoke = None
    if smoke_out is not None:
        smoke = _payload(
            _balanced_sample(cases, smoke_per_attack), details, source_manifest, phase="smoke"
        )
        smoke_out.parent.mkdir(parents=True, exist_ok=True)
        smoke_out.write_text(
            json.dumps(smoke, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return full, smoke


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--details", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--smoke-out", type=Path)
    parser.add_argument("--smoke-per-attack", type=int, default=20)
    args = parser.parse_args()
    full, smoke = prepare(
        args.details,
        args.source_manifest,
        args.out,
        smoke_out=args.smoke_out,
        smoke_per_attack=args.smoke_per_attack,
    )
    print(json.dumps({
        "full_cases": len(full["cases"]),
        "full_distribution": full["expected_counts"],
        "smoke_cases": len(smoke["cases"]) if smoke else 0,
        "smoke_distribution": smoke["expected_counts"] if smoke else {},
    }, indent=2))


if __name__ == "__main__":
    main()
