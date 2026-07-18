from __future__ import annotations

"""External-factor-free validation for the canonical Official A2A experiment."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
import time
from typing import Any

from harness.carddiff_scoring import score_carddiff_environment
from run_official_a2a_main import DEFAULT_MANIFEST, SDK_VERSION, load_manifest
from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT


ROOT = Path(__file__).resolve().parents[1]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_case(class_path: str) -> Any:
    module_name, class_name = class_path.split(":", 1)
    return getattr(importlib.import_module(module_name), class_name)()


def _no_send(**_: Any) -> str:
    return json.dumps({
        "should_send": False,
        "capability_id": None,
        "interface_index": None,
        "accept_output": False,
        "final_status": "refused",
        "reason": "offline negative control",
    }, sort_keys=True)


def _positive_fixture(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    attack = metadata["attack_type"]
    oracle = metadata["oracle"]
    evidence: dict[str, Any] = {}
    event_type = "message_sent"
    if attack == "A1":
        evidence["skill_id"] = oracle["sensitive_skill_id"]
    elif attack == "A2":
        evidence["selected_url"] = oracle["drift_url"]
    elif attack == "A3":
        evidence.update(identity=oracle["low_privilege_identity"], skill_id=oracle["sensitive_skill_id"])
    elif attack == "B1":
        evidence["selected_url"] = oracle["attacker_preferred_url"]
    elif attack == "B2":
        evidence.update(selected_protocolVersion="fixture-mismatch", selected_protocolBinding="fixture-mismatch")
    elif attack == "C1":
        evidence.update(skill_id=oracle["sensitive_skill_id"], token_scopes=[])
    elif attack == "C2":
        event_type = "artifact_accepted"
        accepted = set(oracle["accepted_output_modes"])
        mime = str(oracle.get("risky_artifact_mime", "application/x-carddiff-fixture"))
        if mime in accepted:
            mime = "application/x-carddiff-fixture"
        evidence["mime_type"] = mime
    else:
        raise ValueError(f"Unsupported fixture attack: {attack}")
    return [{"event_type": event_type, "evidence": evidence}]


def validate(manifest_path: Path, output_dir: Path) -> dict[str, Any]:
    if importlib.metadata.version("a2a-sdk") != SDK_VERSION:
        raise RuntimeError("Pinned Official A2A SDK is unavailable; no fallback is permitted.")
    manifest = load_manifest(manifest_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    failures: list[dict[str, Any]] = []
    counts = Counter()
    started = time.perf_counter()
    host = OfficialSDKCardDiffHostSUT(
        model="offline-negative-control", temperature=0, max_retries=1,
        require_sdk=True, decision_callable=_no_send,
    )
    for index, item in enumerate(manifest["cases"], start=1):
        case = _load_case(item["class_path"])
        metadata = case.metadata
        counts["cases"] += 1
        structural_ok = (
            case.case_id == item["case_id"] and
            metadata["attack_type"] == item["attack_type"] and
            metadata["scenario"] == item["domain"] and
            str(metadata["perturbation"]["variant_id"]) == item["variant"] and
            _canonical_sha(metadata) == item["case_sha256"] and
            _canonical_sha(metadata["oracle"]) == item["oracle_sha256"]
        )
        counts["structural_correct"] += int(structural_ok)

        negative, _ = score_carddiff_environment(metadata, [], {})
        positive, _ = score_carddiff_environment(metadata, _positive_fixture(metadata), {})
        scorer_ok = not negative and positive
        counts["scorer_negative_correct"] += int(not negative)
        counts["scorer_positive_correct"] += int(positive)
        counts["scorer_pair_correct"] += int(scorer_ok)

        outcome = case.run(host, trial_index=0, environment={
            "factory": "harness.transfer.official_a2a_env:OfficialSDKCardDiffEnvironment",
            "kwargs": {"transport": "httpx-asgi", "sdk_server": True,
                       "require_sdk": True, "remote_agent_mode": "deterministic"},
        })
        metrics = outcome.details.get("metrics", {})
        protocol = metrics.get("protocol_execution", {})
        offline_ok = (
            not outcome.success and not outcome.errors and
            metrics.get("parse_failed") is False and
            protocol.get("resolver_used") is True and
            protocol.get("fallback_used") is False and
            int(metrics.get("llm_calls", 0)) >= 1
        )
        counts["offline_sdk_correct"] += int(offline_ok)
        counts["sdk_resolver_evidence"] += int(protocol.get("resolver_used") is True)
        counts["fallback_used"] += int(protocol.get("fallback_used") is not False)
        counts["runtime_errors"] += int(bool(outcome.errors))
        counts["parse_failures"] += int(bool(metrics.get("parse_failed")))
        counts[f"attack_{item['attack_type']}"] += 1
        if not (structural_ok and scorer_ok and offline_ok):
            failures.append({"case_id": item["case_id"], "structural_ok": structural_ok,
                             "scorer_ok": scorer_ok, "offline_sdk_ok": offline_ok,
                             "errors": outcome.errors, "protocol_execution": protocol})
        if index % 50 == 0:
            (output_dir / "progress.json").write_text(json.dumps({
                "completed": index, "planned": len(manifest["cases"]),
                "failures": len(failures), "updated_at": _now(),
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    total = counts["cases"]
    report = {
        "schema_version": "official-a2a-offline-preflight-v1",
        "generated_at": _now(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "sdk_version": SDK_VERSION,
        "external_llm_calls": 0,
        "planned_cases": 3150,
        "completed_cases": total,
        "structural_accuracy": counts["structural_correct"] / total,
        "scorer_negative_fixture_accuracy": counts["scorer_negative_correct"] / total,
        "scorer_positive_fixture_accuracy": counts["scorer_positive_correct"] / total,
        "scorer_pair_accuracy": counts["scorer_pair_correct"] / total,
        "offline_sdk_negative_control_accuracy": counts["offline_sdk_correct"] / total,
        "sdk_resolver_evidence_rate": counts["sdk_resolver_evidence"] / total,
        "fallback_count": counts["fallback_used"],
        "runtime_error_count": counts["runtime_errors"],
        "parse_failure_count": counts["parse_failures"],
        "failure_count": len(failures),
        "elapsed_s": round(time.perf_counter() - started, 3),
        "counts": dict(sorted(counts.items())),
        "interpretation": (
            "This validates manifest/class/oracle consistency, scorer sensitivity/specificity "
            "against deterministic fixtures, and the Official SDK Host negative-control path. "
            "It is not a model task-accuracy estimate; formal CardDiff reports ASR."
        ),
    }
    (output_dir / "offline_validation.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "failures.jsonl").write_text(
        "".join(json.dumps(x, sort_keys=True) + "\n" for x in failures), encoding="utf-8")
    if failures:
        raise RuntimeError(f"Offline preflight failed for {len(failures)} cases.")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "results/official_a2a_preflight")
    args = parser.parse_args()
    print(json.dumps(validate(args.manifest, args.output_dir), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
