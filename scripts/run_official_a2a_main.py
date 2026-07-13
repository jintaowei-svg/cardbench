from __future__ import annotations

"""Canonical Official A2A main/cross-model experiment runner.

The runner deliberately has one execution path: the pinned a2a-sdk backed Host
and deterministic SDK peer.  It never imports or invokes a generic HTTP Host.
"""

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Iterable

import yaml

from sut.transfer.common_llm import canonical_prompt_sha256
from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "attacks/carddiff/perturbed_cases.jsonl"
DEFAULT_MANIFEST = ROOT / "attacks/carddiff/official_a2a_main_3150.json"
DEFAULT_RESULTS = ROOT / "results/official_a2a_main"
ATTACKS = ("A1", "A2", "A3", "B1", "B3", "C1", "C2")
DOMAINS = ("travel", "healthcare", "finance")
VARIANTS = ("001", "002", "003")
MODELS = (
    "gpt-5-mini", "gpt-5.6-Luna", "gpt-5.4-mini",
    "gemini-2.5-flash", "gemini-3.5-flash", "claude-haiku-4.5",
    "deepseek-v4-flash", "claude-sonnet-5", "grok-4.5",
)
API_MODELS = {
    "gpt-5-mini": "gpt-5-mini",
    "gpt-5.6-Luna": "gpt-5.6-luna",
    "gpt-5.4-mini": "gpt-5.4-mini",
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-3.5-flash": "gemini-3.5-flash",
    "claude-haiku-4.5": "claude-haiku-4-5-20251001",
    "deepseek-v4-flash": "deepseek-v4-flash",
    "claude-sonnet-5": "claude-sonnet-5",
    "grok-4.5": "grok-4.5",
}
SDK_VERSION = "0.3.26"
TIMEOUT_S = 60.0
MAX_RETRIES = 1
TEMPERATURE = 0.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _canonical_sha(value: Any) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return _sha_bytes(data.encode("utf-8"))


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return os.getenv("CARDDIFF_CODE_SHA", "unavailable")


def build_manifest(output: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    raw = DATASET.read_bytes()
    cases = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    selected = []
    for index, item in enumerate(cases, start=1):
        if item["attack_type"] not in ATTACKS:
            continue
        selected.append({
            "case_id": item["case_id"],
            "class_path": f"attacks.instances.carddiff_perturbed:CardDiffPerturbed{index:03d}",
            "attack_type": item["attack_type"],
            "domain": item["scenario"],
            "variant": str(item["perturbation"]["variant_id"]),
            "base_task_id": item["generation"]["scenario_task_id"],
            "case_sha256": _canonical_sha(item),
            "oracle_sha256": _canonical_sha(item["oracle"]),
        })
    payload = {
        "schema_version": "official-a2a-main-v1",
        "manifest_id": "official_a2a_main_3150",
        "dataset_path": str(DATASET.relative_to(ROOT)).replace("\\", "/"),
        "dataset_sha256": _sha_bytes(raw),
        "attacks": list(ATTACKS),
        "domains": list(DOMAINS),
        "variants": list(VARIANTS),
        "cases": selected,
    }
    validate_manifest(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    validate_manifest(payload)
    return payload


def validate_manifest(payload: dict[str, Any]) -> None:
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != 3150:
        raise ValueError(f"Manifest must contain exactly 3,150 cases; got {len(cases or [])}.")
    ids = [str(case.get("case_id")) for case in cases]
    if len(set(ids)) != 3150:
        duplicates = [key for key, count in Counter(ids).items() if count > 1]
        raise ValueError(f"Manifest contains duplicate case IDs: {duplicates[:5]}")
    if any(case.get("attack_type") == "B2" or "_B2_" in case["case_id"] for case in cases):
        raise ValueError("B2 must not enter the canonical manifest.")
    expected = {(a, d, v): 50 for a in ATTACKS for d in DOMAINS for v in VARIANTS}
    actual = Counter((case["attack_type"], case["domain"], case["variant"]) for case in cases)
    if actual != expected:
        raise ValueError(f"Manifest cell distribution mismatch: {actual - Counter(expected)}")
    if Counter(case["attack_type"] for case in cases) != Counter({a: 450 for a in ATTACKS}):
        raise ValueError("Every attack must have exactly 450 cases.")
    if Counter(case["domain"] for case in cases) != Counter({d: 1050 for d in DOMAINS}):
        raise ValueError("Every domain must have exactly 1,050 cases.")
    if Counter(case["variant"] for case in cases) != Counter({v: 1050 for v in VARIANTS}):
        raise ValueError("Every variant must have exactly 1,050 cases.")


def _load_case(class_path: str) -> Any:
    module_name, class_name = class_path.split(":", 1)
    return getattr(importlib.import_module(module_name), class_name)()


def _run_config(model: str, manifest_path: Path, manifest_sha: str) -> dict[str, Any]:
    return {
        "schema_version": "official-a2a-main-v1",
        "model": model,
        "api_model": API_MODELS[model],
        "temperature": TEMPERATURE,
        "max_retries": MAX_RETRIES,
        "timeout_s": TIMEOUT_S,
        "http_request_retries": MAX_RETRIES,
        "strict_json_parsing": True,
        "response_format": {"type": "json_object"},
        "parse_failure_fallback": False,
        "skill_fallback": False,
        "interface_fallback": False,
        "requests_a2a_fallback": False,
        "attack_specific_prompt": False,
        "model_specific_prompt": False,
        "host": "sut.transfer.official_a2a_host:OfficialSDKCardDiffHostSUT",
        "environment": "harness.transfer.official_a2a_env:OfficialSDKCardDiffEnvironment",
        "transport": "httpx-asgi",
        "remote_peer": "deterministic",
        "event_level_oracle": True,
        "manifest": str(manifest_path.relative_to(ROOT)).replace("\\", "/") if manifest_path.is_relative_to(ROOT) else str(manifest_path),
        "manifest_sha256": manifest_sha,
        "prompt_sha256": canonical_prompt_sha256(),
        "official_a2a_sdk_version": SDK_VERSION,
        "code_commit_sha": _git_sha(),
    }


def _assert_runtime() -> None:
    actual = importlib.metadata.version("a2a-sdk")
    if actual != SDK_VERSION:
        raise RuntimeError(f"Official A2A SDK version mismatch: required {SDK_VERSION}, found {actual}. No fallback is permitted.")
    if not os.getenv("SUT_API_BASE") or not os.getenv("SUT_API_KEY"):
        raise RuntimeError("SUT_API_BASE and SUT_API_KEY must be set.")
    os.environ["SUT_TIMEOUT_S"] = str(int(TIMEOUT_S))
    os.environ["SUT_REQUEST_RETRIES"] = str(MAX_RETRIES)
    os.environ.setdefault("SUT_TRUST_ENV", "false")


def _event_count(events: list[dict[str, Any]], kind: str) -> int:
    return sum(event.get("event_type") == kind for event in events)


def _failure_category(errors: list[str], parse_failed: bool) -> str | None:
    if parse_failed:
        return "parse_failure"
    text = " ".join(errors).lower()
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if errors:
        return "runtime_error"
    return None


def _canonical_record(outcome: Any, case_meta: dict[str, Any], model: str,
                      config_sha: str, manifest_sha: str, elapsed_s: float) -> dict[str, Any]:
    details = outcome.details
    metrics = details.get("metrics", {})
    events = details.get("events", [])
    protocol = metrics.get("protocol_execution", {})
    parse_failed = bool(metrics.get("parse_failed"))
    errors = [str(value) for value in outcome.errors]
    category = _failure_category(errors, parse_failed)
    sdk_evidence = {
        "backend": metrics.get("protocol_backend"),
        "sdk_version": metrics.get("sdk_version") or metrics.get("framework_version"),
        "resolver_used": bool(protocol.get("resolver_used")),
        "client_factory_used": bool(protocol.get("client_factory_used")),
        "sdk_message_used": bool(protocol.get("sdk_message_used")),
        "sdk_server_used": bool(protocol.get("sdk_server_used")),
        "executor_used": bool(protocol.get("executor_used")),
        "fallback_used": protocol.get("fallback_used"),
    }
    fallback_violation = sdk_evidence["fallback_used"] is not False
    runtime_error = category == "runtime_error" or fallback_violation
    timeout = category == "timeout"
    judgment_status = "non_judgment" if category is not None or fallback_violation else "completed"
    return {
        "case_id": outcome.case_id,
        "model": model,
        "api_model": API_MODELS[model],
        "attack_type": case_meta["attack_type"],
        "domain": case_meta["domain"],
        "variant": case_meta["variant"],
        "success": bool(outcome.success),
        "judgment_status": judgment_status,
        "parse_failure": parse_failed,
        "runtime_error": runtime_error,
        "timeout": timeout,
        "failure_category": category or ("fallback_violation" if fallback_violation else None),
        "errors": errors,
        "llm_calls": int(metrics.get("llm_calls", 0)),
        "latency_ms": float(metrics.get("total_latency_ms", elapsed_s * 1000)),
        "llm_latency_ms": float(metrics.get("llm_latency_ms", 0.0)),
        "protocol_latency_ms": float(metrics.get("protocol_latency_ms", 0.0)),
        "selected_skill": details.get("selected_skill"),
        "selected_interface": details.get("selected_interface"),
        "selected_tenant": details.get("selected_tenant"),
        "protocol_binding": details.get("selected_protocolBinding"),
        "protocol_version": details.get("selected_protocolVersion"),
        "artifact_acceptance": bool(_event_count(events, "artifact_accepted")),
        "protocol_completed": bool(sdk_evidence["resolver_used"]) and not runtime_error and not timeout,
        "official_a2a_sdk_evidence": sdk_evidence,
        "run_timestamp": _now(),
        "framework_version": metrics.get("implementation_version"),
        "sdk_version": sdk_evidence["sdk_version"],
        "config_sha256": config_sha,
        "manifest_sha256": manifest_sha,
        "prompt_sha256": canonical_prompt_sha256(),
        "code_commit_sha": _git_sha(),
        "case_sha256": case_meta["case_sha256"],
        "oracle_sha256": case_meta["oracle_sha256"],
        "events": events,
        "oracle_evidence": details.get("success_evidence"),
        "decision_trace": details.get("sut_meta", {}).get("decisions", []),
        "parse_failure_raw_responses": metrics.get("parse_failure_raw_responses", []),
        "response": details.get("response"),
        "provenance": {"phase": "original", "replaces": None},
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Corrupt JSONL at {path}:{line_no}: {exc}") from exc
    return records


def _append(path: Path, value: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
        fp.flush()


def _bucket(records: Iterable[dict[str, Any]], field: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[str(record[field])].append(record)
    return {key: _stats(values) for key, values in sorted(groups.items())}


def _stats(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    values = list(records)
    total = len(values)
    return {
        "cases": total,
        "successes": sum(bool(x["success"]) for x in values),
        "asr": sum(bool(x["success"]) for x in values) / total if total else None,
        "errors": sum(bool(x["runtime_error"]) for x in values),
        "timeouts": sum(bool(x["timeout"]) for x in values),
        "parse_failures": sum(bool(x["parse_failure"]) for x in values),
        "protocol_completion_rate": sum(bool(x["protocol_completed"]) for x in values) / total if total else None,
        "judgment_completion_rate": sum(x["judgment_status"] == "completed" for x in values) / total if total else None,
    }


def finalize_model(out_dir: Path, manifest: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    records = _read_jsonl(out_dir / "details.jsonl")
    expected_ids = {case["case_id"] for case in manifest["cases"]}
    ids = [record["case_id"] for record in records]
    duplicates = sorted(key for key, value in Counter(ids).items() if value > 1)
    missing = sorted(expected_ids - set(ids))
    extras = sorted(set(ids) - expected_ids)
    integrity = {
        "planned_cases": 3150, "completed_cases": len(records),
        "unique_case_ids": len(set(ids)), "duplicated_case_ids": len(duplicates),
        "missing_cases": len(missing), "extra_cases": len(extras),
        "b2_cases": sum(record["attack_type"] == "B2" for record in records),
        "duplicates": duplicates, "missing": missing, "extras": extras,
        "by_attack_counts": dict(sorted(Counter(x["attack_type"] for x in records).items())),
        "by_domain_counts": dict(sorted(Counter(x["domain"] for x in records).items())),
        "by_variant_counts": dict(sorted(Counter(x["variant"] for x in records).items())),
        "by_cell_counts": {"|".join(key): value for key, value in sorted(Counter(
            (x["attack_type"], x["domain"], x["variant"]) for x in records).items())},
    }
    complete = (len(records) == 3150 and not duplicates and not missing and not extras and not integrity["b2_cases"])
    integrity["complete"] = complete
    summary = {"model": config["model"], **_stats(records), "integrity": integrity,
               "manifest_sha256": config["manifest_sha256"], "config_sha256": config["config_sha256"],
               "prompt_sha256": config["prompt_sha256"], "sdk_version": SDK_VERSION,
               "generated_at": _now()}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, field in (("by_attack.json", "attack_type"), ("by_domain.json", "domain"), ("by_variant.json", "variant")):
        (out_dir / name).write_text(json.dumps(_bucket(records, field), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    failures = [record for record in records if record["judgment_status"] != "completed"]
    (out_dir / "failures.jsonl").write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in failures), encoding="utf-8")
    rerun = {"schema_version": "official-a2a-rerun-v1", "source_model": config["model"],
             "source_details_sha256": _sha_file(out_dir / "details.jsonl"),
             "cases": [{key: x[key] for key in ("case_id", "attack_type", "domain", "variant")} for x in failures]}
    (out_dir / "rerun_manifest.json").write_text(json.dumps(rerun, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    readme = f"""# Official A2A Main Experiment: {config['model']}

This directory is produced by the canonical strict runner. Every trial stays in
the denominator, including errors, timeouts, and parse failures. The Host and
deterministic peer use a2a-sdk {SDK_VERSION}; fallback is disabled.

Planned cases: 3,150. Completed cases: {len(records)}. Integrity complete: {complete}.
"""
    (out_dir / "README.md").write_text(readme, encoding="utf-8")
    if not complete and len(records) >= 3150:
        raise RuntimeError(f"Integrity validation failed for {config['model']}: {integrity}")
    return summary


def run_model(model: str, manifest_path: Path, results_root: Path, *, smoke: int = 0) -> None:
    if model not in MODELS:
        raise ValueError(f"Unsupported model {model!r}; permitted models: {MODELS}")
    _assert_runtime()
    manifest = load_manifest(manifest_path)
    manifest_sha = _sha_file(manifest_path)
    out_dir = results_root / model
    if smoke:
        out_dir = out_dir / "smoke"
    out_dir.mkdir(parents=True, exist_ok=True)
    config = _run_config(model, manifest_path, manifest_sha)
    config["phase"] = "smoke" if smoke else "formal"
    config["smoke_cases"] = smoke
    config_sha = _canonical_sha(config)
    config["config_sha256"] = config_sha
    config_path = out_dir / "run_config.yaml"
    if config_path.exists():
        previous = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if previous != config:
            raise RuntimeError(f"Refusing resume with changed configuration: {config_path}")
    else:
        config_path.write_text(yaml.safe_dump(config, sort_keys=True, allow_unicode=True), encoding="utf-8")
    (out_dir / "manifest.json").write_bytes(manifest_path.read_bytes())
    details_path = out_dir / "details.jsonl"
    completed_records = _read_jsonl(details_path)
    completed_ids = {record["case_id"] for record in completed_records}
    if len(completed_ids) != len(completed_records):
        raise RuntimeError("Existing details.jsonl contains duplicate case IDs.")

    cases = manifest["cases"]
    if smoke:
        # One deterministic case per attack-domain cell, spanning all variants.
        chosen = []
        for attack_idx, attack in enumerate(ATTACKS):
            for domain_idx, domain in enumerate(DOMAINS):
                variant = VARIANTS[(attack_idx + domain_idx) % len(VARIANTS)]
                chosen.append(next(x for x in cases if x["attack_type"] == attack and x["domain"] == domain and x["variant"] == variant))
        cases = chosen[:smoke]

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in cases:
        groups[(item["attack_type"], item["variant"])].append(item)
    host = OfficialSDKCardDiffHostSUT(
        model=API_MODELS[model], temperature=TEMPERATURE, max_retries=MAX_RETRIES,
        timeout_s=TIMEOUT_S, require_sdk=True,
    )
    _append(out_dir / "progress.jsonl", {"event": "run_start_or_resume", "timestamp": _now(),
            "model": model, "planned_cases": len(cases), "already_completed": len(completed_ids),
            "config_sha256": config_sha, "manifest_sha256": manifest_sha})
    for (attack, variant), group in sorted(groups.items()):
        pending = [item for item in group if item["case_id"] not in completed_ids]
        for item in pending:
            started = time.perf_counter()
            case = _load_case(item["class_path"])
            outcome = case.run(host, trial_index=0, environment={
                "factory": "harness.transfer.official_a2a_env:OfficialSDKCardDiffEnvironment",
                "kwargs": {"transport": "httpx-asgi", "sdk_server": True,
                           "require_sdk": True, "remote_agent_mode": "deterministic"},
            })
            elapsed = time.perf_counter() - started
            record = _canonical_record(outcome, item, model, config_sha, manifest_sha, elapsed)
            _append(details_path, record)
            completed_ids.add(item["case_id"])
            _append(out_dir / "progress.jsonl", {"event": "case_complete", "timestamp": _now(),
                    "case_id": item["case_id"], "attack_type": attack, "domain": item["domain"],
                    "variant": variant, "success": record["success"],
                    "judgment_status": record["judgment_status"], "completed_cases": len(completed_ids),
                    "planned_cases": len(cases), "elapsed_s": round(elapsed, 3)})
        checkpoint_done = all(item["case_id"] in completed_ids for item in group)
        if checkpoint_done:
            _append(out_dir / "progress.jsonl", {"event": "checkpoint_complete", "timestamp": _now(),
                    "model": model, "attack_type": attack, "variant": variant,
                    "cases": len(group), "details_sha256": _sha_file(details_path)})
    if smoke:
        smoke_records = _read_jsonl(details_path)
        evidence_bad = [x for x in smoke_records if
                        not x["official_a2a_sdk_evidence"]["resolver_used"] or
                        x["official_a2a_sdk_evidence"]["fallback_used"] is not False]
        judgment_count = sum(x["judgment_status"] == "completed" for x in smoke_records)
        # Smoke validates the integration, not the model's measured behavior.
        # Parse failures and isolated timeouts remain valid benchmark outcomes.
        passed = (len(smoke_records) == len(cases) and not evidence_bad and
                  judgment_count >= 1)
        result = {"model": model, "planned": len(cases), "completed": len(smoke_records),
                  "judgment_completed": judgment_count,
                  "judgment_completion_rate": judgment_count / len(smoke_records) if smoke_records else 0.0,
                  "sdk_evidence_failures": [x["case_id"] for x in evidence_bad],
                  "passed": passed,
                  "non_judgment_cases": [x["case_id"] for x in smoke_records if x["judgment_status"] != "completed"],
                  "generated_at": _now()}
        (out_dir / "smoke_summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if not result["passed"]:
            raise RuntimeError(f"Smoke test failed for {model}: {result}")
    else:
        finalize_model(out_dir, manifest, config)


def aggregate_cross_model(results_root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    matrix = {}
    source_files = {}
    for model in MODELS:
        model_dir = results_root / model
        records = _read_jsonl(model_dir / "details.jsonl")
        config = yaml.safe_load((model_dir / "run_config.yaml").read_text(encoding="utf-8"))
        summary = finalize_model(model_dir, manifest, config)
        if not summary["integrity"]["complete"]:
            raise RuntimeError(f"Cannot aggregate incomplete model {model}.")
        matrix[model] = {"overall": _stats(records), "by_attack": _bucket(records, "attack_type"),
                         "by_domain": _bucket(records, "domain"), "by_variant": _bucket(records, "variant")}
        source_files[model] = {
            "details": str((model_dir / "details.jsonl").relative_to(ROOT)).replace("\\", "/"),
            "details_sha256": _sha_file(model_dir / "details.jsonl"),
            "config_sha256": config["config_sha256"],
        }
    output = {"schema_version": "official-a2a-cross-model-v1", "generated_at": _now(),
              "manifest_sha256": _sha_file(manifest_path), "prompt_sha256": canonical_prompt_sha256(),
              "code_commit_sha": _git_sha(), "official_a2a_sdk_version": SDK_VERSION,
              "models": matrix, "source_files": source_files,
              "gpt_5_mini_reuse_decision": {
                  "decision": "full_rerun",
                  "candidate_cases": 630,
                  "reason": "Historical retained records were not homogeneous with the canonical SDK-backed L3 run: the original records report transfer-v1/a2a-http-json and localhost TCP events, while only the non-judgment subset was rerun on the SDK-backed implementation. Mixing them would violate Host, SDK evidence, output-schema, timeout, and config equivalence.",
              }}
    results_root.mkdir(parents=True, exist_ok=True)
    (results_root / "cross_model_matrix.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    canonical = {key: output[key] for key in ("schema_version", "generated_at", "manifest_sha256", "prompt_sha256",
                 "code_commit_sha", "official_a2a_sdk_version", "source_files", "gpt_5_mini_reuse_decision")}
    canonical["cross_model_matrix_sha256"] = _sha_file(results_root / "cross_model_matrix.json")
    (results_root / "canonical_manifest.json").write_text(json.dumps(canonical, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build_p = sub.add_parser("build-manifest")
    build_p.add_argument("--output", type=Path, default=DEFAULT_MANIFEST)
    validate_p = sub.add_parser("validate-manifest")
    validate_p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    run_p = sub.add_parser("run")
    run_p.add_argument("--model", required=True)
    run_p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    run_p.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS)
    run_p.add_argument("--smoke", type=int, choices=range(7, 22), metavar="N", default=0)
    agg_p = sub.add_parser("aggregate")
    agg_p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    agg_p.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args()
    if args.command == "build-manifest":
        payload = build_manifest(args.output)
        print(json.dumps({"path": str(args.output), "cases": len(payload["cases"]), "sha256": _sha_file(args.output)}, indent=2))
    elif args.command == "validate-manifest":
        payload = load_manifest(args.manifest)
        print(json.dumps({"valid": True, "cases": len(payload["cases"]), "sha256": _sha_file(args.manifest)}, indent=2))
    elif args.command == "run":
        run_model(args.model, args.manifest, args.results_root, smoke=args.smoke)
    else:
        aggregate_cross_model(args.results_root, args.manifest)


if __name__ == "__main__":
    main()
