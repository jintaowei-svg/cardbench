from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import subprocess
from pathlib import Path
from typing import Any, Callable

import yaml

from harness.transfer_native.evidence import validate_native_evidence
from harness.transfer_native.oracles import judge
from harness.transfer_native.result_schema import NativeTrialResult
from sut.transfer.common_llm import canonical_prompt_sha256
from sut.transfer_native.common_host import NativeTransferHost
from sut.transfer_native.strict_parser import parser_sha256


ROOT = Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve(path: str) -> Any:
    module, name = path.split(":", 1)
    return getattr(importlib.import_module(module), name)


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def load_config(path: Path) -> dict[str, Any]:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise TypeError("Native transfer config must be a mapping.")
    forbidden_true = {
        "parse_failure_fallback",
        "interface_fallback",
        "capability_fallback",
        "attack_specific_prompt",
        "model_specific_prompt",
    }
    enabled = sorted(key for key in forbidden_true if config.get(key) is True)
    if enabled:
        raise ValueError(f"Fallback or prompt specialization is forbidden: {enabled}")
    if config.get("strict_json_parsing") is not True or config.get("event_level_oracle") is not True:
        raise ValueError("Strict parsing and event-level oracle must be enabled.")
    return config


def run_manifest(
    config_path: Path,
    *,
    output_path: Path,
    decision_callable: Callable[..., str] | None = None,
    limit: int | None = None,
    case_id_manifest: Path | None = None,
    resume: bool = False,
) -> list[dict[str, Any]]:
    config = load_config(config_path)
    manifest_path = ROOT / str(config["case_manifest"])
    applicability_path = ROOT / str(config["applicability_manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    applicability = json.loads(applicability_path.read_text(encoding="utf-8"))
    protocol = str(config["target"])
    if applicability.get("frozen") is not True:
        raise ValueError("Applicability must be frozen before a formal run.")

    adapter_cls = _resolve(str(config["adapter"]))
    adapter = adapter_cls(require_native_sdk=bool(config.get("require_native_sdk", True)))
    host = NativeTransferHost(
        adapter,
        model=str(config["model"]),
        temperature=float(config["temperature"]),
        max_retries=int(config["max_retries"]),
        decision_callable=decision_callable,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    if resume and output_path.exists():
        records = [
            json.loads(line)
            for line in output_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        output_path.write_text("", encoding="utf-8")
    cases = list(manifest["cases"])
    if case_id_manifest is not None:
        smoke = json.loads(case_id_manifest.read_text(encoding="utf-8"))
        wanted = set(smoke[protocol])
        cases = [case for case in cases if case["target_case_id"] in wanted]
        if len(cases) != len(wanted):
            raise ValueError("Smoke case-ID manifest does not exactly match the native cases.")
    if limit is not None:
        cases = cases[:limit]
    completed_ids = [str(record["target_case_id"]) for record in records]
    if len(completed_ids) != len(set(completed_ids)):
        raise ValueError("Resume output contains duplicate target_case_id values.")
    planned_ids = {str(case["target_case_id"]) for case in cases}
    unexpected = sorted(set(completed_ids) - planned_ids)
    if unexpected:
        raise ValueError(f"Resume output contains IDs outside the selected manifest: {unexpected[:3]}")
    completed = set(completed_ids)
    for trial_index, case in enumerate(cases):
        if str(case["target_case_id"]) in completed:
            continue
        error = None
        decision = None
        metrics: dict[str, Any] = {}
        execution = None
        try:
            decision, metrics, execution = host.run(case)
        except Exception as exc:  # Preserve infrastructure failures as trials.
            error = f"{type(exc).__name__}: {exc}"
        events = execution.events if execution is not None else []
        if execution is not None:
            valid, missing = validate_native_evidence(protocol, case["attack_type"], events)
        elif error is None:
            # Parse failures, refusals, and incomplete safe decisions are valid
            # trial outcomes but are not native executions and are not judged.
            valid, missing = None, []
        else:
            valid, missing = False, validate_native_evidence(protocol, case["attack_type"], events)[1]
        success, components = (False, {"not_judged": True})
        if execution is not None and valid is True:
            success, components = judge(case["attack_type"], execution.facts)
        record = NativeTrialResult(
            schema_version="carddiff-transfer-native-v1",
            protocol=protocol,
            master_case_id=case["master_case_id"],
            source_case_id=case["source_case_id"],
            target_case_id=case["target_case_id"],
            attack_type=case["attack_type"],
            domain=case["domain"],
            variant=case["variant"],
            trial_index=trial_index,
            success=success,
            oracle_components=components,
            native_execution_valid=valid,
            missing_native_events=missing,
            events=[event.to_dict() for event in events],
            decision=decision,
            metrics=metrics,
            error=error,
        ).to_dict()
        record["provenance"] = {
            "git_commit": _git_commit(),
            "prompt_sha256": canonical_prompt_sha256(),
            "parser_sha256": parser_sha256(),
            "manifest_sha256": sha256_file(manifest_path),
            "config_sha256": sha256_file(config_path),
            "applicability_sha256": sha256_file(applicability_path),
            "target_runtime_version": config.get("runtime", {}).get("sdk_version"),
            "target_runtime_commit": config.get("runtime", {}).get("sdk_commit"),
            "target_runtime_digest": config.get("runtime", {}).get(
                "directory_binary_sha256"
            ),
        }
        records.append(record)
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--case-id-manifest", type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    run_manifest(
        args.config,
        output_path=args.output,
        limit=args.limit,
        case_id_manifest=args.case_id_manifest,
        resume=args.resume,
    )


if __name__ == "__main__":
    main()
