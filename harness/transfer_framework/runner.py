from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import subprocess
from pathlib import Path
from typing import Any, Callable

import yaml

from harness.transfer_framework.evidence import validate_framework_evidence
from harness.transfer_framework.result_schema import FrameworkTrialResult
from harness.transfer_native.oracles import judge
from sut.transfer.common_llm import canonical_prompt_sha256
from sut.transfer_native.common_host import NativeTransferHost
from sut.transfer_native.strict_parser import parser_sha256


ROOT = Path(__file__).resolve().parents[2]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _resolve(path: str) -> Any:
    module, name = path.split(":", 1)
    return getattr(importlib.import_module(module), name)


def load_config(path: Path) -> dict[str, Any]:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or config.get("target_kind") != "framework":
        raise TypeError("Framework transfer config must declare target_kind: framework.")
    forbidden = {
        "parse_failure_fallback",
        "interface_fallback",
        "capability_fallback",
        "attack_specific_prompt",
        "model_specific_prompt",
    }
    if any(config.get(key) is True for key in forbidden):
        raise ValueError("Fallback and prompt specialization are forbidden.")
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
    manifest_path = ROOT / config["case_manifest"]
    applicability_path = ROOT / config["applicability_manifest"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    applicability = json.loads(applicability_path.read_text(encoding="utf-8"))
    framework = str(config["target"])
    if applicability.get("frozen") is not True:
        raise ValueError("Applicability must be frozen before a formal run.")
    cases = list(manifest["cases"])
    if case_id_manifest is not None:
        smoke = json.loads(case_id_manifest.read_text(encoding="utf-8"))
        wanted = set(smoke[framework])
        cases = [case for case in cases if case["target_case_id"] in wanted]
        if len(cases) != len(wanted):
            raise ValueError("Smoke case-ID manifest does not exactly match the framework cases.")
    if limit is not None:
        cases = cases[:limit]
    adapter_cls = _resolve(config["adapter"])
    adapter = adapter_cls(require_native_sdk=bool(config.get("require_native_sdk", True)))
    host = NativeTransferHost(
        adapter,
        model=config["model"],
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
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        events = execution.events if execution is not None else []
        if execution is not None:
            valid, missing = validate_framework_evidence(
                framework, case["attack_type"], events
            )
        elif error is None:
            valid, missing = None, []
        else:
            valid, missing = False, validate_framework_evidence(
                framework, case["attack_type"], events
            )[1]
        success, components = False, {"not_judged": True}
        if execution is not None and valid is True:
            success, components = judge(case["attack_type"], execution.facts)
        record = FrameworkTrialResult(
            "carddiff-transfer-framework-v1",
            "framework",
            framework,
            case["master_case_id"],
            case["source_case_id"],
            case["target_case_id"],
            case["attack_type"],
            case["domain"],
            case["variant"],
            trial_index,
            success,
            components,
            valid,
            missing,
            [event.to_dict() for event in events],
            decision,
            metrics,
            error,
        ).to_dict()
        runtime = config.get("runtime", {})
        record["provenance"] = {
            "git_commit": _git_commit(),
            "prompt_sha256": canonical_prompt_sha256(),
            "parser_sha256": parser_sha256(),
            "manifest_sha256": _sha(manifest_path),
            "config_sha256": _sha(config_path),
            "applicability_sha256": _sha(applicability_path),
            "target_runtime_version": runtime.get(
                "autogen_agentchat", runtime.get("langgraph")
            ),
            "target_runtime_commit": None,
            "target_runtime_digest": None,
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
