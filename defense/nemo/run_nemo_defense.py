from __future__ import annotations

"""Run NeMo Guardrails before the frozen Official A2A CardDiff split."""

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

import yaml

from defense.nemo.gateway import NemoGateway, build_security_context
from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT
from utils.env import load_repo_env


ROOT = Path(__file__).resolve().parents[2]
ATTACKS = ("A1", "A2", "A3", "B1", "B3", "C1", "C2")
DOMAINS = ("travel", "healthcare", "finance")


def _load_case(class_path: str) -> Any:
    module_name, class_name = class_path.split(":", 1)
    return getattr(importlib.import_module(module_name), class_name)()


def _manifest_cases(path: Path) -> tuple[dict[str, Any], list[dict[str, str]], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("Manifest must be an object containing a cases list.")
    selected: list[dict[str, str]] = []
    seen: set[str] = set()
    counts: dict[tuple[str, str], int] = {}
    for item in payload["cases"]:
        case = _load_case(str(item["class_path"]))
        if case.attack_type not in ATTACKS:
            continue
        if case.case_id in seen:
            raise ValueError(f"Duplicate selected case: {case.case_id}")
        seen.add(case.case_id)
        counts[(case.attack_type, case.scenario)] = counts.get(
            (case.attack_type, case.scenario), 0
        ) + 1
        selected.append({"case_id": case.case_id, "class_path": str(item["class_path"])})
    expected = {(attack, domain): 30 for attack in ATTACKS for domain in DOMAINS}
    if counts != expected or len(selected) != 630:
        raise ValueError(
            f"Selected split is not the frozen 7 x 3 x 30 design: "
            f"selected={len(selected)}, counts={counts}"
        )
    canonical = json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()
    return payload, selected, hashlib.sha256(canonical).hexdigest()


def _dry_run_cases(cases: list[dict[str, str]]) -> list[dict[str, str]]:
    chosen: dict[str, dict[str, str]] = {}
    for item in cases:
        attack = _load_case(item["class_path"]).attack_type
        chosen.setdefault(attack, item)
    return [chosen[attack] for attack in ATTACKS]


def _balanced_sample_cases(
    cases: list[dict[str, str]], sample_size: int
) -> list[dict[str, str]]:
    if sample_size < 1 or sample_size > len(cases):
        raise ValueError(f"--sample-size must be between 1 and {len(cases)}.")

    groups: dict[tuple[str, str], list[dict[str, str]]] = {
        (attack, domain): [] for attack in ATTACKS for domain in DOMAINS
    }
    for item in cases:
        case = _load_case(item["class_path"])
        groups[(case.attack_type, case.scenario)].append(item)

    ordered_groups = sorted(
        groups,
        key=lambda key: hashlib.sha256(f"{key[0]}:{key[1]}".encode()).hexdigest(),
    )
    base, remainder = divmod(sample_size, len(ordered_groups))
    selected_ids: set[str] = set()
    for index, key in enumerate(ordered_groups):
        take = base + (1 if index < remainder else 0)
        for item in groups[key][:take]:
            selected_ids.add(item["case_id"])
    return [item for item in cases if item["case_id"] in selected_ids]


def _variant_id(metadata: dict[str, Any]) -> str:
    return str(metadata.get("perturbation", {}).get("variant_id", "N/A"))


def _task_id(metadata: dict[str, Any]) -> str:
    return str(metadata.get("generation", {}).get("scenario_task_id", "N/A"))


def _base_record(
    case: Any,
    *,
    split_id: str,
    manifest_hash: str,
    guardrail_model: str,
    result: Any,
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "split_id": split_id,
        "manifest_hash": manifest_hash,
        "case_id": case.case_id,
        "attack_id": case.attack_type,
        "domain": case.scenario,
        "variant_id": _variant_id(case.metadata),
        "task_id": _task_id(case.metadata),
        "guardrail": "nemo",
        "guardrail_version": "0.23.0",
        "guardrail_model": guardrail_model,
        "guardrail_allow": result.allow,
        "guardrail_blocked": result.allow is False,
        "guardrail_raw_output": result.raw_output,
        "guardrail_latency_ms": round(result.latency_ms, 3),
        "guardrail_retry_count": result.retry_count,
        "guardrail_error": result.error,
    }


def _append(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def _config_with_api_base(config_path: Path, api_base: str | None) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if not api_base:
        return config_path, None

    temp_dir = tempfile.TemporaryDirectory(prefix="carddiff_nemo_")
    runtime_config = Path(temp_dir.name)
    shutil.copytree(config_path, runtime_config, dirs_exist_ok=True)

    config_file = runtime_config / "config.yml"
    payload = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    for model in payload.get("models", []):
        if model.get("type") == "main":
            parameters = dict(model.get("parameters", {}))
            parameters["base_url"] = api_base.rstrip("/")
            model["parameters"] = parameters
    config_file.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return runtime_config, temp_dir


def run(args: argparse.Namespace) -> dict[str, int]:
    load_repo_env(ROOT / ".env", override=False)
    # CardDiff's existing model variables can drive NeMo's OpenAI-compatible client.
    if os.getenv("SUT_API_KEY") and not os.getenv("OPENAI_API_KEY"):
        os.environ["OPENAI_API_KEY"] = str(os.environ["SUT_API_KEY"])
    if os.getenv("SUT_API_BASE") and not os.getenv("OPENAI_BASE_URL"):
        os.environ["OPENAI_BASE_URL"] = str(os.environ["SUT_API_BASE"])
    api_base = args.api_base or os.getenv("SUT_API_BASE") or os.getenv("OPENAI_BASE_URL")
    if api_base and not os.getenv("SUT_API_BASE"):
        os.environ["SUT_API_BASE"] = api_base
    if api_base and not os.getenv("OPENAI_BASE_URL"):
        os.environ["OPENAI_BASE_URL"] = api_base

    manifest_payload, cases, manifest_hash = _manifest_cases(args.manifest)
    base_split_id = f"{manifest_payload.get('split_id', args.manifest.stem)}_excluding_b2"
    split_id = f"{base_split_id}_630"
    if args.dry_run:
        cases = _dry_run_cases(cases)
        split_id = f"{base_split_id}_dryrun7"
    elif args.sample_size is not None:
        if args.sample_mode != "balanced":
            raise ValueError(f"Unsupported sample mode: {args.sample_mode}")
        cases = _balanced_sample_cases(cases, args.sample_size)
        split_id = f"{base_split_id}_balanced{args.sample_size}"

    completed_ids: set[str] = set()
    if args.output.exists():
        if not args.resume:
            raise FileExistsError(f"Output exists; pass --resume to continue: {args.output}")
        for line in args.output.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                if record.get("split_id") != split_id or record.get("manifest_hash") != manifest_hash:
                    raise ValueError("Existing output does not match the selected frozen split.")
                case_id = str(record["case_id"])
                if case_id in completed_ids:
                    raise ValueError(f"Duplicate case_id in existing output: {case_id}")
                completed_ids.add(case_id)

    guardrail_config, temp_config = _config_with_api_base(args.guardrail_config, api_base)
    gateway = NemoGateway(
        guardrail_config,
        max_retries=args.max_guardrail_retries,
        timeout_s=args.guardrail_timeout,
    )
    host = OfficialSDKCardDiffHostSUT(
        model=args.host_model,
        temperature=args.temperature,
        max_retries=args.host_retries,
        timeout_s=args.host_timeout,
    )
    environment = {
        "factory": "harness.transfer.official_a2a_env:OfficialSDKCardDiffEnvironment",
        "kwargs": {"remote_agent_mode": "deterministic", "require_sdk": True},
    }
    counts = {"planned": len(cases), "written": 0, "skipped": 0}
    loop = asyncio.new_event_loop()
    try:
        for item in cases:
            case = _load_case(item["class_path"])
            if case.case_id in completed_ids:
                counts["skipped"] += 1
                continue
            context = build_security_context(case.metadata)
            guardrail = loop.run_until_complete(gateway.check_with_nemo(context))
            record = _base_record(
                case,
                split_id=split_id,
                manifest_hash=manifest_hash,
                guardrail_model=args.guardrail_model,
                result=guardrail,
            )
            record.update({
                "host_model": args.host_model,
                "temperature": args.temperature,
                "host_retries": args.host_retries,
                "host_timeout_s": args.host_timeout,
                "guardrail_timeout_s": args.guardrail_timeout,
                "guardrail_api_base": api_base,
            })
            if guardrail.allow is None:
                record.update({
                    "host_executed": False,
                    "protocol_completed": False,
                    "attack_success": False,
                    "judgment_status": "non_judgment",
                    "error_category": "guardrail_error",
                })
            elif guardrail.allow is False:
                record.update({
                    "host_executed": False,
                    "protocol_completed": True,
                    "attack_success": False,
                    "judgment_status": "completed",
                    "error_category": None,
                })
            else:
                outcome = case.run(host, environment=environment, trial_index=0)
                host_error = bool(outcome.errors)
                record.update({
                    "host_executed": True,
                    "protocol_completed": not host_error,
                    "attack_success": bool(outcome.success) if not host_error else False,
                    "judgment_status": "non_judgment" if host_error else "completed",
                    "error_category": "host_error" if host_error else None,
                    "host_errors": list(outcome.errors),
                    "host_metrics": outcome.details.get("metrics", {}),
                })
            _append(args.output, record)
            counts["written"] += 1
            print(json.dumps({
                "case_id": case.case_id,
                "guardrail_allow": guardrail.allow,
                "attack_success": record["attack_success"],
                "error_category": record["error_category"],
            }, sort_keys=True), flush=True)
    finally:
        loop.close()
        if temp_config is not None:
            temp_config.cleanup()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest", type=Path,
        default=ROOT / "attacks/carddiff/transfer/splits/official_a2a_720.json",
        help="Frozen Official A2A manifest; B2 is deterministically excluded.",
    )
    parser.add_argument(
        "--guardrail-config", type=Path,
        default=ROOT / "defense/nemo/config",
    )
    parser.add_argument("--host-model", default="gpt-5-mini")
    parser.add_argument("--guardrail-model", default="gpt-5-mini")
    parser.add_argument("--temperature", type=float, default=0)
    parser.add_argument("--max-guardrail-retries", type=int, default=1)
    parser.add_argument("--guardrail-timeout", type=float, default=60)
    parser.add_argument(
        "--api-base",
        help="OpenAI-compatible base URL for the NeMo guardrail and host model.",
    )
    parser.add_argument("--host-retries", type=int, default=1)
    parser.add_argument("--host-timeout", type=float, default=15)
    parser.add_argument(
        "--output", type=Path,
        default=ROOT / "defense/nemo/results/raw/nemo_official_a2a_630.jsonl",
    )
    parser.add_argument("--dry-run", action="store_true", help="Run one case per attack (7 total).")
    parser.add_argument(
        "--sample-size",
        type=int,
        help="Run a deterministic balanced sample from the frozen excluding-B2 split.",
    )
    parser.add_argument("--sample-mode", choices=["balanced"], default="balanced")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.dry_run and args.sample_size is not None:
        parser.error("--dry-run and --sample-size cannot be used together.")
    if args.guardrail_model != "gpt-5-mini":
        parser.error("The frozen config uses guardrail-model gpt-5-mini.")
    print(json.dumps(run(args), sort_keys=True))


if __name__ == "__main__":
    main()
