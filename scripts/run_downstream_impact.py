from __future__ import annotations

import argparse
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml

from harness.downstream.impact_oracles import classify_impact
from harness.downstream.llm_workers import worker_registry_from_config
from harness.downstream.trace_loader import load_manifest
from scripts.summarize_downstream_impact import summarize


def _load(path: str) -> Any:
    module, name = path.split(":", 1)
    return getattr(importlib.import_module(module), name)


def run(config_path: Path) -> dict[str, Any]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    manifest_path = Path(config["manifest"]["path"])
    cases = load_manifest(manifest_path)
    out_dir = Path(config["output"]["directory"]); out_dir.mkdir(parents=True, exist_ok=True)
    host = _load(config["sut"]["carddiff_host"])(**config["sut"].get("kwargs", {}))
    env_cls = _load(config["environment"]["factory"])
    env_kwargs = dict(config["environment"].get("kwargs", {}))
    workers = worker_registry_from_config(config["workers"])
    env_kwargs["worker_registry"] = workers
    rows, infra = [], []
    details_path = out_dir / "details.jsonl"
    with details_path.open("w", encoding="utf-8") as fp:
        for item in cases:
            case = _load(item["class_path"])()
            errors: list[str] = []
            events: list[dict[str, Any]] = []
            sdk: dict[str, Any] = {}
            resource_before: dict[str, Any] = {}
            resource_after: dict[str, Any] = {}
            worker_result: Any | None = None
            for attempt in range(int(config["workers"].get("max_retries", 1)) + 1):
                with env_cls(case.metadata, 0, manifest_case=item, **env_kwargs) as env:
                    resource_before = env.resource.snapshot()
                    result = host.run_probe(env.public_view, env)
                    worker_infra = any(x["event_type"] == "worker_infrastructure_error" for x in env.impact_events)
                    if (result.error_message and item["attack_type"] == "B3" and
                            not worker_infra and not _is_transient(result.error_message)):
                        env.impact_recorder.record("task_unavailable", "carddiff-host", error=result.error_message)
                    env.complete(); events = env.impact_events; sdk = env.metrics["protocol_execution"]
                    resource_after = env.resource.snapshot(); worker_result = env.worker_result
                    errors = [result.error_message] if result.error_message else []
                retryable = bool(errors) and (_is_transient(errors[0]) or worker_infra)
                if not errors or not retryable or attempt == int(config["workers"].get("max_retries", 1)):
                    break
                infra.append({"case_id": item["case_id"], "attempt": attempt + 1, "errors": errors})
            impact_types = classify_impact(events, item)
            success = bool(impact_types)
            row = {"case_id": item["case_id"], "attack_type": item["attack_type"], "scenario": item["scenario"],
                   "variant": item["variant"], "worker_model": workers[item["scenario"]].model,
                   "selected_skill": item["decision"]["capability_id"],
                   "selected_interface": item["trace"]["selected_url"],
                   "identity": item["trace"]["identity"], "token_scopes": item["trace"]["token_scopes"],
                   "worker_tool_calls": worker_result.tool_calls if worker_result else [],
                   "worker_model_calls": worker_result.model_calls if worker_result else 0,
                   "artifact": worker_result.artifact if worker_result else {},
                   "resource_before": resource_before, "resource_after": resource_after,
                   "impact_success": success, "impact_type": impact_types,
                   "impact_events": events, "sdk_evidence": sdk, "errors": errors}
            fp.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"); fp.flush(); rows.append(row)
    summary = summarize(rows)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "impact_by_attack.json").write_text(json.dumps(summary["by_attack"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "impact_by_domain.json").write_text(json.dumps(summary["by_domain"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "impact_by_variant.json").write_text(json.dumps(summary["by_variant"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "infrastructure_failures.jsonl").write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in infra), encoding="utf-8")
    metadata = {"experiment_id": config["experiment_id"], "mode": config["mode"],
                "timestamp": datetime.now(timezone.utc).isoformat(), "manifest": str(manifest_path), "cases": len(cases)}
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def _is_transient(error: str) -> bool:
    value = error.lower()
    return any(token in value for token in ("rate limit", "429", "http 5", "timeout", "temporar", "connection"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--config", required=True, type=Path)
    print(json.dumps(run(parser.parse_args().config), indent=2))
