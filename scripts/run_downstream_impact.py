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

from harness.downstream.impact_oracles import IMPACT_TYPES, judge_impact
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
    rows, infra = [], []
    details_path = out_dir / "details.jsonl"
    with details_path.open("w", encoding="utf-8") as fp:
        for item in cases:
            case = _load(item["class_path"])()
            errors: list[str] = []
            events: list[dict[str, Any]] = []
            sdk: dict[str, Any] = {}
            for attempt in range(2):
                with env_cls(case.metadata, 0, manifest_case=item, **env_kwargs) as env:
                    result = host.run_probe(env.public_view, env)
                    env.complete(); events = env.impact_events; sdk = env.metrics["protocol_execution"]
                    errors = [result.error_message] if result.error_message else []
                if not errors or attempt == 1:
                    break
                infra.append({"case_id": item["case_id"], "attempt": attempt + 1, "errors": errors})
            success = not errors and judge_impact(item["attack_type"], events, item)
            row = {"case_id": item["case_id"], "attack_type": item["attack_type"], "scenario": item["scenario"],
                   "variant": item["variant"], "impact_success": success, "impact_type": IMPACT_TYPES[item["attack_type"]],
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--config", required=True, type=Path)
    print(json.dumps(run(parser.parse_args().config), indent=2))
