from __future__ import annotations

"""Run one paid decision or the complete deterministic Official A2A split."""

import argparse
import importlib
import json
from pathlib import Path

from attacks.instances.carddiff_perturbed import CardDiffPerturbed001
from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT

ROOT = Path(__file__).resolve().parents[1]


def _deterministic(**kwargs: object) -> str:
    view = json.loads(str(kwargs["user"]))
    return json.dumps({"should_send": True, "capability_id": view["capabilities"][0]["id"],
        "interface_index": 1, "accept_output": True, "final_status": "completed", "reason": "deterministic smoke"})


def _load_case(class_path: str):
    module_name, class_name = class_path.split(":", 1)
    return getattr(importlib.import_module(module_name), class_name)()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["official_a2a"], default="official_a2a")
    parser.add_argument("--deterministic", action="store_true")
    args = parser.parse_args()
    cases = [CardDiffPerturbed001()]
    if args.deterministic:
        manifest = json.loads((ROOT / "attacks/carddiff/transfer/splits/official_a2a_720.json").read_text(encoding="utf-8"))
        cases = [_load_case(item["class_path"]) for item in manifest["cases"]]
    host = OfficialSDKCardDiffHostSUT(model="gpt-5-mini", temperature=0, max_retries=1,
        decision_callable=_deterministic if args.deterministic else None)
    outcomes = [case.run(
        host,
        environment={
            "factory": "harness.transfer.official_a2a_env:OfficialSDKCardDiffEnvironment",
            "kwargs": {"remote_agent_mode": "deterministic"},
        },
    ) for case in cases]
    protocol_errors = sum(bool(outcome.errors) for outcome in outcomes)
    evidence_failures = sum(not (outcome.details["metrics"]["protocol_execution"]["client_factory_used"]
        and outcome.details["metrics"]["protocol_execution"]["sdk_server_used"]) for outcome in outcomes)
    print(json.dumps({"target": args.target, "deterministic": args.deterministic, "cases": len(outcomes),
        "completed": len(outcomes) - protocol_errors, "protocol_errors": protocol_errors,
        "sdk_evidence_failures": evidence_failures}, sort_keys=True))


if __name__ == "__main__":
    main()
