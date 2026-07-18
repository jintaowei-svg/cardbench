from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import build_transfer_extension_cases as extension
from scripts import build_transfer_native_cases as native


SOURCE = ROOT / "attacks/carddiff/perturbed_cases.jsonl"
LEGACY_MASTER = ROOT / "attacks/carddiff/transfer_native/master_cases.json"
NATIVE_APPLICABILITY = ROOT / "attacks/carddiff/transfer_native/applicability.json"
EXTENSION_APPLICABILITY = ROOT / "attacks/carddiff/transfer_extension/applicability.json"
OUTPUT = ROOT / "attacks/carddiff/transfer_full"
ATTACKS = ("A2", "A3", "B1", "B2", "C1", "C2")
CASES_PER_CELL = 50
CASES_PER_ATTACK = 450


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _full_master(case: dict[str, Any], legacy: dict[str, dict[str, Any]]) -> dict[str, Any]:
    previous = legacy.get(case["case_id"])
    if previous is not None:
        return previous
    master = native._master(case, 0)
    master["master_case_id"] = f"TRANSFER-FULL-{case['case_id']}"
    return master


def build() -> dict[str, int]:
    native_applicability = _read_json(NATIVE_APPLICABILITY)
    extension_applicability = _read_json(EXTENSION_APPLICABILITY)
    if native_applicability.get("frozen") is not True:
        raise RuntimeError("Native applicability must be frozen.")
    if extension_applicability.get("frozen") is not True:
        raise RuntimeError("Extension applicability must be frozen.")

    source_cases = [
        json.loads(line)
        for line in SOURCE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in source_cases:
        attack = str(case["attack_type"])
        variant = native._variant(case)
        if attack in ATTACKS and variant in {"001", "002", "003"}:
            grouped[(attack, native._domain(case), variant)].append(case)

    selected: list[dict[str, Any]] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda item: item["case_id"])
        if len(group) != CASES_PER_CELL:
            raise RuntimeError(
                f"Expected {CASES_PER_CELL} source cases for {key}, found {len(group)}"
            )
        selected.extend(group)
    if len(selected) != len(ATTACKS) * CASES_PER_ATTACK:
        raise RuntimeError(f"Expected 2,700 full master cases, found {len(selected)}")

    legacy_payload = _read_json(LEGACY_MASTER)
    legacy = {item["source_case_id"]: item for item in legacy_payload["cases"]}
    masters = [_full_master(case, legacy) for case in selected]
    master_by_source = {item["source_case_id"]: item for item in masters}

    outputs: dict[str, list[dict[str, Any]]] = {
        "anp": [],
        "nlip": [],
        "agntcy": [],
        "autogen": [],
        "langgraph": [],
    }
    for case in selected:
        attack = str(case["attack_type"])
        master = master_by_source[case["case_id"]]
        if native_applicability["anp"].get(attack) == "applicable":
            outputs["anp"].append(
                {
                    **master,
                    "target_case_id": master["target_case_ids"]["anp"],
                    "canonical_state": native._canonical_state(case, protocol="anp"),
                    "native": native._anp_native(case),
                }
            )
        if native_applicability["nlip"].get(attack) == "applicable":
            outputs["nlip"].append(
                {
                    **master,
                    "target_case_id": master["target_case_ids"]["nlip"],
                    "canonical_state": native._canonical_state(case, protocol="nlip"),
                    "native": native._nlip_native(case),
                }
            )
        if extension_applicability["agntcy"].get(attack) == "applicable":
            outputs["agntcy"].append(extension._agntcy_case(master, case))
        if extension_applicability["autogen"].get(attack) == "applicable":
            outputs["autogen"].append(extension._autogen_case(master, case))
        if extension_applicability["langgraph"].get(attack) == "applicable":
            outputs["langgraph"].append(extension._langgraph_case(master, case))

    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "master_cases.json").write_text(
        json.dumps(
            {
                "schema_version": "carddiff-transfer-full-master-v1",
                "source_sha256": _sha(SOURCE),
                "sampling": "complete_50_per_attack_domain_variant",
                "cases_per_attack": CASES_PER_ATTACK,
                "cases": masters,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    for target, cases in outputs.items():
        attacks = sorted({case["attack_type"] for case in cases})
        counts = {attack: sum(case["attack_type"] == attack for case in cases) for attack in attacks}
        if set(counts.values()) != {CASES_PER_ATTACK}:
            raise RuntimeError(f"Invalid full counts for {target}: {counts}")
        payload = {
            "schema_version": "carddiff-transfer-full-cases-v1",
            "target": target,
            "cases_per_attack": CASES_PER_ATTACK,
            "source_master_sha256": _sha(OUTPUT / "master_cases.json"),
            "cases": cases,
        }
        (OUTPUT / f"{target}_cases.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    smoke = {
        target: [
            next(case["target_case_id"] for case in cases if case["attack_type"] == attack)
            for attack in sorted({case["attack_type"] for case in cases})
        ]
        for target, cases in outputs.items()
    }
    (OUTPUT / "smoke_case_ids.json").write_text(
        json.dumps({"schema_version": "carddiff-transfer-full-smoke-v1", **smoke}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return {"master": len(masters), **{target: len(cases) for target, cases in outputs.items()}}


if __name__ == "__main__":
    print(json.dumps(build(), indent=2, sort_keys=True))
