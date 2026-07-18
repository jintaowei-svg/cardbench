from __future__ import annotations

"""Refresh active case references after a taxonomy-preserving identifier migration."""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "attacks/carddiff/official_a2a_main_3150.json"
DEFENSE = ROOT / "attacks/carddiff/defense/nemo_official_a2a_630.json"
DOWNSTREAM = (
    ROOT / "attacks/carddiff/downstream/official_a2a_triggered_621.json",
    ROOT / "attacks/carddiff/downstream/official_a2a_recorded_triggered_3116.json",
    ROOT / "attacks/carddiff/downstream/official_a2a_recorded_smoke_140.json",
    ROOT / "attacks/carddiff/downstream/official_a2a_recorded_missing_111_local.json",
)


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _index() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    payload = json.loads(MAIN.read_text(encoding="utf-8"))
    return payload, {str(case["case_id"]): case for case in payload["cases"]}


def build_defense(main: dict[str, Any]) -> None:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in main["cases"]:
        grouped[(case["attack_type"], case["domain"], case["variant"])].append(case)
    selected = []
    for key in sorted(grouped):
        selected.extend(sorted(grouped[key], key=lambda item: item["case_id"])[:10])
    if len(selected) != 630:
        raise ValueError(f"Expected 630 defense cases, found {len(selected)}")
    _write(
        DEFENSE,
        {
            "schema_version": "carddiff-defense-manifest-v1",
            "manifest_id": "nemo_official_a2a_630",
            "parent_manifest": "official_a2a_main_3150",
            "sampling": "case_id_ascending_first_10_per_attack_domain_variant",
            "cases": selected,
        },
    )


def refresh_downstream(path: Path, index: dict[str, dict[str, Any]]) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    for case in payload.get("cases", []):
        canonical = index.get(str(case.get("case_id")))
        if canonical is None:
            raise ValueError(f"{path} contains a case absent from the canonical manifest: {case.get('case_id')}")
        for key in ("attack_type", "class_path", "variant", "base_task_id"):
            if key in canonical:
                case[key] = canonical[key]
        if "scenario" in case:
            case["scenario"] = canonical["domain"]
        if "case_sha256" in case:
            case["case_sha256"] = canonical["case_sha256"]
        if "source_case_sha256" in case:
            case["source_case_sha256"] = canonical["case_sha256"]
    _write(path, payload)


def main() -> None:
    main, index = _index()
    build_defense(main)
    for path in DOWNSTREAM:
        refresh_downstream(path, index)
    print(json.dumps({"defense_cases": 630, "downstream_manifests": len(DOWNSTREAM)}, indent=2))


if __name__ == "__main__":
    main()
