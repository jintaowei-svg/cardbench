from __future__ import annotations

import json
from pathlib import Path

from sut.transfer_native.canonical_view import build_canonical_view


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "attacks/carddiff/transfer_full/langgraph_cases.json"
RERUN_IDS = ROOT / "attacks/carddiff/transfer_full/langgraph_b1_neutral_rerun_ids.json"
SMOKE_IDS = ROOT / "attacks/carddiff/transfer_full/langgraph_b1_neutral_smoke_ids.json"
FORBIDDEN = ("attacker", "trusted", "oracle")


def prepare() -> dict[str, object]:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases = [case for case in payload["cases"] if case["attack_type"] == "B1"]
    if len(cases) != 450:
        raise RuntimeError(f"Expected 450 LangGraph B1 cases, found {len(cases)}")

    for case in cases:
        view = build_canonical_view(case["canonical_state"])
        serialized = json.dumps(view, ensure_ascii=False, sort_keys=True).lower()
        leaked = [term for term in FORBIDDEN if term in serialized]
        if leaked:
            raise RuntimeError(
                f"Private role label leaked into {case['target_case_id']}: {leaked}"
            )
        ids = [item["id"] for item in view["capabilities"]]
        if ids != ["participant_1", "participant_2"]:
            raise RuntimeError(f"Non-neutral B1 participants in {case['target_case_id']}: {ids}")

    rerun_ids = [str(case["target_case_id"]) for case in cases]
    smoke_ids = [
        next(str(case["target_case_id"]) for case in cases if case["domain"] == domain)
        for domain in ("finance", "healthcare", "travel")
    ]
    RERUN_IDS.write_text(
        json.dumps(
            {
                "schema_version": "carddiff-langgraph-b1-neutral-rerun-v1",
                "langgraph": rerun_ids,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    SMOKE_IDS.write_text(
        json.dumps(
            {
                "schema_version": "carddiff-langgraph-b1-neutral-smoke-v1",
                "langgraph": smoke_ids,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "rerun_cases": len(rerun_ids),
        "smoke_cases": len(smoke_ids),
        "forbidden_labels": list(FORBIDDEN),
    }


if __name__ == "__main__":
    print(json.dumps(prepare(), indent=2, sort_keys=True))
