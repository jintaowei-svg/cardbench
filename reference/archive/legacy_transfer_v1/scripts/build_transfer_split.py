from __future__ import annotations

"""Build deterministic, balanced CardDiff transfer manifests."""

import hashlib
import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "attacks" / "carddiff" / "perturbed_cases.jsonl"
OUTPUT = ROOT / "attacks" / "carddiff" / "transfer" / "splits"
APPLICABILITY = {
    "source_720": ["A1", "A2", "A3", "B1", "B2", "B3", "C1", "C2"],
    "official_a2a_720": ["A1", "A2", "A3", "B1", "B2", "B3", "C1", "C2"],
    "anp_540": ["A1", "A2", "B1", "B3", "C1", "C2"],
    "langgraph_270": ["B2", "C1", "C2"],
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _task_id(item: dict) -> str:
    return str(item["generation"]["scenario_task_id"])


def _stable_key(task_id: str) -> str:
    return _sha(("carddiff-transfer-v1:" + task_id).encode("utf-8"))


def build() -> dict[str, Path]:
    lines = [line for line in DATASET.read_text(encoding="utf-8").splitlines() if line]
    dataset_sha256 = _sha(("\n".join(lines) + "\n").encode("utf-8"))
    cases = [json.loads(line) for line in lines]
    grouped: dict[tuple[str, str], dict[str, list[tuple[int, dict]]]] = defaultdict(lambda: defaultdict(list))
    for index, item in enumerate(cases, start=1):
        grouped[(item["attack_type"], item["scenario"])][_task_id(item)].append((index, item))

    master: list[dict] = []
    for (_attack, _scenario), tasks in sorted(grouped.items()):
        selected = sorted(tasks, key=_stable_key)[:10]
        for task in selected:
            variants = sorted(tasks[task], key=lambda pair: str(pair[1]["perturbation"]["variant_id"]))
            for index, item in variants:
                if str(item["perturbation"]["variant_id"]) in {"001", "002", "003"}:
                    master.append({"case_id": item["case_id"], "class_path": f"attacks.instances.carddiff_perturbed:CardDiffPerturbed{index:03d}"})
    if len(master) != 720:
        raise RuntimeError(f"Expected 720 selected cases, got {len(master)}.")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, Path] = {}
    master_ids = {item["case_id"] for item in master}
    for split_id, attacks in APPLICABILITY.items():
        selected = [item for item in master if item["case_id"].split("_")[1] in attacks]
        payload = {"split_id": split_id, "parent_split": "transfer_master_720", "dataset_sha256": dataset_sha256, "sampling_seed": "carddiff-transfer-v1", "applicable_attacks": attacks, "cases": selected}
        target = OUTPUT / f"{split_id}.json"
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        outputs[split_id] = target
    master_payload = {"split_id": "transfer_master_720", "dataset_sha256": dataset_sha256, "sampling_seed": "carddiff-transfer-v1", "cases": master}
    target = OUTPUT / "transfer_master_720.json"
    target.write_text(json.dumps(master_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    outputs["transfer_master_720"] = target
    (OUTPUT.parent / "applicability.json").write_text(json.dumps(APPLICABILITY, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return outputs


if __name__ == "__main__":
    for name, path in build().items():
        print(f"{name}: {path}")
