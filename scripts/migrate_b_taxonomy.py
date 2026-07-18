from __future__ import annotations

"""Migrate active artifacts from the legacy B2/B3 labels to canonical B1/B2.

The legacy taxonomy used B2 for Same-URL Multi-Tenant Confusion and B3 for
Binding Downgrade / Version Confusion. The canonical taxonomy removes the
former vector and renames the latter to B2. Archived inputs are intentionally
out of scope.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TASK_BANK = ROOT / "attacks/carddiff/scenario_tasks.json"
MIGRATION_MANIFEST = ROOT / "results/taxonomy_b2_migration_manifest.json"
ACTIVE_ARTIFACT_ROOTS = (
    ROOT / "attacks/carddiff",
    ROOT / "defense/nemo/results",
    ROOT / "results",
    ROOT / "remote_results",
)
EXCLUDED_GENERATED_INPUTS = {
    ROOT / "attacks/carddiff/cases.jsonl",
    ROOT / "attacks/carddiff/perturbed_cases.jsonl",
}
TEXT_SUFFIXES = {".csv", ".json", ".jsonl", ".log", ".md", ".tex", ".txt", ".yaml", ".yml"}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _replace_label(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("B3", "B2").replace("b3", "b2")
    if isinstance(value, list):
        return [_replace_label(item) for item in value]
    if isinstance(value, dict):
        return {_replace_label(key): _replace_label(item) for key, item in value.items()}
    return value


def migrate_task_bank() -> dict[str, str]:
    before = _sha(TASK_BANK)
    payload = json.loads(TASK_BANK.read_text(encoding="utf-8"))
    cells = []
    removed = 0
    renamed = 0
    for cell in payload.get("cells", []):
        attack = str(cell.get("attack_type", ""))
        name = str(cell.get("attack_name", ""))
        if attack == "B2" and name == "Same-URL Multi-Tenant Confusion":
            removed += 1
            continue
        if attack == "B3" and name == "Binding Downgrade / Version Confusion":
            cell = _replace_label(cell)
            cell["attack_type"] = "B2"
            cell["taxonomy"] = "Interface Selection/Binding Confusion"
            renamed += 1
        cells.append(cell)
    if removed != 3 or renamed != 3:
        raise ValueError(
            f"Expected three legacy B2 cells and three binding B3 cells; "
            f"found removed={removed}, renamed={renamed}."
        )
    payload["cells"] = cells
    payload["taxonomy_migration"] = {
        "removed": "B2 Same-URL Multi-Tenant Confusion",
        "renamed": "B3 Binding Downgrade / Version Confusion -> B2",
        "numeric_results_changed": False,
    }
    TASK_BANK.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return {"path": TASK_BANK.relative_to(ROOT).as_posix(), "before_sha256": before, "after_sha256": _sha(TASK_BANK)}


def _repair_legacy_integrity_fields(value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _repair_legacy_integrity_fields(item)
        return
    if not isinstance(value, dict):
        return
    if "b2_cases" in value:
        value["legacy_tenant_confusion_cases"] = value.pop("b2_cases")
        counts = value.get("by_attack_counts")
        if isinstance(counts, dict) and "B2" in counts:
            value["canonical_binding_b2_cases"] = counts["B2"]
    for item in value.values():
        _repair_legacy_integrity_fields(item)


def migrate_artifact(path: Path) -> dict[str, str] | None:
    if path == MIGRATION_MANIFEST or path in EXCLUDED_GENERATED_INPUTS:
        return None
    raw = path.read_text(encoding="utf-8-sig")
    if "B3" not in raw and "b3" not in raw:
        return None
    before = _sha(path)
    migrated = raw.replace("B3", "B2").replace("b3", "b2")
    if path.suffix == ".json":
        payload = json.loads(migrated)
        _repair_legacy_integrity_fields(payload)
        migrated = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    path.write_text(migrated, encoding="utf-8", newline="")
    return {"path": path.relative_to(ROOT).as_posix(), "before_sha256": before, "after_sha256": _sha(path)}


def migrate_active_artifacts() -> list[dict[str, str]]:
    changed = []
    for root in ACTIVE_ARTIFACT_ROOTS:
        if not root.exists():
            continue
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            record = migrate_artifact(path)
            if record is not None:
                changed.append(record)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--skip-task-bank",
        action="store_true",
        help="Only relabel active experiment artifacts; use after the task bank was already migrated.",
    )
    args = parser.parse_args()
    records = []
    if not args.skip_task_bank:
        records.append(migrate_task_bank())
    records.extend(migrate_active_artifacts())
    manifest = {
        "schema_version": "carddiff-taxonomy-migration-v1",
        "migration": {
            "removed": "legacy B2 Same-URL Multi-Tenant Confusion",
            "renamed": "legacy B3 Binding Downgrade / Version Confusion to canonical B2",
            "numeric_results_changed": False,
            "hash_policy": "before/after file hashes preserve the byte-level migration audit; embedded run-input hashes continue to identify the original execution inputs",
        },
        "files": records,
    }
    MIGRATION_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MIGRATION_MANIFEST.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"changed_files": len(records), "manifest": str(MIGRATION_MANIFEST)}, indent=2))


if __name__ == "__main__":
    main()
