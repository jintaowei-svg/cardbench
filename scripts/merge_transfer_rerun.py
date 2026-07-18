from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def merge(
    original_path: Path,
    rerun_path: Path,
    manifest_path: Path,
    output_path: Path,
    *,
    target: str,
) -> list[dict[str, Any]]:
    original = _load(original_path)
    rerun = _load(rerun_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = set(manifest[target])
    replacements = {str(row["target_case_id"]): row for row in rerun}
    if set(replacements) != expected or len(replacements) != len(rerun):
        raise ValueError("Rerun records do not exactly match the frozen replacement manifest.")

    original_by_id = {str(row["target_case_id"]): row for row in original}
    if not expected <= set(original_by_id):
        raise ValueError("Replacement manifest includes IDs absent from the original run.")
    for case_id in sorted(expected):
        old = original_by_id[case_id]
        new = replacements[case_id]
        if old.get("native_execution_valid") is not False or not old.get("error"):
            raise ValueError(f"Original {case_id} is not an infrastructure failure.")
        if new.get("native_execution_valid") is not True or new.get("error") is not None:
            raise ValueError(f"Replacement {case_id} is not a valid completed native trial.")
        for field in (
            "master_case_id",
            "source_case_id",
            "target_case_id",
            "attack_type",
            "domain",
            "variant",
        ):
            if old.get(field) != new.get(field):
                raise ValueError(f"Replacement identity mismatch for {case_id}: {field}")

    merged = [
        replacements.get(str(row["target_case_id"]), row)
        for row in original
    ]
    if len(merged) != len(original):
        raise AssertionError("Replacement changed the frozen trial count.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in merged),
        encoding="utf-8",
    )
    return merged


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--rerun", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    rows = merge(
        args.original,
        args.rerun,
        args.manifest,
        args.output,
        target=args.target,
    )
    print(json.dumps({"output": str(args.output), "records": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
