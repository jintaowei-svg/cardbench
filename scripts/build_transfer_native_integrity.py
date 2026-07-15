from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATHS = (
    "attacks/carddiff/transfer_native/applicability.json",
    "attacks/carddiff/transfer_native/master_cases.json",
    "attacks/carddiff/transfer_native/anp_cases.json",
    "attacks/carddiff/transfer_native/nlip_cases.json",
    "attacks/carddiff/transfer_native/case_mapping.json",
    "configs/transfer_native/anp.yaml",
    "configs/transfer_native/nlip.yaml",
    "constraints/transfer-native.txt",
)
RESULT_PATHS = (
    "results/transfer_native/native_support_audit.json",
    "results/transfer_native/official_a2a_reference/details.jsonl",
    "results/transfer_native/official_a2a_reference/selected_case_ids.json",
    "results/transfer_native/official_a2a_reference/source_provenance.json",
    "results/transfer_native/official_a2a_reference/summary.json",
)


def build(output: Path) -> dict:
    files = {}
    for relative in DEFAULT_PATHS:
        path = ROOT / relative
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in RESULT_PATHS:
        path = ROOT / relative
        if path.is_file():
            files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"
    report = {"schema_version": "carddiff-transfer-native-integrity-v1", "git_commit": commit, "files": files}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "results/transfer_native/integrity_report.json")
    args = parser.parse_args()
    print(json.dumps(build(args.output), indent=2))
