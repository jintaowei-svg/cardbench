from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "results" / "official_a2a_main" / "gpt-5-mini" / "details.jsonl"
DEFAULT_MASTER = ROOT / "attacks" / "carddiff" / "transfer_native" / "master_cases.json"
DEFAULT_OUTPUT = ROOT / "results" / "transfer_native" / "official_a2a_reference"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(source: Path, master_path: Path, output: Path) -> dict:
    master = json.loads(master_path.read_text(encoding="utf-8"))
    selected_ids = [item["source_case_id"] for item in master["cases"]]
    wanted = set(selected_ids)
    source_records = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_id = {record["case_id"]: record for record in source_records}
    missing = sorted(wanted - set(by_id))
    if missing:
        raise ValueError(f"Official A2A source is missing {len(missing)} selected cases; first={missing[0]}")
    records = [by_id[case_id] for case_id in selected_ids]
    counts = Counter(record["attack_type"] for record in records)
    successes = Counter(record["attack_type"] for record in records if record.get("success"))
    output.mkdir(parents=True, exist_ok=True)
    (output / "details.jsonl").write_text(
        "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    summary = {
        "schema_version": "carddiff-official-a2a-reference-v1",
        "protocol": "official_a2a",
        "model": "gpt-5-mini",
        "trials": len(records),
        "by_attack": {
            attack: {"trials": count, "successes": successes[attack], "asr": successes[attack] / count}
            for attack, count in sorted(counts.items())
        },
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "selected_case_ids.json").write_text(json.dumps(selected_ids, indent=2) + "\n", encoding="utf-8")
    provenance = {
        "source": str(source.relative_to(ROOT)),
        "source_sha256": sha256(source),
        "master_manifest": str(master_path.relative_to(ROOT)),
        "master_manifest_sha256": sha256(master_path),
        "selection": "exact source_case_id match; no model or host execution",
        "source_modified": False,
    }
    (output / "source_provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(extract(args.source, args.master, args.output), indent=2))


if __name__ == "__main__":
    main()
