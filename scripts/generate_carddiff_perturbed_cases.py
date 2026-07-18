from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attacks.carddiff.adapter import write_perturbed_cases


def _parse_variant_ids(text: str | None) -> set[str] | None:
    if not text:
        return None
    return {
        item.strip().zfill(3) if item.strip().isdigit() else item.strip()
        for item in text.split(",")
        if item.strip()
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate CardDiff perturbed cases.")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--variant-ids",
        default=None,
        help="Comma-separated perturbation variant IDs to include, for example 001,002,003.",
    )
    args = parser.parse_args()

    variant_ids = _parse_variant_ids(args.variant_ids) or {"001", "002", "003"}
    path = write_perturbed_cases(args.output, variant_ids=variant_ids)
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
