from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attacks.carddiff.adapter import write_cases


def main() -> None:
    path = write_cases()
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
