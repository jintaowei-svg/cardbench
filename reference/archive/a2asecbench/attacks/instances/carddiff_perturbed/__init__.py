from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attacks.carddiff_attack import CardDiffCase


CASES_PATH = Path(__file__).resolve().parents[2] / "carddiff" / "perturbed_cases.jsonl"


def _load_cases() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in CASES_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


CASE_METADATA = _load_cases()


def _make_case_class(metadata: dict[str, Any], class_name: str):
    class GeneratedCardDiffPerturbedCase(CardDiffCase):
        def __init__(self) -> None:
            super().__init__(metadata)

    GeneratedCardDiffPerturbedCase.__name__ = class_name
    GeneratedCardDiffPerturbedCase.__qualname__ = class_name
    return GeneratedCardDiffPerturbedCase


__all__ = ["CASE_METADATA"]
for _index, _metadata in enumerate(CASE_METADATA, start=1):
    _class_name = f"CardDiffPerturbed{_index:03d}"
    globals()[_class_name] = _make_case_class(_metadata, _class_name)
    __all__.append(_class_name)

