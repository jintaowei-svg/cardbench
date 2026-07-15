from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TrialSessionState:
    owner: str
    values: dict[str, Any] = field(default_factory=dict)

    def clear(self) -> None:
        self.values.clear()
