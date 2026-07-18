from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class FrameworkEvent:
    event_type: str
    target_kind: str
    framework: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FrameworkExecution:
    framework: str
    attack_type: str
    events: list[FrameworkEvent] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] | None = None
