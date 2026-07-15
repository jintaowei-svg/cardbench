from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Protocol


class ApplicabilityStatus(str, Enum):
    MAIN_ONLY = "main_only"
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    PENDING_NATIVE_GATE = "pending_native_gate"


@dataclass(frozen=True)
class NativeEvent:
    event_type: str
    protocol: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NativeExecution:
    protocol: str
    attack_type: str
    events: list[NativeEvent] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] | None = None


class NativeAdapter(Protocol):
    protocol: str

    def execute(self, case: dict[str, Any], decision: dict[str, Any]) -> NativeExecution:
        """Execute one trial through the protocol's native client/server path."""
