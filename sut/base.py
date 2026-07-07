from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class A2AProbeResult:
    response_text: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    error_message: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


class CardDiffHostSUTBase(ABC):
    @abstractmethod
    def run_probe(self, case: dict[str, Any], env: Any | None = None) -> A2AProbeResult:
        raise NotImplementedError


A2ASecuritySUT = CardDiffHostSUTBase
