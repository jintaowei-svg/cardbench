from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImpactEventRecorder:
    case_id: str
    events: list[dict[str, Any]] = field(default_factory=list)

    def record(self, event_type: str, actor_id: str, **evidence: Any) -> None:
        self.events.append({"event_type": event_type, "actor_id": actor_id,
                            "case_id": self.case_id, "evidence": evidence})
