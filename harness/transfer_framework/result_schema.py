from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FrameworkTrialResult:
    schema_version: str
    target_kind: str
    framework: str
    master_case_id: str
    source_case_id: str
    target_case_id: str
    attack_type: str
    domain: str
    variant: str
    trial_index: int
    success: bool
    oracle_components: dict[str, Any]
    native_execution_valid: bool | None
    missing_native_events: list[str]
    events: list[dict[str, Any]]
    decision: dict[str, Any] | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
