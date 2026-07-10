from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class TransferDecision:
    should_send: bool
    capability_id: str | None
    interface_index: int | None
    accept_output: bool
    final_status: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)
