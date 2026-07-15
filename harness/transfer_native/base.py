from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from harness.transfer_native.contracts import NativeExecution
from harness.transfer_native.evidence import EvidenceRecorder


class NativeProtocolEnvironment(ABC):
    """A fresh protocol runtime. Instances must never be reused across trials."""

    protocol = "unknown"

    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case
        self.evidence = EvidenceRecorder(self.protocol)
        self._entered = False

    def __enter__(self) -> "NativeProtocolEnvironment":
        if self._entered:
            raise RuntimeError("Native trial environments are single-use.")
        self._entered = True
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def execute(self, decision: dict[str, Any]) -> NativeExecution: ...
