from __future__ import annotations

import pytest

from harness.transfer_native.base import NativeProtocolEnvironment
from harness.transfer_native.contracts import NativeExecution


class Environment(NativeProtocolEnvironment):
    protocol = "test"

    def start(self) -> None: pass
    def stop(self) -> None: pass
    def execute(self, decision): return NativeExecution("test", "A3")


def test_environment_is_single_use() -> None:
    environment = Environment({})
    with environment:
        pass
    with pytest.raises(RuntimeError, match="single-use"):
        environment.__enter__()
