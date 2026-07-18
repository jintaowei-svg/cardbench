from __future__ import annotations

from harness.transfer.base import TransferEnvironmentBase


class LangGraphCardDiffEnvironment(TransferEnvironmentBase):
    """Fresh in-process runtime context for every compiled graph invocation."""

    transfer_target = "langgraph"
    transport = "in_process"
