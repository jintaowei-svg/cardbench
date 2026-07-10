from __future__ import annotations

from harness.transfer.base import TransferEnvironmentBase


class OfficialSDKCardDiffEnvironment(TransferEnvironmentBase):
    """In-process peer environment for the official SDK-backed target."""

    transfer_target = "official_a2a"
    transport = "asgi"
