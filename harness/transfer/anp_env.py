from __future__ import annotations

from harness.transfer.base import TransferEnvironmentBase


class ANPCardDiffEnvironment(TransferEnvironmentBase):
    """Local DID-scoped peer environment for the ANP transfer target."""

    transfer_target = "anp"
    transport = "asgi_or_localhost"
