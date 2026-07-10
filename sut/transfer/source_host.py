from __future__ import annotations

from sut.transfer.base import TransferHostBase


class MinimalReferenceTransferHostSUT(TransferHostBase):
    """Matched source run using the same strict parsing policy as transfer targets."""

    transfer_target = "source"
    framework_version = "minimal-reference"
