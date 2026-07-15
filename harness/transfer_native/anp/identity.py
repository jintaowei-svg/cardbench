from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ANPIdentity:
    label: str
    did: str
    did_document_path: Path
    private_key_path: Path

    def build_auth(self):
        try:
            from anp.authentication import DIDWbaAuthHeader
        except ModuleNotFoundError as exc:  # pragma: no cover - optional formal dependency
            raise RuntimeError("ANP SDK 0.8.8 is required; no HTTP fallback is permitted.") from exc
        return DIDWbaAuthHeader(
            did_document_path=str(self.did_document_path),
            private_key_path=str(self.private_key_path),
        )


class ANPIdentityResolver:
    """Resolve benchmark labels to real DID-WBA key material supplied at runtime."""

    def resolve(self, label: str, did: str) -> ANPIdentity:
        prefix = f"CARDDIFF_ANP_{label.upper()}"
        document = os.getenv(f"{prefix}_DID_DOCUMENT")
        private_key = os.getenv(f"{prefix}_PRIVATE_KEY")
        if not document or not private_key:
            raise RuntimeError(
                f"Missing {prefix}_DID_DOCUMENT/{prefix}_PRIVATE_KEY for native ANP identity."
            )
        identity = ANPIdentity(label, did, Path(document), Path(private_key))
        for path in (identity.did_document_path, identity.private_key_path):
            if not path.is_file():
                raise FileNotFoundError(path)
        return identity
