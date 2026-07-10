"""Optional official A2A SDK integration surface.

The imports are deliberately isolated so the repository's non-transfer baseline
can run without optional framework packages installed.
"""
from __future__ import annotations

try:  # pragma: no cover - exercised in dependency-enabled integration tests.
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.types import AgentCard, Message, Part
    SDK_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover
    A2ACardResolver = ClientConfig = ClientFactory = AgentCard = Message = Part = None
    SDK_AVAILABLE = False
