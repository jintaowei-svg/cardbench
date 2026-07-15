from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DiscoveredANPAgent:
    sdk_agent: Any
    ad_url: str
    methods: tuple[Any, ...]


def _run(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError("Native ANP runner must be called outside an active asyncio event loop.")


def discover_agent(ad_url: str, auth: Any) -> DiscoveredANPAgent:
    try:
        from anp.openanp import RemoteAgent
    except ModuleNotFoundError as exc:  # pragma: no cover - optional formal dependency
        raise RuntimeError("ANP SDK 0.8.8 is required; discovery cannot fall back to requests.") from exc
    agent = _run(RemoteAgent.discover(ad_url, auth))
    return DiscoveredANPAgent(agent, ad_url, tuple(agent.methods))


def invoke(agent: DiscoveredANPAgent, method: str, **params: Any) -> Any:
    return _run(agent.sdk_agent.call(method, **params))
