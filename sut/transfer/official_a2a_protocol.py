"""Strict official a2a-sdk 0.3.x protocol adapter."""
from __future__ import annotations

import asyncio
import threading
from importlib.metadata import version
from typing import Any
from uuid import uuid4

try:
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.server.agent_execution import AgentExecutor, RequestContext
    from a2a.server.apps import A2AStarletteApplication
    from a2a.server.events import EventQueue
    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.types import (AgentCapabilities, AgentCard, AgentSkill, DataPart,
                           Message, Part, Role, TextPart)
except ImportError as exc:  # pragma: no cover - dependency guard
    raise ImportError("Official A2A transfer requires a2a-sdk 0.3.x.") from exc

SDK_VERSION = version("a2a-sdk")


def run_async(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    result: dict[str, Any] = {}
    def runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:
            result["error"] = exc
    thread = threading.Thread(target=runner, daemon=True)
    thread.start(); thread.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


def build_message(task: str, metadata: dict[str, Any]) -> Message:
    return Message(role=Role.user, message_id=str(uuid4()),
                   parts=[Part(root=TextPart(text=task))], metadata=metadata)


def normalize_sdk_result(result: Any) -> dict[str, Any]:
    if isinstance(result, tuple):
        result = result[0]
    if result is None:
        raise RuntimeError("Official A2A SDK returned no message or task.")
    parts = getattr(result, "parts", None) or []
    for part in parts:
        root = getattr(part, "root", part)
        if isinstance(root, DataPart) and isinstance(root.data, dict):
            return {"_status_code": 200, **root.data}
        if isinstance(root, TextPart):
            return {"_status_code": 200, "kind": "message", "text": root.text}
    raw = result.model_dump(mode="json", by_alias=True)
    if isinstance(raw, dict):
        return {"_status_code": 200, **raw}
    raise TypeError("Unsupported official A2A SDK response.")
