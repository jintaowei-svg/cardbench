from __future__ import annotations

from typing import Any


def method_view(methods: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [
        {
            "id": method.name,
            "name": method.name,
            "description": method.description,
            "required_scopes": [],
            "output_modes": [],
        }
        for method in methods
    ]


def interface_view(methods: tuple[Any, ...]) -> list[dict[str, Any]]:
    seen: list[str] = []
    for method in methods:
        if method.rpc_url not in seen:
            seen.append(method.rpc_url)
    return [
        {
            "index": index,
            "url": url,
            "tenant": None,
            "protocol_binding": "openrpc-jsonrpc",
            "protocol_version": "1.3.2",
        }
        for index, url in enumerate(seen, start=1)
    ]
