from __future__ import annotations

import importlib.util


def native_codec_support() -> dict[str, bool]:
    """Capabilities of the maintained 0.1.2 Python SDK/client, not the ECMA spec."""
    return {
        "json_text": importlib.util.find_spec("nlip_sdk") is not None,
        "websocket_text": False,
        "websocket_binary": False,
        "cbor": False,
    }


def b2_gate_passes() -> bool:
    support = native_codec_support()
    return all(support[key] for key in ("websocket_text", "websocket_binary", "cbor"))
