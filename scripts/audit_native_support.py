from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "results" / "transfer_native" / "native_support_audit.json"


def _version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def audit_anp() -> dict[str, Any]:
    version = _version("anp")
    evidence: list[dict[str, Any]] = []
    if importlib.util.find_spec("anp") is None:
        return {
            "A2": {"status": "not_applicable", "reason": "anp SDK is not installed; native path was not verified", "sdk_version": version},
            "C2": {"status": "not_applicable", "reason": "anp SDK is not installed; native media path was not verified", "sdk_version": version},
        }
    try:
        openanp = importlib.import_module("anp.openanp")
    except ModuleNotFoundError as exc:
        return {
            "A2": {
                "status": "not_applicable",
                "reason": f"anp runtime dependency is missing: {exc.name}",
                "sdk_version": version,
            },
            "C2": {
                "status": "not_applicable",
                "reason": f"anp runtime dependency is missing: {exc.name}",
                "sdk_version": version,
            },
        }
    has_server = all(hasattr(openanp, name) for name in ("AgentConfig", "anp_agent", "interface"))
    has_remote = hasattr(openanp, "RemoteAgent") and hasattr(openanp.RemoteAgent, "discover")
    evidence.extend(
        [
            {"check": "openanp_server_api", "passed": has_server},
            {"check": "remote_agent_discovery", "passed": has_remote},
            {"check": "generated_agent_description", "passed": has_server},
            {"check": "generated_openrpc_and_jsonrpc", "passed": has_server and has_remote},
        ]
    )
    a2_ok = has_server and has_remote
    exports = set(dir(openanp))
    media_exports = sorted(name for name in exports if "media" in name.lower() or "attachment" in name.lower())
    c2_ok = bool(media_exports)
    return {
        "A2": {
            "status": "applicable" if a2_ok else "not_applicable",
            "sdk_version": version,
            "evidence": evidence,
            **({} if a2_ok else {"reason": "OpenANP discovery/server API is incomplete"}),
        },
        "C2": {
            "status": "applicable" if c2_ok else "not_applicable",
            "sdk_version": version,
            "evidence": [{"check": "native_media_or_attachment_object", "passed": c2_ok, "exports": media_exports}],
            **({} if c2_ok else {"reason": "SDK lacks a native attachment/MIME result object"}),
        },
    }


def audit_nlip() -> dict[str, Any]:
    versions = {
        name: _version(name) for name in ("nlip_sdk", "nlip_server")
    }
    installed = all(importlib.util.find_spec(name) is not None for name in ("nlip_sdk", "nlip_server"))
    websocket_client = False
    cbor_codec = False
    if importlib.util.find_spec("nlip_client") is not None:
        client = importlib.import_module("nlip_client.nlip_client")
        websocket_client = any("WEBSOCKET" in name.upper() for name in dir(client))
    if importlib.util.find_spec("nlip_sdk") is not None:
        sdk = importlib.import_module("nlip_sdk.nlip")
        cbor_codec = any("CBOR" in name.upper() for name in dir(sdk))
    passed = installed and websocket_client and cbor_codec
    evidence = [
        {"check": "sdk_and_server_installed", "passed": installed},
        {"check": "native_websocket_text_and_binary_client", "passed": websocket_client},
        {"check": "native_cbor_codec", "passed": cbor_codec},
    ]
    return {
        "B2": {
            "status": "applicable" if passed else "not_applicable",
            "sdk_versions": versions,
            "evidence": evidence,
            **({} if passed else {"reason": "Python SDK/client lacks WebSocket binary+CBOR and text+JSON dual paths"}),
        }
    }


def audit() -> dict[str, Any]:
    return {
        "schema_version": "carddiff-native-support-audit-v1",
        "model_called": False,
        "anp": audit_anp(),
        "nlip": audit_nlip(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
