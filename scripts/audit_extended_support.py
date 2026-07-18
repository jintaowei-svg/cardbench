from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import inspect
import json
import socket
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _git_head(path: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=path, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit_agntcy(address: str) -> dict[str, Any]:
    from agntcy.dir_sdk.client import Client, Config
    from agntcy.dir_sdk.models import core_v1, routing_v1, search_v1

    binary = (
        ROOT
        / ".codex_work"
        / "agntcy-dir-v1.5.0"
        / "dirctl-windows-amd64.exe"
    )
    host, port = address.rsplit(":", 1)
    connected = False
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            connected = True
    except OSError:
        pass
    version = importlib.metadata.version("agntcy-dir")
    api_checks = {
        "client_push": callable(getattr(Client, "push", None)),
        "client_publish": callable(getattr(Client, "publish", None)),
        "client_search_cids": callable(getattr(Client, "search_cids", None)),
        "client_pull": callable(getattr(Client, "pull", None)),
        "record_type": inspect.isclass(core_v1.Record),
        "publish_type": inspect.isclass(routing_v1.PublishRequest),
        "search_type": inspect.isclass(search_v1.SearchCIDsRequest),
        "config_constructed": isinstance(Config(server_address=address), Config),
    }
    expected_hash = "037279351f06738024df88d02a3b8337fcad1b8e1818e1d7adc0d7ee6eadd5f9"
    observed_hash = _sha256(binary)
    passed = (
        version == "1.5.0"
        and connected
        and all(api_checks.values())
        and observed_hash == expected_hash
    )
    return {
        "target": "agntcy",
        "status": "passed" if passed else "failed",
        "model_called": False,
        "runtime": {
            "sdk_version": version,
            "sdk_commit": _git_head(ROOT / ".codex_work" / "agntcy-dir-sdk-python"),
            "directory_commit": _git_head(ROOT / ".codex_work" / "agntcy-dir-v1.5.0"),
            "directory_address": address,
            "directory_reachable": connected,
            "binary_sha256": observed_hash,
        },
        "api_checks": api_checks,
        "applicability": {"A2": "applicable", "B2": "applicable", "C1": "not_applicable"},
    }


def audit_autogen() -> dict[str, Any]:
    from autogen_agentchat.agents import BaseChatAgent
    from autogen_agentchat.messages import MultiModalMessage, TextMessage
    from autogen_agentchat.teams import SelectorGroupChat

    versions = {
        name: importlib.metadata.version(name)
        for name in ("autogen-agentchat", "autogen-core")
    }
    api_checks = {
        "base_agent_state_save": callable(getattr(BaseChatAgent, "save_state", None)),
        "base_agent_state_load": callable(getattr(BaseChatAgent, "load_state", None)),
        "selector_group_chat": inspect.isclass(SelectorGroupChat),
        "text_message": inspect.isclass(TextMessage),
        "multimodal_message": inspect.isclass(MultiModalMessage),
        "candidate_func_parameter": "candidate_func"
        in inspect.signature(SelectorGroupChat).parameters,
        "selector_func_parameter": "selector_func"
        in inspect.signature(SelectorGroupChat).parameters,
    }
    passed = set(versions.values()) == {"0.7.5"} and all(api_checks.values())
    return {
        "target": "autogen",
        "target_kind": "framework",
        "status": "passed" if passed else "failed",
        "model_called": False,
        "runtime": versions,
        "api_checks": api_checks,
        "applicability": {
            "A3": "applicable",
            "B1": "not_applicable",
            "C1": "applicable",
            "C2": "applicable",
        },
    }


def audit_langgraph() -> dict[str, Any]:
    from langchain_core.messages import AIMessage
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import StateGraph

    versions = {
        name: importlib.metadata.version(name)
        for name in ("langgraph", "langchain-core")
    }
    api_checks = {
        "state_graph": inspect.isclass(StateGraph),
        "conditional_edges": callable(getattr(StateGraph, "add_conditional_edges", None)),
        "in_memory_saver": inspect.isclass(InMemorySaver),
        "multimodal_ai_message": inspect.isclass(AIMessage),
    }
    expected = {"langgraph": "1.2.9", "langchain-core": "1.4.9"}
    passed = versions == expected and all(api_checks.values())
    return {
        "target": "langgraph",
        "target_kind": "framework",
        "status": "passed" if passed else "failed",
        "model_called": False,
        "runtime": versions,
        "api_checks": api_checks,
        "applicability": {
            "A3": "applicable",
            "B1": "applicable",
            "C1": "applicable",
            "C2": "applicable",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target", required=True, choices=("agntcy", "autogen", "langgraph")
    )
    parser.add_argument("--directory-address", default="127.0.0.1:8888")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.target == "agntcy":
        result = audit_agntcy(args.directory_address)
    elif args.target == "autogen":
        result = audit_autogen()
    else:
        result = audit_langgraph()
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
