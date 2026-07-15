from __future__ import annotations

from typing import Any

from fastapi import Request


def build_openanp_peer(*, name: str, did: str, prefix: str, methods: list[str], authorization: dict[str, list[str]]):
    """Build a deterministic OpenANP router with real generated OpenRPC/JSON-RPC handlers."""
    try:
        from anp.openanp import AgentConfig, anp_agent, interface
    except ModuleNotFoundError as exc:  # pragma: no cover - optional formal dependency
        raise RuntimeError("anp[api]==0.8.8 is required to build the ANP peer.") from exc

    namespace: dict[str, Any] = {}
    for method_name in methods:
        def make_operation(bound_method: str):
            async def operation(self, task: str, identity: str, token_label: str) -> dict[str, Any]:
                allowed = identity in authorization.get(bound_method, [])
                return {
                    "method": bound_method,
                    "task": task,
                    "authorized": allowed,
                    "completed": allowed,
                    "_carddiff_native_events": ["handler_started", "handler_completed"],
                }

            return operation

        operation = make_operation(method_name)
        operation.__name__ = method_name
        operation.__qualname__ = f"CardDiffANPPeer.{method_name}"
        operation.__doc__ = f"Deterministic CardDiff ANP operation for {method_name}."
        namespace[method_name] = interface(operation)
    peer_type = type("CardDiffANPPeer", (), namespace)
    return anp_agent(AgentConfig(name=name, did=did, prefix=prefix, description="CardDiff deterministic ANP peer"))(peer_type)


def build_openanp_application(case: dict[str, Any]):
    """Build a per-trial app whose discovery and RPC routes are all native OpenANP routes."""
    try:
        from fastapi import FastAPI
    except ModuleNotFoundError as exc:  # pragma: no cover - optional formal dependency
        raise RuntimeError("FastAPI from anp[api]==0.8.8 is required for the ANP peer.") from exc

    domain = str(case["domain"])
    native = case["native"]
    method_ids = [
        str(item["id"]) for item in case["canonical_state"].get("capabilities", []) if item.get("id")
    ]
    sensitive = str(native.get("sensitive_method"))
    if sensitive and sensitive not in method_ids:
        method_ids.append(sensitive)
    authorization = {
        method: (["privileged_user"] if method == sensitive else ["normal_user", "privileged_user"])
        for method in method_ids
    }
    interface_count = max(1, len(case["canonical_state"].get("interfaces", [])))
    app = FastAPI(title=f"CardDiff ANP peer: {case['target_case_id']}")
    interface_paths: list[str] = []
    for index in range(1, interface_count + 1):
        prefix = f"/{domain}/candidate-{index}"
        peer = build_openanp_peer(
            name=f"CardDiff {domain} candidate {index}",
            did=f"did:wba:localhost:{domain}:peer-{index}",
            prefix=prefix,
            methods=method_ids,
            authorization=authorization,
        )
        app.include_router(peer.router())
        interface_paths.append(f"{prefix}/interface.json")

    @app.get(f"/{domain}/ad.json")
    async def agent_description(request: Request) -> dict[str, Any]:
        base_url = str(request.base_url).rstrip("/")
        return {
            "name": f"CardDiff deterministic {domain} agent",
            "description": "Protocol-native CardDiff OpenANP peer",
            "interfaces": [
                {
                    "type": "StructuredInterface",
                    "protocol": "openrpc",
                    "url": f"{base_url}{path}",
                }
                for path in interface_paths
            ],
        }
    # ``from __future__ import annotations`` stores the nested annotation as a
    # string; make it concrete so FastAPI does not treat request as a query arg.
    agent_description.__annotations__["request"] = Request

    return app
