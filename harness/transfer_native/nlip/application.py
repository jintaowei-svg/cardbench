from __future__ import annotations

from typing import Any


def build_nlip_application(
    authorization: dict[str, list[str]],
    output: dict[str, str],
    token_identities: dict[str, str] | None = None,
):
    """Create SDK NLIP_Application/NLIP_Session subclasses for the deterministic peer."""
    try:
        from nlip_sdk.nlip import NLIP_Factory
        from nlip_server.server import NLIP_Application, NLIP_Session
    except ModuleNotFoundError as exc:  # pragma: no cover - optional formal dependency
        raise RuntimeError("nlip_sdk/nlip_server 0.1.2 are required for the NLIP peer.") from exc

    class CardDiffSession(NLIP_Session):
        async def execute(self, msg):
            payloads = msg.extract_field_list("structured", "JSON")
            payload = payloads[0] if payloads else {}
            authentication_token = msg.extract_authentication_token()
            identity = str((token_identities or {}).get(str(authentication_token), ""))
            operation = str(payload.get("operation", ""))
            authorized = identity in authorization.get(operation, [])
            fmt = output.get("format", "structured")
            subformat = output.get("subformat", "JSON")
            if fmt == "text":
                response = NLIP_Factory.create_text("completed", subformat)
            elif fmt == "binary":
                binary_type, _, encoding = subformat.partition("/")
                response = NLIP_Factory.create_binary("Y2FyZGRpZmY=", binary_type or "application", encoding or "base64")
            else:
                response = NLIP_Factory.create_structured("completed", subformat)
            response.add_json(
                {
                    "decoded": True,
                    "handler_started": True,
                    "handler_completed": True,
                    "response_serialized": True,
                    "authorized": authorized,
                    "operation_completed": authorized,
                    "authenticated_identity": identity,
                    "authentication_token_present": authentication_token is not None,
                },
                label="carddiff-native-evidence",
            )
            return response

    class CardDiffApplication(NLIP_Application):
        async def startup(self):
            self.session_list = []

        async def shutdown(self):
            self.session_list = []

        def create_session(self):
            session = CardDiffSession()
            session.set_correlator()
            return session

    return CardDiffApplication()
