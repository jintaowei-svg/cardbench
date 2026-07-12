from __future__ import annotations

"""Generic NeMo input gateway and CardDiff security-context projection."""

import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import time
from typing import Any, Awaitable, Callable


@dataclass(frozen=True)
class GuardrailResult:
    allow: bool | None
    raw_output: str
    latency_ms: float
    retry_count: int = 0
    error: str | None = None


CheckCallable = Callable[[str], str | bool | Any | Awaitable[str | bool | Any]]


def _json(value: Any) -> str:
    if value is None:
        return "N/A"
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_security_context(metadata: dict[str, Any]) -> str:
    """Project only Host-visible state; the private oracle is never included."""
    public = metadata.get("public", {})
    agent = metadata.get("agent", {})
    public_card = agent.get("public_card")
    all_extended_cards = agent.get("extended_cards", {})
    tokens = agent.get("tokens", {})

    principals: list[dict[str, Any]] = []
    for step in public.get("auth_sequence", []):
        token_label = str(step.get("token_label", ""))
        profile = tokens.get(token_label, {})
        principals.append({
            "identity": profile.get("identity", step.get("identity")),
            "scopes": profile.get("scopes", []),
        })

    visible_identities = {str(item["identity"]) for item in principals}
    extended_cards = {
        identity: card for identity, card in all_extended_cards.items()
        if identity in visible_identities
    }

    candidate_interfaces: dict[str, Any] = {
        "public": (public_card or {}).get("supportedInterfaces", []),
        "extended": {
            identity: card.get("supportedInterfaces", [])
            for identity, card in extended_cards.items()
        },
    }
    sections = [
        ("USER TASK", public.get("task")),
        ("PUBLIC AGENT CARD", public_card),
        ("AUTHENTICATED OR EXTENDED AGENT CARD", extended_cards),
        ("CURRENT IDENTITY", [item["identity"] for item in principals]),
        ("TOKEN SCOPES", [item["scopes"] for item in principals]),
        ("CANDIDATE INTERFACES", candidate_interfaces),
        # Card binding/version fields are already present in the supplied cards.
        # There is no separate trusted configuration in the frozen case schema.
        ("TRUSTED OR REFERENCE CONFIGURATION", None),
        ("ACCEPTED OUTPUT MODES", public.get("accepted_output_modes")),
    ]
    return "\n\n".join(f"[{name}]\n{_json(value)}" for name, value in sections)


def _parse_verdict(value: Any) -> tuple[bool | None, str]:
    if isinstance(value, bool):
        return value, "No" if value else "Yes"

    status = getattr(value, "status", None)
    if status is not None:
        status_text = str(getattr(status, "value", status)).strip().lower()
        if status_text.endswith("blocked"):
            return False, "Yes"
        if status_text.endswith("passed") or status_text.endswith("modified"):
            return True, "No"

    if isinstance(value, dict):
        value = value.get("content", value.get("response", value.get("status", "")))
    raw = str(value).strip()
    normalized = raw.strip().strip('"\'').strip().lower().rstrip(".! ")
    if normalized == "no":
        return True, raw
    if normalized == "yes":
        return False, raw
    return None, raw


class NemoGateway:
    """Run the configured NeMo input rail with one parse retry by default."""

    def __init__(
        self,
        config_path: str | Path,
        *,
        max_retries: int = 1,
        timeout_s: float = 60.0,
        checker: CheckCallable | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.max_retries = int(max_retries)
        self.timeout_s = float(timeout_s)
        self._checker = checker
        self._rails: Any | None = None

    def _load_rails(self) -> Any:
        if self._rails is None:
            try:
                from nemoguardrails import LLMRails, RailsConfig
            except ModuleNotFoundError as exc:
                raise RuntimeError(
                    'NeMo Guardrails is not installed. Run: pip install -e ".[defense-nemo]"'
                ) from exc
            config = RailsConfig.from_path(str(self.config_path))
            self._rails = LLMRails(config)
        return self._rails

    async def _check_once(self, security_context: str) -> Any:
        if self._checker is not None:
            result = self._checker(security_context)
            return await result if hasattr(result, "__await__") else result
        rails = self._load_rails()
        messages = [{"role": "user", "content": security_context}]
        if hasattr(rails, "check_async"):
            return await rails.check_async(messages)
        # Compatibility fallback for NeMo installations without check_async.
        return await rails.generate_async(messages=messages)

    async def check_with_nemo(self, security_context: str) -> GuardrailResult:
        started = time.perf_counter()
        last_raw = ""
        try:
            for attempt in range(self.max_retries + 1):
                value = await asyncio.wait_for(
                    self._check_once(security_context), timeout=self.timeout_s
                )
                allow, last_raw = _parse_verdict(value)
                if allow is not None:
                    return GuardrailResult(
                        allow=allow,
                        raw_output=last_raw,
                        latency_ms=(time.perf_counter() - started) * 1000,
                        retry_count=attempt,
                    )
            return GuardrailResult(
                allow=None,
                raw_output=last_raw,
                latency_ms=(time.perf_counter() - started) * 1000,
                retry_count=self.max_retries,
                error="NeMo returned an unparseable verdict after the allowed retry.",
            )
        except Exception as exc:
            return GuardrailResult(
                allow=None,
                raw_output=last_raw,
                latency_ms=(time.perf_counter() - started) * 1000,
                retry_count=0,
                error=f"{type(exc).__name__}: {exc}",
            )
