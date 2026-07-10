from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

import requests


@dataclass(frozen=True)
class OpenAICompatibleClient:
    api_base: str
    api_key: str
    timeout_s: float
    trust_env: bool


def get_openai_compatible_client() -> OpenAICompatibleClient:
    api_base = os.getenv("SUT_API_BASE", "").strip()
    api_key = os.getenv("SUT_API_KEY", "").strip()
    timeout_s_raw = os.getenv("SUT_TIMEOUT_S", "60").strip()
    trust_env_raw = os.getenv("SUT_TRUST_ENV", "true").strip().lower()

    missing = []
    if not api_base:
        missing.append("SUT_API_BASE")
    if not api_key:
        missing.append("SUT_API_KEY")
    if missing:
        raise RuntimeError(
            "LLM SUT requires environment variables that are not set: "
            f"{', '.join(missing)}. Set them before running LLM-based selectors/comparators."
        )

    try:
        timeout_s = float(timeout_s_raw)
    except ValueError as exc:
        raise RuntimeError(f"SUT_TIMEOUT_S must be numeric, got '{timeout_s_raw}'.") from exc

    trust_env = trust_env_raw not in {"0", "false", "no", "off"}
    return OpenAICompatibleClient(
        api_base=api_base.rstrip("/"),
        api_key=api_key,
        timeout_s=timeout_s,
        trust_env=trust_env,
    )


def chat(system: str, user: str, model: str | None = None, temperature: float | None = None) -> str:
    client = get_openai_compatible_client()
    resolved_model = model or os.getenv("SUT_MODEL", "").strip()
    if not resolved_model:
        raise RuntimeError(
            "LLM SUT requires a model. Pass model=... or set SUT_MODEL in the environment."
        )

    if temperature is None:
        temperature_raw = os.getenv("SUT_TEMPERATURE", "0").strip()
        try:
            resolved_temperature = float(temperature_raw)
        except ValueError as exc:
            raise RuntimeError(f"SUT_TEMPERATURE must be numeric, got '{temperature_raw}'.") from exc
    else:
        resolved_temperature = float(temperature)

    payload = {
        "model": resolved_model,
        "temperature": resolved_temperature,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    max_tokens_raw = os.getenv("SUT_MAX_TOKENS", "").strip()
    if max_tokens_raw:
        try:
            payload["max_tokens"] = int(max_tokens_raw)
        except ValueError as exc:
            raise RuntimeError(f"SUT_MAX_TOKENS must be an integer, got '{max_tokens_raw}'.") from exc
    headers = {
        "Authorization": f"Bearer {client.api_key}",
        "Content-Type": "application/json",
    }

    session = requests.Session()
    session.trust_env = client.trust_env
    response = session.post(
        f"{client.api_base}/chat/completions",
        headers=headers,
        json=payload,
        timeout=client.timeout_s,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise RuntimeError(
            f"LLM request failed with status {response.status_code}: {response.text[:500]}"
        ) from exc

    data = response.json()
    _write_usage_log(
        model=resolved_model,
        usage=data.get("usage"),
        response_id=data.get("id"),
    )
    try:
        return data["choices"][0]["message"]["content"]
    except Exception as exc:
        raise RuntimeError(f"Unexpected OpenAI-compatible response format: {data}") from exc


def _write_usage_log(*, model: str, usage: object, response_id: object) -> None:
    usage_log = os.getenv("SUT_USAGE_LOG", "").strip()
    if not usage_log:
        return
    path = Path(usage_log)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "response_id": response_id,
        "usage": usage,
    }
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(record, sort_keys=True) + "\n")
