from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import time

import requests


@dataclass(frozen=True)
class OpenAICompatibleClient:
    api_base: str
    api_key: str
    timeout_s: float
    trust_env: bool
    request_retries: int
    retry_backoff_s: float


def get_openai_compatible_client() -> OpenAICompatibleClient:
    api_base = os.getenv("SUT_API_BASE", "").strip()
    api_key = os.getenv("SUT_API_KEY", "").strip()
    timeout_s_raw = os.getenv("SUT_TIMEOUT_S", "60").strip()
    trust_env_raw = os.getenv("SUT_TRUST_ENV", "true").strip().lower()
    request_retries_raw = os.getenv("SUT_REQUEST_RETRIES", "2").strip()
    retry_backoff_raw = os.getenv("SUT_RETRY_BACKOFF_S", "0.5").strip()

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
    try:
        request_retries = int(request_retries_raw)
    except ValueError as exc:
        raise RuntimeError(f"SUT_REQUEST_RETRIES must be an integer, got '{request_retries_raw}'.") from exc
    try:
        retry_backoff_s = float(retry_backoff_raw)
    except ValueError as exc:
        raise RuntimeError(f"SUT_RETRY_BACKOFF_S must be numeric, got '{retry_backoff_raw}'.") from exc
    if request_retries < 0:
        raise RuntimeError("SUT_REQUEST_RETRIES must be non-negative.")
    if retry_backoff_s < 0:
        raise RuntimeError("SUT_RETRY_BACKOFF_S must be non-negative.")

    trust_env = trust_env_raw not in {"0", "false", "no", "off"}
    return OpenAICompatibleClient(
        api_base=api_base.rstrip("/"),
        api_key=api_key,
        timeout_s=timeout_s,
        trust_env=trust_env,
        request_retries=request_retries,
        retry_backoff_s=retry_backoff_s,
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
        "response_format": {"type": "json_object"},
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
    response = _post_with_retries(
        session,
        _completion_url(client.api_base),
        headers=headers,
        payload=payload,
        timeout_s=client.timeout_s,
        request_retries=client.request_retries,
        retry_backoff_s=client.retry_backoff_s,
    )
    # Some OpenAI-compatible gateways advertise a bare origin as ``base_url``
    # but expose the API below /v1.  A non-JSON landing page is unambiguously
    # not a completion response, so retry that conventional path once.
    if (
        response.ok
        and "json" not in response.headers.get("Content-Type", "").lower()
        and not client.api_base.rstrip("/").endswith("/v1")
    ):
        response = _post_with_retries(
            session,
            _completion_url(client.api_base + "/v1"),
            headers=headers,
            payload=payload,
            timeout_s=client.timeout_s,
            request_retries=client.request_retries,
            retry_backoff_s=client.retry_backoff_s,
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


def _completion_url(api_base: str) -> str:
    return f"{api_base.rstrip('/')}/chat/completions"


def _post_with_retries(
    session: requests.Session,
    url: str,
    *,
    headers: dict[str, str],
    payload: dict[str, object],
    timeout_s: float,
    request_retries: int,
    retry_backoff_s: float,
) -> requests.Response:
    transient_statuses = {408, 409, 425, 429}
    for attempt in range(request_retries + 1):
        try:
            response = session.post(url, headers=headers, json=payload, timeout=timeout_s)
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt >= request_retries:
                raise RuntimeError(
                    f"LLM request failed after {attempt + 1} attempts: {exc}"
                ) from exc
            _sleep_before_retry(attempt, retry_backoff_s)
            continue
        if (
            attempt < request_retries
            and (response.status_code in transient_statuses or response.status_code >= 500)
        ):
            _sleep_before_retry(attempt, retry_backoff_s)
            continue
        return response
    raise RuntimeError("LLM request retry loop exhausted unexpectedly.")


def _sleep_before_retry(attempt: int, retry_backoff_s: float) -> None:
    if retry_backoff_s:
        time.sleep(retry_backoff_s * (2 ** attempt))


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
