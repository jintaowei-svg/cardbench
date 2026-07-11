from __future__ import annotations

import requests

from utils import llm_client


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {
            "choices": [{"message": {"content": "{\"should_send\": false}"}}],
            "id": "fake",
            "usage": {},
        }
        self.headers = {"Content-Type": "application/json"}
        self.ok = 200 <= status_code < 300
        self.text = "{}"

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError("boom")

    def json(self) -> dict:
        return self._payload


class FakeSession:
    def __init__(self) -> None:
        self.trust_env = True
        self.calls = 0

    def post(self, *args, **kwargs) -> FakeResponse:
        self.calls += 1
        if self.calls == 1:
            raise requests.ReadTimeout("Read timed out")
        return FakeResponse(200)


def test_chat_retries_transient_request_error(monkeypatch) -> None:
    fake_session = FakeSession()
    monkeypatch.setenv("SUT_API_BASE", "https://example.test/v1")
    monkeypatch.setenv("SUT_API_KEY", "test-key")
    monkeypatch.setenv("SUT_MODEL", "test-model")
    monkeypatch.setenv("SUT_RETRY_BACKOFF_S", "0")
    monkeypatch.setattr(llm_client.requests, "Session", lambda: fake_session)

    assert llm_client.chat("system", "user") == "{\"should_send\": false}"
    assert fake_session.calls == 2
