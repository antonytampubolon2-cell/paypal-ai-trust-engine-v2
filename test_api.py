"""API contract/security tests. All OpenAI behavior is mocked; no provider calls occur."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

import app as api
from ai_service import AIConfigurationError, AIProviderError, AIProviderTimeout, AIResult


@pytest.fixture(autouse=True)
def auth_token(monkeypatch):
    monkeypatch.setenv("TRUSTGUARD_API_BEARER_TOKEN", "test-token-that-is-long-enough-for-local-tests-123")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    api.rate_limiter._events.clear()


@pytest.fixture
def client():
    # Assert the HTTP response produced by the app's generic 500 handler.
    # Starlette's default TestClient setting re-raises server exceptions after
    # the response is sent, which would bypass this response-level assertion.
    return TestClient(api.app, raise_server_exceptions=False)


def auth_headers():
    return {"Authorization": "Bearer test-token-that-is-long-enough-for-local-tests-123"}


def test_asgi_application_starts_and_healthz_is_minimal(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_does_not_expose_secrets(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret-value-never-return-this")
    response = client.get("/readyz")
    assert response.status_code == 200
    assert "sk-test-secret-value-never-return-this" not in response.text
    assert "test-token-that-is-long-enough-for-local-tests-123" not in response.text
    assert response.json()["checks"]["openai_credentials"] == "configured"


def test_missing_authentication_is_rejected(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    response = client.post("/v1/ai/respond", json={"prompt": "hello"})
    assert response.status_code == 401


@pytest.mark.parametrize("body", [
    {},
    {"prompt": ""},
    {"prompt": "x" * 4001},
    {"prompt": "hello", "unexpected": "field"},
    ["not", "an", "object"],
])
def test_invalid_request_bodies_are_rejected(client, body):
    response = client.post("/v1/ai/respond", json=body, headers=auth_headers())
    assert response.status_code == 422


def test_oversized_body_is_rejected(client):
    response = client.post(
        "/v1/ai/respond",
        content=b'{"prompt":"' + b"x" * (api.MAX_REQUEST_BYTES + 10) + b'"}',
        headers={**auth_headers(), "Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_missing_openai_credentials_fail_safely(client, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    response = client.post("/v1/ai/respond", json={"prompt": "hello"}, headers=auth_headers())
    assert response.status_code == 503
    assert "OPENAI_API_KEY" not in response.text
    assert "Traceback" not in response.text


def test_successful_ai_call_is_mocked_and_filtered(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret-value-never-return-this")

    async def fake_generate(prompt):
        assert prompt == "hello"
        return AIResult("hello sk-abcdefghijklmnop1234567890", "test-model")

    monkeypatch.setattr(api, "generate_ai_response", fake_generate)
    response = client.post("/v1/ai/respond", json={"prompt": "hello"}, headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["response"] == "hello [REDACTED]"
    assert "sk-abcdefghijklmnop1234567890" not in response.text


@pytest.mark.parametrize(
    ("error", "status"),
    [(AIProviderTimeout(), 504), (AIProviderError(), 502)],
)
def test_provider_errors_are_safe(client, monkeypatch, error, status):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    async def fake_generate(_prompt):
        raise error

    monkeypatch.setattr(api, "generate_ai_response", fake_generate)
    response = client.post("/v1/ai/respond", json={"prompt": "hello"}, headers=auth_headers())
    assert response.status_code == status
    assert "Traceback" not in response.text
    assert "test-openai-key" not in response.text
    assert "Authorization" not in response.text


def test_unexpected_error_does_not_expose_stack_trace(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    async def fake_generate(_prompt):
        raise RuntimeError("internal secret and stack details")

    monkeypatch.setattr(api, "generate_ai_response", fake_generate)
    response = client.post("/v1/ai/respond", json={"prompt": "hello"}, headers=auth_headers())
    assert response.status_code == 500
    assert "internal secret" not in response.text
    assert "Traceback" not in response.text


def test_unconfigured_server_auth_fails_closed(client, monkeypatch):
    monkeypatch.delenv("TRUSTGUARD_API_BEARER_TOKEN", raising=False)
    response = client.post("/v1/ai/respond", json={"prompt": "hello"}, headers=auth_headers())
    assert response.status_code == 503


def test_process_local_rate_limit(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    async def fake_generate(_prompt):
        return AIResult("ok", "test-model")

    monkeypatch.setattr(api, "generate_ai_response", fake_generate)
    monkeypatch.setattr(api.rate_limiter, "limit", 1)
    assert client.post("/v1/ai/respond", json={"prompt": "one"}, headers=auth_headers()).status_code == 200
    assert client.post("/v1/ai/respond", json={"prompt": "two"}, headers=auth_headers()).status_code == 429


def test_ai_endpoint_does_not_invoke_transaction_dispatcher(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    async def fake_generate(_prompt):
        return AIResult("advisory only", "test-model")

    monkeypatch.setattr(api, "generate_ai_response", fake_generate)
    response = client.post("/v1/ai/respond", json={"prompt": "should not pay"}, headers=auth_headers())
    assert response.status_code == 200
    assert "main_public" not in api.__dict__
    assert "paypal_rest" not in api.__dict__


def test_authentication_configuration_error_does_not_leak(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    async def fake_generate(_prompt):
        raise AIConfigurationError("secret configuration details")

    monkeypatch.setattr(api, "generate_ai_response", fake_generate)
    response = client.post("/v1/ai/respond", json={"prompt": "hello"}, headers=auth_headers())
    assert response.status_code == 503
    assert "secret configuration" not in response.text
