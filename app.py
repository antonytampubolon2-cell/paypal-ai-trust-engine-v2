"""FastAPI HTTP boundary for TrustGuard AI assistance.

This module deliberately does not import or invoke the PayPal transaction dispatcher.
AI responses are advisory only and cannot authorize transactions.
"""
from __future__ import annotations

import hmac
import importlib.util
import json
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ai_service import (
    AIConfigurationError,
    AIProviderError,
    AIProviderTimeout,
    generate_ai_response,
    filter_sensitive_output,
)

MAX_REQUEST_BYTES = 16 * 1024
MAX_PROMPT_CHARS = 4_000
MAX_RESPONSE_CHARS = 8_000
AUTH_ENV = "TRUSTGUARD_API_BEARER_TOKEN"
RATE_LIMIT_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60


class AIRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)


class AIResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = "ok"
    response: str = Field(min_length=1, max_length=MAX_RESPONSE_CHARS)
    model: str = Field(min_length=1, max_length=100)


class RequestSizeLimitMiddleware:
    """Enforce a body cap before FastAPI/Pydantic parse request data."""

    def __init__(self, app: Any, max_bytes: int = MAX_REQUEST_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                if int(raw_length) > self.max_bytes:
                    await self._too_large(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)(scope, receive, send)
                return

        body_parts: list[bytes] = []
        total = 0
        disconnected = False
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
                break
            part = message.get("body", b"")
            total += len(part)
            if total > self.max_bytes:
                await self._too_large(scope, receive, send)
                return
            body_parts.append(part)
            if not message.get("more_body", False):
                break
        if disconnected:
            return

        body = b"".join(body_parts)
        sent = False

        async def replay_receive() -> dict:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)

    async def _too_large(self, scope: dict, receive: Any, send: Any) -> None:
        await JSONResponse({"detail": "Request body exceeds the allowed size."}, status_code=413)(scope, receive, send)


class ProcessLocalRateLimiter:
    """Sliding-window limiter; process-local only, not distributed enforcement."""

    def __init__(self, limit: int = RATE_LIMIT_REQUESTS, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            events = self._events[key]
            cutoff = now - self.window_seconds
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


rate_limiter = ProcessLocalRateLimiter()
app = FastAPI(
    title="TrustGuard AI Assistance API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)
cors_origins = [origin.strip() for origin in os.getenv("TRUSTGUARD_CORS_ORIGINS", "").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


def _auth_token_is_configured() -> bool:
    token = os.getenv(AUTH_ENV, "")
    return len(token) >= 32 and token.strip() == token


def _authenticate(request: Request) -> None:
    expected = os.getenv(AUTH_ENV, "")
    scheme, credentials = get_authorization_scheme_param(request.headers.get("Authorization"))
    if not _auth_token_is_configured():
        raise HTTPException(status_code=503, detail="Service authentication is not configured.")
    if scheme.lower() != "bearer" or not credentials or not hmac.compare_digest(credentials, expected):
        raise HTTPException(status_code=401, detail="Authentication required.", headers={"WWW-Authenticate": "Bearer"})


@app.exception_handler(Exception)
async def safe_unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Do not log prompts, headers, tokens, exception text, or stack traces.
    return JSONResponse(status_code=500, content={"detail": "Internal service error."})


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict[str, Any]:
    sdk_available = importlib.util.find_spec("openai") is not None
    key_configured = bool(os.getenv("OPENAI_API_KEY", "").strip())
    auth_configured = _auth_token_is_configured()
    ready = sdk_available and key_configured and auth_configured
    return {
        "status": "ready" if ready else "not_ready",
        "checks": {
            "openai_sdk": "available" if sdk_available else "missing",
            "openai_credentials": "configured" if key_configured else "missing",
            "client_authentication": "configured" if auth_configured else "missing",
        },
    }


@app.post("/v1/ai/respond", response_model=AIResponse)
async def ai_respond(request: Request) -> AIResponse:
    _authenticate(request)
    client_host = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_host):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    try:
        raw_body = await request.json()
        payload = AIRequest.model_validate(raw_body)
    except (ValueError, ValidationError, json.JSONDecodeError):
        raise HTTPException(status_code=422, detail="Invalid request body.") from None

    try:
        result = await generate_ai_response(payload.prompt)
    except AIConfigurationError:
        raise HTTPException(status_code=503, detail="AI service is not configured.") from None
    except AIProviderTimeout:
        raise HTTPException(status_code=504, detail="AI provider timed out.") from None
    except AIProviderError:
        raise HTTPException(status_code=502, detail="AI provider request failed.") from None

    filtered = filter_sensitive_output(result.text)
    if not filtered or len(filtered) > MAX_RESPONSE_CHARS:
        raise HTTPException(status_code=502, detail="AI provider returned an unusable response.")
    return AIResponse(status="ok", response=filtered, model=result.model)
