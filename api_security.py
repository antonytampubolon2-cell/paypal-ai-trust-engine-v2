"""Profile-neutral HTTP request bounds for the single-process FastAPI service."""
from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

ASGIApp = Callable[[dict[str, Any], Callable[..., Awaitable[dict[str, Any]]], Callable[..., Awaitable[None]]], Awaitable[None]]


def _response(status: int, detail: str, *, headers: list[tuple[bytes, bytes]] | None = None):
    body = (f'{{"detail":"{detail}"}}').encode("ascii")
    response_headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))]
    response_headers.extend(headers or [])

    async def send_response(send):
        await send({"type": "http.response.start", "status": status, "headers": response_headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    return send_response


class RequestGuardMiddleware:
    """Enforce request limits using ASGI receive and the actual socket peer only."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = 1_048_576,
        max_concurrent_requests: int = 16,
        rate_limit_requests: int = 120,
        rate_limit_window_seconds: int = 60,
        request_timeout_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if max_body_bytes < 1 or max_concurrent_requests < 1 or rate_limit_requests < 1 or rate_limit_window_seconds < 1 or request_timeout_seconds <= 0:
            raise ValueError("request guard limits must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.clock = clock
        self._slots = threading.BoundedSemaphore(max_concurrent_requests)
        self._rate_lock = threading.Lock()
        self._rate: dict[str, tuple[int, int]] = {}

    def _rate_allowed(self, peer: str) -> bool:
        now = int(self.clock())
        window = now // self.rate_limit_window_seconds
        with self._rate_lock:
            # Bound memory even if an attacker can create many direct peer addresses.
            if len(self._rate) > 10_000:
                self._rate = {key: value for key, value in self._rate.items() if value[0] >= window - 1}
            prior_window, count = self._rate.get(peer, (window, 0))
            if prior_window != window:
                count = 0
            if count >= self.rate_limit_requests:
                self._rate[peer] = (window, count)
                return False
            self._rate[peer] = (window, count + 1)
            return True

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        if not self._slots.acquire(blocking=False):
            await _response(503, "service busy", headers=[(b"retry-after", b"1")])(send)
            return

        try:
            client = scope.get("client")
            # Deliberately do not use X-Forwarded-For or other caller-controlled headers.
            peer = str(client[0]) if isinstance(client, (tuple, list)) and client else "unknown-peer"
            if not self._rate_allowed(peer):
                await _response(429, "request rate limit exceeded", headers=[(b"retry-after", str(self.rate_limit_window_seconds).encode("ascii"))])(send)
                return

            content_lengths = [value for name, value in scope.get("headers", []) if name.lower() == b"content-length"]
            if len(content_lengths) > 1:
                await _response(400, "invalid content length")(send)
                return
            content_length = content_lengths[0] if content_lengths else None
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except (TypeError, ValueError):
                    await _response(400, "invalid content length")(send)
                    return
                if declared_length < 0:
                    await _response(400, "invalid content length")(send)
                    return
                if declared_length > self.max_body_bytes:
                    await _response(413, "request body too large")(send)
                    return

            body = bytearray()
            started = False

            async def guarded_send(message):
                nonlocal started
                if message.get("type") == "http.response.start":
                    started = True
                await send(message)

            async def run_request():
                while True:
                    message = await receive()
                    if message.get("type") == "http.disconnect":
                        return
                    if message.get("type") != "http.request":
                        continue
                    chunk = message.get("body", b"")
                    if not isinstance(chunk, bytes) or len(body) + len(chunk) > self.max_body_bytes:
                        await _response(413, "request body too large")(send)
                        return
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        delivered = False

                        async def buffered_receive():
                            nonlocal delivered
                            if not delivered:
                                delivered = True
                                return {"type": "http.request", "body": bytes(body), "more_body": False}
                            return {"type": "http.disconnect"}

                        await self.app(scope, buffered_receive, guarded_send)
                        return

            try:
                await asyncio.wait_for(run_request(), timeout=self.request_timeout_seconds)
            except asyncio.TimeoutError:
                if not started:
                    await _response(504, "request timed out")(send)
        finally:
            self._slots.release()


class TokenCacheControlMiddleware:
    """Protect responses that depend on sensitive KYAPay token headers from shared caches."""

    def __init__(self, app: ASGIApp, *, token_headers: Sequence[str]):
        self.app = app
        self.token_headers = {header.lower().encode("ascii") for header in token_headers}

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        present = any(
            name.lower() in self.token_headers
            for name, _value in scope.get("headers", [])
        )
        if not present:
            await self.app(scope, receive, send)
            return

        async def protected_send(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                vary_values = [value for name, value in headers if name.lower() == b"vary"]
                vary_tokens = {
                    token.strip().lower()
                    for value in vary_values
                    for token in value.split(b",")
                }
                if b"*" not in vary_tokens:
                    for header in self.token_headers:
                        if header not in vary_tokens:
                            vary_values.append(header)
                    headers = [(name, value) for name, value in headers if name.lower() != b"vary"]
                    if vary_values:
                        headers.append((b"vary", b", ".join(vary_values)))
                headers = [(name, value) for name, value in headers if name.lower() != b"cache-control"]
                headers.append((b"cache-control", b"private, no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, protected_send)
