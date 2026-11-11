import asyncio
import json

import pytest

from api_security import RequestGuardMiddleware


def make_request(guard, peer, *, headers=()):
    async def run():
        sent = []
        scope = {
            "type": "http",
            "method": "GET",
            "headers": [(name.lower(), value) for name, value in headers],
            "client": (peer, 12345),
        }
        received = False

        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        await guard(scope, receive, send)
        start = next(message for message in sent if message["type"] == "http.response.start")
        body = b"".join(
            message.get("body", b"") for message in sent
            if message["type"] == "http.response.body"
        )
        try:
            decoded_body = json.loads(body)
        except json.JSONDecodeError:
            decoded_body = body.decode("utf-8")
        return start["status"], dict(start["headers"]), decoded_body

    return asyncio.run(run())


def ok_app(scope, receive, send):
    async def respond():
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})
    return respond()


def test_duplicate_content_length_is_rejected_before_downstream_app():
    called = []

    async def downstream(scope, receive, send):
        called.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    guard = RequestGuardMiddleware(downstream)
    status, _, body = make_request(
        guard,
        "192.0.2.20",
        headers=((b"content-length", b"0"), (b"content-length", b"0")),
    )

    assert status == 400
    assert body["detail"] == "invalid content length"
    assert called == []


def test_high_cardinality_cannot_grow_rate_state_past_capacity():
    capacity = 24
    guard = RequestGuardMiddleware(
        ok_app, rate_limit_requests=100, max_rate_limit_state_entries=capacity,
        clock=lambda: 12.25,
    )

    statuses = [make_request(guard, f"198.51.100.{index}")[0] for index in range(1000)]

    assert statuses[:capacity] == [200] * capacity
    assert statuses[capacity:] == [503] * (1000 - capacity)
    assert len(guard._rate) == capacity
    assert all(status == 503 for status in statuses[capacity:])


def test_capacity_failure_is_distinguishable_and_retry_after_is_measurable():
    guard = RequestGuardMiddleware(
        ok_app, rate_limit_requests=10, rate_limit_window_seconds=60,
        max_rate_limit_state_entries=1, clock=lambda: 12.25,
    )
    assert make_request(guard, "peer-a")[0] == 200

    status, headers, body = make_request(guard, "peer-b")

    assert status == 503
    assert body["detail"] == "rate limiter capacity exhausted"
    assert headers[b"retry-after"] == b"48"
    assert set(guard._rate) == {"peer-a"}


def test_expired_entries_are_removed_and_capacity_returns_after_window():
    now = [1.0]
    guard = RequestGuardMiddleware(
        ok_app, rate_limit_requests=10, rate_limit_window_seconds=10,
        max_rate_limit_state_entries=2, clock=lambda: now[0],
    )
    assert make_request(guard, "old-a")[0] == 200
    assert make_request(guard, "old-b")[0] == 200
    assert set(guard._rate) == {"old-a", "old-b"}

    now[0] = 10.1
    status, _, _ = make_request(guard, "new-peer")

    assert status == 200
    assert set(guard._rate) == {"new-peer"}
    assert len(guard._rate) == 1


def test_active_peer_bucket_is_not_evicted_to_admit_another_peer():
    now = [1.0]
    guard = RequestGuardMiddleware(
        ok_app, rate_limit_requests=2, rate_limit_window_seconds=10,
        max_rate_limit_state_entries=1, clock=lambda: now[0],
    )
    assert make_request(guard, "peer-a")[0] == 200
    assert make_request(guard, "peer-b")[0] == 503
    # Existing identities retain their own bucket; a new identity cannot evict it.
    assert make_request(guard, "peer-a")[0] == 200
    assert set(guard._rate) == {"peer-a"}
    assert make_request(guard, "peer-a")[0] == 429
    assert make_request(guard, "peer-b")[0] == 503


def test_forwarded_ip_headers_cannot_change_the_trusted_peer_bucket():
    guard = RequestGuardMiddleware(
        ok_app, rate_limit_requests=1, max_rate_limit_state_entries=4,
    )

    first = make_request(guard, "192.0.2.10", headers=((b"x-forwarded-for", b"198.51.100.1"),))
    spoof_same_peer = make_request(guard, "192.0.2.10", headers=((b"x-forwarded-for", b"203.0.113.9"),))
    different_socket_peer = make_request(guard, "192.0.2.11", headers=((b"x-forwarded-for", b"198.51.100.1"),))

    assert first[0] == 200
    assert spoof_same_peer[0] == 429
    assert different_socket_peer[0] == 200
    assert set(guard._rate) == {"192.0.2.10", "192.0.2.11"}


def test_concurrent_distinct_peers_fail_closed_at_capacity():
    async def run():
        capacity = 3
        entered = asyncio.Event()
        release = asyncio.Event()
        entered_downstream = 0

        async def slow_app(scope, receive, send):
            nonlocal entered_downstream
            entered_downstream += 1
            entered.set()
            await release.wait()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok", "more_body": False})

        guard = RequestGuardMiddleware(
            slow_app, max_concurrent_requests=16, rate_limit_requests=10,
            max_rate_limit_state_entries=capacity,
        )

        async def invoke(peer):
            sent = []
            delivered = False

            async def receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": b"", "more_body": False}
                return {"type": "http.disconnect"}

            async def send(message):
                sent.append(message)

            await guard({"type": "http", "method": "GET", "headers": [], "client": (peer, 1)}, receive, send)
            return next(m["status"] for m in sent if m["type"] == "http.response.start")

        tasks = [asyncio.create_task(invoke(f"peer-{index}")) for index in range(12)]
        await entered.wait()
        # Let all competing requests reach the locked admission decision while
        # successful requests remain in downstream processing.
        await asyncio.sleep(0)
        release.set()
        statuses = await asyncio.gather(*tasks)
        return statuses, guard, entered_downstream

    statuses, guard, entered = asyncio.run(run())
    assert statuses.count(200) == 3
    assert statuses.count(503) == 9
    assert entered == 3
    assert len(guard._rate) == 3
