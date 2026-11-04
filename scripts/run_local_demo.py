#!/usr/bin/env python3
"""LOCAL TEST ONLY: offline HTTP-route demonstration, never genuine Sandbox evidence."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

DISCLAIMER = (
    "LOCAL TEST ONLY — generated ES256 keys and synthetic Skyfire-like claims; "
    "not genuine Skyfire tokens, not proof of real Sandbox integration. "
    "IsolationForest uses synthetic training data. No real payment is created or completed."
)


class LocalASGITestClient:
    """In-process HTTP test client: no listening socket or external HTTP transport."""

    def __init__(self, application):
        self.application = application
        self.requests = []

    def request(self, method, path, *, headers=None, payload=None):
        self.requests.append((method, path))  # Never record headers, JWTs or body.
        body = json.dumps(payload).encode() if payload is not None else b""
        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "method": method, "scheme": "http",
            "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
            "headers": [(b"host", b"local-test-only"), (b"content-type", b"application/json"),
                        *[(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]],
            "server": ("local-test-only", 80), "client": ("127.0.0.1", 1),
        }
        messages = []
        received = False

        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)

        asyncio.run(self.application(scope, receive, send))
        status = next(m["status"] for m in messages if m["type"] == "http.response.start")
        result = json.loads(b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body"))
        return status, result


class ProviderSpy:
    def __init__(self):
        self.invocations = 0
        self.network_attempts = 0

    def forbidden_provider(self, *_args, **_kwargs):
        self.invocations += 1
        raise RuntimeError("LOCAL TEST ONLY: provider invocation forbidden")

    def forbidden_network(self, *_args, **_kwargs):
        self.network_attempts += 1
        raise RuntimeError("LOCAL TEST ONLY: outbound network forbidden")


class CountingScorer:
    """Instrumentation only: delegate inference to the existing, unchanged model."""
    def __init__(self, scorer):
        self.scorer = scorer
        self.calls = 0
        self.model_version = scorer.model_version
        self.training_dataset_id = scorer.training_dataset_id

    def score(self, features):
        self.calls += 1
        return self.scorer.score(features)


def run_demo():
    """Return non-sensitive scenario evidence. Temporary data is removed on exit."""
    from trustguard import Ledger, MockProvider, TrustGuard
    from paypal_rest import PayPalRestOrdersProvider
    from skyfire_auth import (
        DOCUMENTED_SANDBOX_ISSUER, DOCUMENTED_SANDBOX_JWKS_URL,
        SkyfireSettings, SkyfireTokenVerifier,
    )
    from risk_scoring import SyntheticIsolationForestScorer

    spy = ProviderSpy()
    with tempfile.TemporaryDirectory(prefix="trustguard-local-test-only-") as directory, ExitStack() as stack:
        # Ignore all ambient credentials/config; restore the caller's environment afterwards.
        stack.enter_context(patch.dict(os.environ, {"TRUSTGUARD_ENABLE_PAYPAL_SANDBOX": "false"}, clear=True))
        for cls, names in (
            (PayPalRestOrdersProvider, ("create_order", "get_order_details")),
            (MockProvider, ("create_order", "get_order_details")),
            (TrustGuard, ("authorize_and_dispatch", "reconcile")),
        ):
            for name in names:
                stack.enter_context(patch.object(cls, name, spy.forbidden_provider))
        stack.enter_context(patch("requests.sessions.Session.request", spy.forbidden_network))
        stack.enter_context(patch("socket.create_connection", spy.forbidden_network))
        stack.enter_context(patch.object(SkyfireTokenVerifier, "_fetch_jwks", spy.forbidden_network))
        from app import create_app

        path = Path(directory) / "local-test-only.sqlite3"
        settings = SkyfireSettings(
            DOCUMENTED_SANDBOX_ISSUER, DOCUMENTED_SANDBOX_JWKS_URL, "sandbox",
            "LOCAL-TEST-ONLY-SELLER", "LOCAL-TEST-ONLY-SERVICE", str(path),
        )
        private = ec.generate_private_key(ec.SECP256R1())
        public_jwk = jwt.algorithms.ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
        public_jwk.update(kid="LOCAL-TEST-ONLY-KEY", alg="ES256", use="sig")
        verifier = SkyfireTokenVerifier(settings, jwks_fetcher=lambda: {"keys": [public_jwk]})
        scorer = CountingScorer(SyntheticIsolationForestScorer())
        reviewer_credential = secrets.token_urlsafe(48)  # Memory only; never environment/file/output.

        def application(ledger):
            instance = create_app(settings=settings, ledger=ledger, verifier=verifier, risk_scorer=scorer)
            instance.state.reviewer_id = "LOCAL-TEST-ONLY-REVIEWER"
            instance.state.reviewer_credential = reviewer_credential
            instance.state.reviewer_enabled = True
            return instance

        def token(subject):
            now = int(time.time())
            return jwt.encode({
                "iss": settings.issuer, "aud": settings.seller_agent_account_id,
                "tsi": settings.seller_service_id, "sub": subject, "env": "sandbox",
                "iat": now - 5, "exp": now + 600, "jti": str(uuid.uuid4()),
                "amt": "50.00", "cur": "USD", "val": "50000000", "stp": "card",
                "sti": {"verified": True, "payment_token": "LOCAL-TEST-ONLY-NOT-SETTLEMENT"},
            }, private, algorithm="ES256", headers={"kid": public_jwk["kid"], "typ": "kya-pay+jwt"})

        ledger = Ledger(path)
        client = LocalASGITestClient(application(ledger))
        low_token = token("LOCAL-TEST-ONLY-LOW-BUYER")
        high_token = token("LOCAL-TEST-ONLY-HIGH-BUYER")
        low_payload = {"transaction_id": "LOCAL-TEST-ONLY-LOW", "idempotency_key": "LOCAL-TEST-ONLY-LOW-IDEM", "amount": "5.00", "currency": "USD"}
        high_payload = {"transaction_id": "LOCAL-TEST-ONLY-HIGH", "idempotency_key": "LOCAL-TEST-ONLY-HIGH-IDEM", "amount": "50.00", "currency": "USD"}
        screening_path = "/v1/agent/screen-transaction"
        status, low = client.request("POST", screening_path, headers={"skyfire-pay-id": low_token}, payload=low_payload)
        assert status == 200 and low["status"] == "ALLOW" and scorer.calls == 1
        status, high = client.request("POST", screening_path, headers={"skyfire-pay-id": high_token}, payload=high_payload)
        assert status == 200 and high["status"] == "HOLD" and scorer.calls == 2
        assert low["paypal_integration_status"] == high["paypal_integration_status"] == "NOT_CONFIGURED"

        review_path = "/v1/admin/transactions/LOCAL-TEST-ONLY-HIGH/review"
        review_payload = {"decision": "RELEASE_RESERVATION", "reason": "LOCAL TEST ONLY: abandon synthetic held transaction"}
        held = ledger.get(high_payload["transaction_id"])
        active = "('RESERVED','SCREENED_ALLOW','HOLD','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','UNKNOWN')"

        def reserved_minor(database, grant_id):
            db = database._connect()
            try:
                return db.execute(f"SELECT COALESCE(SUM(amount_minor),0) FROM transactions WHERE grant_id=? AND status IN {active}", (grant_id,)).fetchone()[0]
            finally:
                db.close()

        before = reserved_minor(ledger, held["grant_id"])
        status, review = client.request("POST", review_path, headers={"x-trustguard-reviewer-credential": reviewer_credential}, payload=review_payload)
        assert status == 200 and review["transaction_state"] == "REVIEW_RELEASED"
        after = reserved_minor(ledger, held["grant_id"])
        assert before == 5000 and after == 0

        reopened = Ledger(path)
        low_record = reopened.get(low_payload["transaction_id"])
        high_record = reopened.get(high_payload["transaction_id"])
        assert low_record["status"] == "SCREENED_ALLOW" and low_record["risk_decision"] == "ALLOW"
        assert high_record["status"] == "REVIEW_RELEASED" and high_record["risk_decision"] == "HOLD"
        assert high_record["review_decision"] == "RELEASE_RESERVATION"
        assert high_record["reviewed_at"] == review["reviewed_at"]
        assert high_record["reviewer_id"] == review["reviewer_id"]
        assert high_record["review_reason"] == review["reason"]
        for record, result in ((low_record, low), (high_record, high)):
            assert record["anomaly_score"] == result["risk_assessment"]["anomaly_score"]
            assert record["risk_model_version"] == result["risk_assessment"]["model_version"]
        restarted_client = LocalASGITestClient(application(reopened))
        status, low_retry = restarted_client.request("POST", screening_path, headers={"skyfire-pay-id": low_token}, payload=low_payload)
        assert status == 200 and low_retry == low and scorer.calls == 2
        status, review_retry = restarted_client.request("POST", review_path, headers={"x-trustguard-reviewer-credential": reviewer_credential}, payload=review_payload)
        assert status == 200 and review_retry == review
        status, _ = restarted_client.request("POST", screening_path, headers={"skyfire-pay-id": high_token}, payload=high_payload)
        assert status == 409  # Released transactions stay terminal; never re-reserved.
        db = reopened._connect()
        try:
            assert db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 2
            assert db.execute("SELECT COUNT(*) FROM transaction_reviews").fetchone()[0] == 1
        finally:
            db.close()
        assert low_record["provider_order_id"] is None and high_record["provider_order_id"] is None
        assert spy.invocations == spy.network_attempts == 0

        def summary(name, result):
            return {
                "scenario": name, "transaction_id": result["transaction_id"],
                "risk_decision": result["status"], "anomaly_score": result["risk_assessment"]["anomaly_score"],
                "model_version": result["risk_assessment"]["model_version"],
                "durable_ledger_state": result["transaction_state"], "reason_code": result["reason_code"],
            }

        return {
            "disclaimer": DISCLAIMER,
            "scenarios": [
                summary("A — LOW RISK", low), summary("B — HIGH RISK", high),
                {**summary("C — ADMIN REVIEW", high), "durable_ledger_state": high_record["status"],
                 "reviewer_decision": review["decision"], "reserved_minor_before": before, "reserved_minor_after": after,
                 "audit_persisted": True, "payment_authorized": False},
                {"scenario": "D — DURABILITY", "transaction_id": high_record["transaction_id"],
                 "risk_decision": high_record["risk_decision"], "anomaly_score": high_record["anomaly_score"],
                 "model_version": high_record["risk_model_version"], "durable_ledger_state": high_record["status"],
                 "reviewer_decision": high_record["review_decision"], "restart_idempotency_verified": True,
                 "transaction_count": 2, "audit_count": 1},
                {"scenario": "E — PROVIDER SAFETY", "provider_invocation_count": spy.invocations,
                 "external_network_attempt_count": spy.network_attempts, "paypal_dispatch": "DISABLED_NOT_CALLED"},
            ],
            "model_inference_count": scorer.calls,
            "http_routes_exercised": client.requests + restarted_client.requests,
            "provider_invocation_count": spy.invocations,
            "paypal_dispatch": "DISABLED_NOT_CALLED",
        }


def main():
    try:
        report = run_demo()
    except Exception:
        # Never emit tracebacks containing synthetic JWTs or ephemeral reviewer material.
        print("LOCAL TEST ONLY demonstration FAILED; no successful payment is claimed.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
