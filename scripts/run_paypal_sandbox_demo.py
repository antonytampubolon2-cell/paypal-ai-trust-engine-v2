#!/usr/bin/env python3
"""LOCAL TEST ONLY: PayPal Sandbox checkout with locally generated TrustGuard credentials.

This is an operator-run demonstration, not a production verifier or public callback
application. It deliberately uses synthetic locally generated ES256 access/DPoP
credentials and binds its callback server to IPv4 loopback only.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


DISCLAIMER = (
    "LOCAL TEST ONLY — this demo uses locally generated ES256 access and DPoP "
    "credentials, not Skyfire credentials. Local authorization is not genuine "
    "Skyfire authorization. Never deploy this mode or port-forward localhost."
)
REQUIRED_ENV = (
    "TRUSTGUARD_LOCAL_SANDBOX_DEMO",
    "TRUSTGUARD_ENABLE_PAYPAL_SANDBOX",
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID",
    "TRUSTGUARD_PAYPAL_MERCHANT_ID",
    "TRUSTGUARD_DATABASE_PATH",
)
LOCAL_ACCESS_KID = "LOCAL-TEST-ONLY-ACCESS-ES256"
LOCAL_AUDIENCE = "trustguard-local-paypal-sandbox-demo"
LOCAL_TRANSACTION_AMOUNT = "5.00"
LOCAL_GRANT_LIMIT_MINOR = 10_000


@dataclass(frozen=True)
class SandboxDemoConfig:
    """Non-secret, validated values needed to start the demo."""

    client_id: str
    client_secret: str
    seller_service_id: str
    mapped_service_id: str
    merchant_id: str
    database_path: str


@dataclass(frozen=True)
class LocalCredentials:
    """Synthetic credentials kept in memory for one local demo run."""

    trust_config: Any
    access_token: str
    dpop_proof: str
    dispatch_url: str


class CallbackState:
    """Accept only the expected PayPal order token on the expected nonce path."""

    def __init__(self, nonce: str):
        self.nonce = nonce
        self.expected_order_id: str | None = None
        self.received_token: str | None = None
        self.received_payer_id: str | None = None
        self.signal = threading.Event()
        self._lock = threading.Lock()

    @property
    def path(self) -> str:
        return f"/paypal/callback/{self.nonce}"

    def set_expected_order(self, order_id: str) -> None:
        if not isinstance(order_id, str) or not order_id:
            raise ValueError("provider order identity is invalid")
        with self._lock:
            self.expected_order_id = order_id

    def accept(self, request_path: str, query: Mapping[str, list[str]]) -> bool:
        token = query.get("token", [None])[0]
        payer_id = query.get("PayerID", [None])[0]
        with self._lock:
            if (request_path != self.path or not self.expected_order_id
                    or query.get("token") != [self.expected_order_id]):
                return False
            self.received_token = token
            self.received_payer_id = payer_id if isinstance(payer_id, str) else None
            self.signal.set()
            return True


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    server_version = "TrustGuardLocalDemo/1.0"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        state: CallbackState = self.server.callback_state  # type: ignore[attr-defined]
        # The server is bound to 127.0.0.1; reject a request if a custom server
        # implementation ever supplies a different peer address.
        peer = self.client_address[0] if self.client_address else ""
        valid_peer = peer == "127.0.0.1"
        parsed = urlsplit(self.path)
        accepted = valid_peer and state.accept(parsed.path, parse_qs(parsed.query, keep_blank_values=True))
        body = (
            b"Approval callback received. Return to the local terminal; it is not capture proof."
            if accepted
            else b"Invalid local callback. No payment action was taken."
        )
        self.send_response(200 if accepted else 400)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: Any) -> None:
        # Never log query strings, which may contain provider callback material.
        return


def validate_config(env: Mapping[str, str] | None = None) -> SandboxDemoConfig:
    """Validate every required gate before a provider or network-capable object exists."""
    values = os.environ if env is None else env
    for name in REQUIRED_ENV:
        if not str(values.get(name, "")).strip():
            raise ValueError(f"required local-demo setting is missing: {name}")
    if values["TRUSTGUARD_LOCAL_SANDBOX_DEMO"].strip().lower() != "true":
        raise ValueError("TRUSTGUARD_LOCAL_SANDBOX_DEMO must be exactly true")
    if values["TRUSTGUARD_ENABLE_PAYPAL_SANDBOX"].strip().lower() != "true":
        raise ValueError("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX must be exactly true")

    local_service_id = values.get("TRUSTGUARD_LOCAL_TEST_SERVICE_ID", "").strip()
    if local_service_id:
        if not local_service_id.startswith("LOCAL-TEST-ONLY-PAYPAL-") or len(local_service_id) > 128:
            raise ValueError("TRUSTGUARD_LOCAL_TEST_SERVICE_ID must be a LOCAL-TEST-ONLY-PAYPAL-prefixed synthetic identifier")
        seller_service_id = local_service_id
    else:
        seller_service_id = values.get("SKYFIRE_SELLER_SERVICE_ID", "").strip()
        if not seller_service_id:
            raise ValueError("configure TRUSTGUARD_LOCAL_TEST_SERVICE_ID or confirmed SKYFIRE_SELLER_SERVICE_ID")
    mapped_service_id = values["TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID"].strip()
    merchant_id = values["TRUSTGUARD_PAYPAL_MERCHANT_ID"].strip()
    if mapped_service_id != seller_service_id:
        raise ValueError("PayPal mapping must exactly equal the selected service identity")
    if merchant_id == seller_service_id:
        raise ValueError("PayPal merchant ID must differ from the Skyfire service ID")

    database_path = values["TRUSTGUARD_DATABASE_PATH"].strip()
    if database_path == ":memory:":
        raise ValueError("TRUSTGUARD_DATABASE_PATH must be a persistent file path")
    if database_path.endswith(("/", "\\")):
        raise ValueError("TRUSTGUARD_DATABASE_PATH must name a persistent file")

    return SandboxDemoConfig(
        client_id=values["PAYPAL_CLIENT_ID"].strip(),
        client_secret=values["PAYPAL_CLIENT_SECRET"].strip(),
        seller_service_id=seller_service_id,
        mapped_service_id=mapped_service_id,
        merchant_id=merchant_id,
        database_path=database_path,
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    members = {key: jwk[key] for key in ("crv", "kty", "x", "y")}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url(hashlib.sha256(canonical).digest())


def generate_local_credentials(*, callback_port: int, merchant_id: str, seller_service_id: str) -> LocalCredentials:
    """Generate one synthetic access/DPoP pair; private keys never leave memory."""
    from trustguard import TrustConfig

    issuer = f"http://127.0.0.1:{callback_port}"
    dispatch_url = f"{issuer}/local/paypal/authorize"
    access_private = ec.generate_private_key(ec.SECP256R1())
    dpop_private = ec.generate_private_key(ec.SECP256R1())
    dpop_jwk = jwt.algorithms.ECAlgorithm.to_jwk(dpop_private.public_key(), as_dict=True)
    dpop_jwk.update({"kid": "LOCAL-TEST-ONLY-DPOP", "alg": "ES256", "use": "sig"})
    trust_config = TrustConfig.from_values(
        issuer=issuer,
        audience=LOCAL_AUDIENCE,
        trusted_keys={LOCAL_ACCESS_KID: access_private.public_key()},
        grant_id_field="gid",
        grant_limit_field="limit",
        grant_currency_field="currency",
        grant_payees_field="payees",
        jwt_algorithms=("ES256",),
    )
    now = int(time.time())
    access_token = jwt.encode(
        {
            "iss": issuer,
            "sub": "LOCAL-TEST-ONLY-BUYER",
            "aud": LOCAL_AUDIENCE,
            "iat": now - 1,
            "exp": now + 600,
            "jti": str(uuid.uuid4()),
            "cnf": {"jkt": _jwk_thumbprint(dpop_jwk)},
            "delegation_grant": {
                "gid": f"local-demo-grant-{uuid.uuid4().hex}",
                "limit": LOCAL_GRANT_LIMIT_MINOR,
                "currency": "USD",
                "payees": [merchant_id],
            },
        },
        access_private,
        algorithm="ES256",
        headers={"kid": LOCAL_ACCESS_KID, "typ": "kya-pay+jwt"},
    )
    dpop_proof = jwt.encode(
        {
            "htm": "POST",
            "htu": dispatch_url,
            "iat": now,
            "jti": str(uuid.uuid4()),
            "ath": _b64url(hashlib.sha256(access_token.encode("utf-8")).digest()),
        },
        dpop_private,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": dpop_jwk},
    )
    return LocalCredentials(trust_config, access_token, dpop_proof, dispatch_url)


def _callback_server(state: CallbackState) -> http.server.ThreadingHTTPServer:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CallbackHandler)
    server.callback_state = state  # type: ignore[attr-defined]
    return server


def _verified_approval_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        return None
    if parsed.netloc != "www.sandbox.paypal.com" or parsed.path not in {"/checkoutnow", "/webapps/hermes"}:
        return None
    return value


def _public_result(result: Any) -> dict[str, Any]:
    """Allowlist verified, non-secret checkout evidence; never print provider bodies."""
    if not isinstance(result, Mapping):
        return {"status": "UNKNOWN"}
    public: dict[str, Any] = {}
    for key in ("status", "transaction_id", "provider_order_id", "payment_completed"):
        value = result.get(key)
        if isinstance(value, (str, bool)):
            public[key] = value
    approval_url = _verified_approval_url(result.get("approval_url"))
    if (approval_url is not None and result.get("provider_order_id")
            and parse_qs(urlsplit(approval_url).query).get("token") == [result["provider_order_id"]]):
        public["approval_url"] = approval_url
    capture_id = result.get("capture_id")
    if isinstance(capture_id, str) and capture_id:
        public["capture_id"] = capture_id
    capture_ids = result.get("capture_ids")
    if isinstance(capture_ids, list) and all(isinstance(item, str) and item for item in capture_ids):
        public["capture_ids"] = capture_ids
    return public or {"status": "UNKNOWN"}


def run_demo(*, input_fn=input, output_fn=print, error_fn=print) -> int:
    """Run one guarded checkout; ambiguity is reported and never retried."""
    try:
        config = validate_config()
    except ValueError as exc:
        error_fn(f"LOCAL TEST ONLY: configuration rejected ({exc}). No provider or network was initialized.")
        return 2

    state = CallbackState(secrets.token_urlsafe(24))
    server: http.server.ThreadingHTTPServer | None = None
    thread: threading.Thread | None = None
    provider_initialized = False
    try:
        # All environment checks happen above. Only after they pass do we bind
        # the loopback callback and construct the network-capable PayPal adapter.
        server = _callback_server(state)
        thread = threading.Thread(target=server.serve_forever, name="trustguard-local-callback", daemon=True)
        thread.start()
        callback_url = f"http://127.0.0.1:{server.server_port}{state.path}"
        credentials = generate_local_credentials(
            callback_port=server.server_port,
            merchant_id=config.merchant_id,
            seller_service_id=config.seller_service_id,
        )

        from paypal_rest import PayPalRestOrdersProvider
        from trustguard import CanonicalTransaction, Ledger, TrustGuard

        provider = PayPalRestOrdersProvider(
            credentials.trust_config,
            return_url=callback_url,
            cancel_url=callback_url,
        )
        provider_initialized = True
        ledger = Ledger(config.database_path)
        guard = TrustGuard(credentials.trust_config, ledger, provider)
        transaction_id = f"local-paypal-demo-{uuid.uuid4().hex}"
        transaction = CanonicalTransaction.build(
            transaction_id=transaction_id,
            idempotency_key=str(uuid.uuid4()),
            amount=LOCAL_TRANSACTION_AMOUNT,
            currency="USD",
            skyfire_service_id=config.seller_service_id,
            paypal_merchant_id=config.merchant_id,
        )
        result = guard.authorize_and_dispatch(
            credentials.access_token,
            credentials.dpop_proof,
            "POST",
            credentials.dispatch_url,
            transaction,
        )
        public = _public_result(result)
        output_fn(DISCLAIMER)
        output_fn(json.dumps(public, sort_keys=True))
        if public.get("status") == "UNKNOWN":
            output_fn("Checkout stopped: provider outcome is ambiguous; do not retry automatically.")
            return 3
        order_id = public.get("provider_order_id")
        approval_url = public.get("approval_url")
        if not isinstance(order_id, str) or not order_id or not isinstance(approval_url, str):
            output_fn("Checkout stopped: no verified PayPal approval URL was returned.")
            return 3
        state.set_expected_order(order_id)
        output_fn(f"Open this verified PayPal Sandbox approval URL: {approval_url}")
        output_fn("Approve with your Sandbox Personal account, then enter the returned order ID. No callback or port forwarding is required.")
        supplied_order_id = input_fn("Returned PayPal order ID (not a URL or JWT): ").strip()
        persisted = ledger.get(transaction_id)
        if (not persisted or persisted["provider_order_id"] != order_id
                or not secrets.compare_digest(supplied_order_id.encode(), order_id.encode())):
            output_fn("Checkout stopped: manual order identity does not match the persisted order; no capture was attempted.")
            return 3
        if input_fn("Type APPROVE to capture: ").strip() != "APPROVE":
            output_fn("Checkout stopped: buyer approval was not entered; no capture was attempted.")
            return 0
        # Main TrustGuard owns the provider GET APPROVED verification and capture.
        capture_result = guard.capture_approved_order(transaction_id, buyer_approved=True)
        output_fn(json.dumps(_public_result(capture_result), sort_keys=True))
        if _public_result(capture_result).get("status") == "UNKNOWN":
            output_fn("Capture outcome is ambiguous; stop and reconcile manually. No retry was attempted.")
            return 3
        final_result = guard.reconcile(transaction_id)
        output_fn(json.dumps(_public_result(final_result), sort_keys=True))
        if final_result.get("status") != "COMPLETED" or final_result.get("payment_completed") is not True:
            output_fn("Final reconciliation did not confirm a completed payment; inspect the durable ledger.")
            return 3
        return 0
    except Exception:
        # Do not disclose provider exception text, response bodies, credentials, or
        # diagnostic stack details. The durable ledger remains the source for manual reconciliation.
        if provider_initialized:
            error_fn("LOCAL TEST ONLY: checkout stopped safely; inspect the persistent ledger and reconcile manually. No automatic retry was attempted.")
        else:
            error_fn("LOCAL TEST ONLY: checkout could not start; no payment result is claimed.")
        return 3
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)


def main() -> int:
    return run_demo()


if __name__ == "__main__":
    raise SystemExit(main())
