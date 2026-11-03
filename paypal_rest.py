"""PayPal REST Orders v2 adapter. Sandbox endpoint only; HTTP session is injectable for tests."""
from __future__ import annotations

import os
import time
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from urllib.parse import quote

import requests

from trustguard import (
    CanonicalTransaction,
    ConfigurationError,
    ProviderAmbiguousError,
    ProviderDefinitiveError,
    TrustConfig,
    build_paypal_order_payload,
)


SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"
TOKEN_PATH = "/v1/oauth2/token"
ORDERS_PATH = "/v2/checkout/orders"


class PayPalRestOrdersProvider:
    """OAuth-authenticated Sandbox-only Orders v2 client.

    Construct via ``from_env`` after loading TrustConfig. Credentials are kept in
    memory only and never interpolated into errors or log output.
    """

    def __init__(self, trust_config: TrustConfig,
                 *, session: Any | None = None, timeout: tuple[float, float] = (3.05, 15.0)):
        if os.environ.get("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "").lower() != "true":
            raise ConfigurationError("PayPal Sandbox dispatch requires TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true")
        client_id = os.environ.get("PAYPAL_CLIENT_ID", "")
        client_secret = os.environ.get("PAYPAL_CLIENT_SECRET", "")
        if not client_id or not client_secret:
            raise ConfigurationError("PayPal Sandbox credentials are missing")
        if not isinstance(trust_config, TrustConfig) or not trust_config.issuer or not trust_config.audience or not trust_config.trusted_keys or not all((trust_config.grant_id_field, trust_config.grant_limit_field, trust_config.grant_currency_field, trust_config.grant_payees_field)):
            raise ConfigurationError("complete KYAPay issuer, audience, key, and grant configuration is required")
        if not isinstance(timeout, tuple) or len(timeout) != 2 or any(not isinstance(x, (int, float)) or x <= 0 for x in timeout):
            raise ConfigurationError("positive connect/read timeouts are required")
        self._client_id = client_id
        self._client_secret = client_secret
        self._session = session or requests.Session()
        self._timeout = timeout
        self._access_token: str | None = None
        self._access_token_expires_at = 0.0

    @staticmethod
    def _ensure_enabled() -> None:
        if os.environ.get("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "").lower() != "true":
            raise ConfigurationError("PayPal Sandbox dispatch is disabled")

    @classmethod
    def from_env(cls, trust_config: TrustConfig, *, session: Any | None = None,
                 timeout: tuple[float, float] = (3.05, 15.0)) -> "PayPalRestOrdersProvider":
        if os.environ.get("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "").lower() != "true":
            raise ConfigurationError("PayPal Sandbox dispatch is disabled")
        client_id = os.environ.get("PAYPAL_CLIENT_ID", "")
        client_secret = os.environ.get("PAYPAL_CLIENT_SECRET", "")
        if not client_id or not client_secret:
            raise ConfigurationError("PayPal Sandbox credentials are missing")
        return cls(trust_config, session=session, timeout=timeout)

    def _oauth_token(self) -> str:
        self._ensure_enabled()
        now = time.time()
        if self._access_token and now < self._access_token_expires_at - 30:
            return self._access_token
        try:
            response = self._session.post(
                SANDBOX_BASE_URL + TOKEN_PATH,
                auth=(self._client_id, self._client_secret),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"},
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.RequestException as e:
            raise ProviderDefinitiveError("PayPal OAuth request failed; no order request was sent") from e
        if response.status_code < 200 or response.status_code >= 300:
            raise ProviderDefinitiveError("PayPal OAuth rejected the configured credentials")
        try:
            data = response.json()
        except (ValueError, AttributeError) as e:
            raise ProviderDefinitiveError("PayPal OAuth returned malformed JSON") from e
        token = data.get("access_token") if isinstance(data, dict) else None
        expires_in = data.get("expires_in", 300) if isinstance(data, dict) else 0
        if not isinstance(token, str) or not token or not isinstance(expires_in, (int, float)) or expires_in <= 0:
            raise ProviderDefinitiveError("PayPal OAuth response is missing a valid access token")
        self._access_token = token
        self._access_token_expires_at = now + float(expires_in)
        return token

    @staticmethod
    def _validate_order_binding(tx: CanonicalTransaction, body: Mapping[str, Any]) -> bool:
        if body.get("id") is None or not isinstance(body.get("purchase_units"), list) or len(body["purchase_units"]) != 1:
            return False
        unit = body["purchase_units"][0]
        if not isinstance(unit, dict):
            return False
        if unit.get("reference_id") != tx.transaction_id:
            return False
        payee = unit.get("payee")
        amount = unit.get("amount")
        if not isinstance(payee, dict) or payee.get("merchant_id") != tx.payee or not isinstance(amount, dict):
            return False
        if amount.get("currency_code") != tx.currency:
            return False
        try:
            returned_amount = Decimal(str(amount.get("value")))
        except (InvalidOperation, ValueError):
            return False
        return returned_amount.is_finite() and returned_amount == tx.amount_decimal

    def create_order(self, tx: CanonicalTransaction) -> Mapping[str, Any]:
        """Create exactly one canonical order; ambiguity is surfaced, never retried."""
        if not isinstance(tx, CanonicalTransaction):
            raise ProviderDefinitiveError("a canonical authorized transaction is required")
        token = self._oauth_token()
        payload = build_paypal_order_payload(tx)
        try:
            response = self._session.post(
                SANDBOX_BASE_URL + ORDERS_PATH,
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Prefer": "return=representation",
                    "PayPal-Request-Id": tx.idempotency_key,
                },
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.RequestException as e:
            raise ProviderAmbiguousError("PayPal order request outcome is unknown") from e
        if response.status_code < 200 or response.status_code >= 300:
            if response.status_code == 409:
                raise ProviderAmbiguousError("PayPal reported a conflicting order request; reconciliation is required")
            if 400 <= response.status_code < 500:
                raise ProviderDefinitiveError("PayPal rejected the order request")
            raise ProviderAmbiguousError("PayPal order request outcome is unknown")
        try:
            body = response.json()
        except (ValueError, AttributeError) as e:
            raise ProviderAmbiguousError("PayPal order response was malformed") from e
        order_id = body.get("id") if isinstance(body, dict) else None
        if not isinstance(order_id, str) or not order_id:
            raise ProviderAmbiguousError("PayPal order response did not include an order ID")
        if not self._validate_order_binding(tx, body):
            raise ProviderAmbiguousError("PayPal order response did not match the authorized transaction", order_id)
        status = body.get("status")
        if status in {"CREATED", "APPROVED"}:
            return {"id": order_id, "status": status}
        # Even if a create response claims COMPLETED, only GET reconciliation may
        # confirm completed captures and transition the ledger to COMPLETED.
        raise ProviderAmbiguousError("PayPal returned an unexpected create-order state", order_id)

    @staticmethod
    def _capture_evidence_matches(tx: CanonicalTransaction, unit: Mapping[str, Any]) -> bool:
        payments = unit.get("payments")
        captures = payments.get("captures") if isinstance(payments, dict) else None
        if not isinstance(captures, list) or not captures:
            return False
        total = Decimal("0")
        for capture in captures:
            if not isinstance(capture, dict) or not isinstance(capture.get("id"), str) or not capture["id"] or capture.get("status") != "COMPLETED":
                return False
            amount = capture.get("amount")
            if not isinstance(amount, dict) or amount.get("currency_code") != tx.currency:
                return False
            try:
                capture_amount = Decimal(str(amount.get("value")))
            except (InvalidOperation, ValueError):
                return False
            if not capture_amount.is_finite() or capture_amount <= 0:
                return False
            total += capture_amount
        return total == tx.amount_decimal

    def get_order_details(self, tx: CanonicalTransaction, order_id: str) -> Mapping[str, Any]:
        """Read and reconcile an order; COMPLETED requires exact completed-capture evidence."""
        if not isinstance(tx, CanonicalTransaction) or not isinstance(order_id, str) or not order_id:
            return {"id": order_id, "status": "UNKNOWN"}
        token = self._oauth_token()
        try:
            response = self._session.get(
                SANDBOX_BASE_URL + ORDERS_PATH + "/" + quote(order_id, safe=""),
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.RequestException as e:
            raise ProviderAmbiguousError("PayPal order reconciliation outcome is unknown", order_id) from e
        if response.status_code < 200 or response.status_code >= 300:
            raise ProviderAmbiguousError("PayPal order reconciliation could not be confirmed", order_id)
        try:
            body = response.json()
        except (ValueError, AttributeError) as e:
            raise ProviderAmbiguousError("PayPal reconciliation response was malformed", order_id) from e
        if not isinstance(body, dict) or body.get("id") != order_id or not self._validate_order_binding(tx, body):
            return {"id": order_id, "status": "UNKNOWN"}
        order_status = body.get("status")
        unit = body["purchase_units"][0]
        if order_status in {"CREATED", "APPROVED"}:
            return {"id": order_id, "status": order_status}
        if order_status == "COMPLETED":
            if self._capture_evidence_matches(tx, unit):
                return {"id": order_id, "status": "COMPLETED", "verified_capture": True}
            return {"id": order_id, "status": "UNKNOWN"}
        if order_status == "VOIDED":
            payments = unit.get("payments") if isinstance(unit, dict) else None
            captures = payments.get("captures", []) if isinstance(payments, dict) else []
            if not any(isinstance(c, dict) and c.get("status") == "COMPLETED" for c in captures):
                return {"id": order_id, "status": "FAILED"}
        return {"id": order_id, "status": "UNKNOWN"}
