"""PayPal REST Orders v2 adapter. Sandbox-only HTTPS transport."""
from __future__ import annotations

import math
import os
import time
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from urllib.parse import quote, urlsplit, parse_qs

import requests

from trustguard import (
    CanonicalTransaction,
    ConfigurationError,
    Ledger,
    ProviderAmbiguousError,
    ProviderDefinitiveError,
    TrustConfig,
    build_paypal_order_payload,
)


SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"
SANDBOX_HOST = "api-m.sandbox.paypal.com"
TOKEN_PATH = "/v1/oauth2/token"
ORDERS_PATH = "/v2/checkout/orders"
MAX_TIMEOUT_SECONDS = 60.0


def _new_sandbox_session() -> requests.Session:
    """Create the production transport with verified TLS and no env proxy overrides."""
    session = requests.Session()
    session.verify = True
    session.trust_env = False
    return session


def _validated_timeout(value: Any) -> float | tuple[float, float]:
    """Accept Requests scalar or connect/read timeouts, bounded to (0, 60] seconds."""
    def component(item: Any) -> float:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ConfigurationError("timeouts must be finite positive numbers no greater than 60 seconds")
        try:
            seconds = float(item)
        except (OverflowError, ValueError):
            raise ConfigurationError("timeouts must be finite positive numbers no greater than 60 seconds") from None
        if not math.isfinite(seconds) or not 0.0 < seconds <= MAX_TIMEOUT_SECONDS:
            raise ConfigurationError("timeouts must be finite positive numbers no greater than 60 seconds")
        return seconds

    if isinstance(value, tuple):
        if len(value) != 2:
            raise ConfigurationError("tuple timeout must contain connect and read values")
        return component(value[0]), component(value[1])
    return component(value)


class PayPalRestOrdersProvider:
    """OAuth-authenticated Sandbox-only Orders v2 client.

    Construct via ``from_env`` after loading TrustConfig. Credentials are kept in
    memory only and never interpolated into errors or log output.
    """

    def __init__(self, trust_config: TrustConfig,
                 *, timeout: float | tuple[float, float] = (3.05, 15.0),
                 return_url: str | None = None, cancel_url: str | None = None):
        if os.environ.get("PAYPAL_ENV", "").strip().lower() != "sandbox":
            raise ConfigurationError("PAYPAL_ENV must be explicitly set to sandbox")
        if os.environ.get("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "").lower() != "true":
            raise ConfigurationError("PayPal Sandbox dispatch requires TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true")
        client_id = os.environ.get("PAYPAL_CLIENT_ID", "")
        client_secret = os.environ.get("PAYPAL_CLIENT_SECRET", "")
        if not client_id or not client_secret:
            raise ConfigurationError("PayPal Sandbox credentials are missing")
        if not isinstance(trust_config, TrustConfig) or not trust_config.issuer or not trust_config.audience or not trust_config.trusted_keys or not all((trust_config.grant_id_field, trust_config.grant_limit_field, trust_config.grant_currency_field, trust_config.grant_payees_field)):
            raise ConfigurationError("complete KYAPay issuer, audience, key, and grant configuration is required")
        if os.environ.get("TRUSTGUARD_LOCAL_TEST_SERVICE_ID", "").strip():
            local_issuer = urlsplit(trust_config.issuer)
            if (os.environ.get("TRUSTGUARD_LOCAL_SANDBOX_DEMO", "").lower() != "true"
                    or local_issuer.scheme != "http" or local_issuer.hostname != "127.0.0.1"
                    or not local_issuer.port or local_issuer.username or local_issuer.password
                    or local_issuer.path or local_issuer.query or local_issuer.fragment
                    or trust_config.audience != "trustguard-local-paypal-sandbox-demo"):
                raise ConfigurationError("synthetic Sandbox identity requires isolated loopback demo authorization")
        timeout = _validated_timeout(timeout)
        self._client_id = client_id
        self._client_secret = client_secret
        self._session = _new_sandbox_session()
        self._timeout = timeout
        self._access_token: str | None = None
        self._access_token_expires_at = 0.0
        self._callback_urls = None
        if return_url is not None or cancel_url is not None:
            if os.environ.get("TRUSTGUARD_LOCAL_SANDBOX_DEMO", "").lower() != "true":
                raise ConfigurationError("local Sandbox callbacks require explicit local demo mode")
            for url in (return_url, cancel_url):
                parsed = urlsplit(url or "")
                if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                        or not parsed.port or parsed.username or parsed.password or parsed.fragment):
                    raise ConfigurationError("Sandbox demo callbacks must bind to literal localhost")
            self._callback_urls = {"return_url": return_url, "cancel_url": cancel_url}

    @staticmethod
    def _ensure_enabled() -> None:
        if os.environ.get("PAYPAL_ENV", "").strip().lower() != "sandbox":
            raise ConfigurationError("PayPal requests require PAYPAL_ENV=sandbox")
        if os.environ.get("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "").lower() != "true":
            raise ConfigurationError("PayPal Sandbox dispatch is disabled")

    @classmethod
    def _check_transaction_mapping(cls, tx: CanonicalTransaction) -> None:
        cls._ensure_enabled()
        merchant = os.environ.get("TRUSTGUARD_PAYPAL_MERCHANT_ID", "").strip()
        if not merchant or tx.paypal_merchant_id != merchant or tx.payee != merchant:
            raise ConfigurationError("canonical PayPal merchant must match explicit server configuration")
        if tx.skyfire_service_id is not None:
            source = os.environ.get("TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID", "").strip()
            service = os.environ.get("SKYFIRE_SELLER_SERVICE_ID", "").strip()
            local_service = os.environ.get("TRUSTGUARD_LOCAL_TEST_SERVICE_ID", "").strip()
            if local_service:
                if (os.environ.get("TRUSTGUARD_LOCAL_SANDBOX_DEMO", "").lower() != "true"
                        or not local_service.startswith("LOCAL-TEST-ONLY-PAYPAL-") or len(local_service) > 128):
                    raise ConfigurationError("synthetic service identity requires isolated LOCAL TEST ONLY mode")
                service = local_service
            elif tx.skyfire_service_id.startswith("LOCAL-TEST-ONLY-PAYPAL-"):
                raise ConfigurationError("synthetic service identity requires explicit local test configuration")
            if not service or source != service or tx.skyfire_service_id != service or merchant == service:
                raise ConfigurationError("Skyfire service to PayPal merchant mapping is missing or inconsistent")

    @classmethod
    def from_env(cls, trust_config: TrustConfig, *,
                 timeout: float | tuple[float, float] = (3.05, 15.0)) -> "PayPalRestOrdersProvider":
        if os.environ.get("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "").lower() != "true":
            raise ConfigurationError("PayPal Sandbox dispatch is disabled")
        client_id = os.environ.get("PAYPAL_CLIENT_ID", "")
        client_secret = os.environ.get("PAYPAL_CLIENT_SECRET", "")
        if not client_id or not client_secret:
            raise ConfigurationError("PayPal Sandbox credentials are missing")
        return cls(trust_config, timeout=timeout)

    @staticmethod
    def _provider_url(path: str) -> str:
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
            raise ConfigurationError("PayPal provider path is invalid")
        url = SANDBOX_BASE_URL.rstrip("/") + path
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            raise ConfigurationError("PayPal endpoint must be the verified Sandbox HTTPS origin") from None
        if (parsed.scheme != "https" or parsed.hostname != SANDBOX_HOST or port not in (None, 443)
                or parsed.path != path
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ConfigurationError("PayPal endpoint must be the verified Sandbox HTTPS origin")
        return url

    def _oauth_token(self) -> str:
        self._ensure_enabled()
        now = time.time()
        if self._access_token and now < self._access_token_expires_at - 30:
            return self._access_token
        try:
            response = self._session.post(
                self._provider_url(TOKEN_PATH),
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
        merchant = tx.paypal_merchant_id or tx.payee
        if not merchant or not isinstance(payee, dict) or payee.get("merchant_id") != merchant or not isinstance(amount, dict):
            return False
        if amount.get("currency_code") != tx.currency:
            return False
        try:
            returned_amount = Decimal(str(amount.get("value")))
        except (InvalidOperation, ValueError):
            return False
        if not returned_amount.is_finite() or returned_amount != tx.amount_decimal:
            return False

        # Bind the item list to the same canonical transaction authorized by
        # TrustGuard. This prototype has one fixed server-generated item and
        # does not accept payer-supplied names, quantities, prices, or currency.
        expected_total = f"{tx.amount_decimal:.2f}"
        items = unit.get("items")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            return False
        item = items[0]
        unit_amount = item.get("unit_amount")
        if (item.get("name") != "Authorized transaction" or item.get("quantity") != "1"
                or not isinstance(unit_amount, dict)
                or unit_amount.get("currency_code") != tx.currency):
            return False
        try:
            item_amount = Decimal(str(unit_amount.get("value")))
        except (InvalidOperation, ValueError):
            return False
        if not item_amount.is_finite() or item_amount != tx.amount_decimal:
            return False
        breakdown = amount.get("breakdown")
        item_total = breakdown.get("item_total") if isinstance(breakdown, dict) else None
        if (not isinstance(item_total, dict) or item_total.get("currency_code") != tx.currency
                or item_total.get("value") != expected_total):
            return False
        return True

    @staticmethod
    def _approval_url(body: Mapping[str, Any], order_id: str) -> str | None:
        links = body.get("links", [])
        if not isinstance(links, list):
            raise ProviderAmbiguousError("PayPal approval links were malformed", order_id)
        selected = [link for link in links if isinstance(link, dict) and link.get("rel") in {"approve", "payer-action"}]
        if not selected:
            return None
        if len(selected) != 1:
            raise ProviderAmbiguousError("PayPal approval links were ambiguous", order_id)
        href = selected[0].get("href")
        if not isinstance(href, str):
            raise ProviderAmbiguousError("PayPal approval URL was malformed", order_id)
        p = urlsplit(href)
        if (p.scheme != "https" or p.netloc != "www.sandbox.paypal.com"
                or p.path not in {"/checkoutnow", "/webapps/hermes"}
                or p.fragment or parse_qs(p.query).get("token") != [order_id]):
            raise ProviderAmbiguousError("PayPal approval URL was not a bound Sandbox URL", order_id)
        return href

    def create_order(self, tx: CanonicalTransaction) -> Mapping[str, Any]:
        """Create exactly one canonical order; ambiguity is surfaced, never retried."""
        if not isinstance(tx, CanonicalTransaction):
            raise ProviderDefinitiveError("a canonical authorized transaction is required")
        self._check_transaction_mapping(tx)
        payload = build_paypal_order_payload(tx)
        if self._callback_urls:
            payload["payment_source"] = {"paypal": {"experience_context": {**self._callback_urls, "user_action": "PAY_NOW"}}}
        token = self._oauth_token()
        try:
            response = self._session.post(
                self._provider_url(ORDERS_PATH),
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
        if status == "PAYER_ACTION_REQUIRED":
            status = "CREATED"
        if status in {"CREATED", "APPROVED"}:
            result = {"id": order_id, "status": status}
            approval_url = self._approval_url(body, order_id)
            if approval_url:
                result["approval_url"] = approval_url
            return result
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
        identifiers = set()
        for capture in captures:
            if not isinstance(capture, dict) or not isinstance(capture.get("id"), str) or not capture["id"] or capture.get("status") != "COMPLETED":
                return False
            if capture["id"] in identifiers:
                return False
            identifiers.add(capture["id"])
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
        self._check_transaction_mapping(tx)
        token = self._oauth_token()
        try:
            response = self._session.get(
                self._provider_url(ORDERS_PATH + "/" + quote(order_id, safe="")),
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
        if order_status == "PAYER_ACTION_REQUIRED":
            order_status = "CREATED"
        unit = body["purchase_units"][0]
        if order_status in {"CREATED", "APPROVED"}:
            return {"id": order_id, "status": order_status}
        if order_status == "COMPLETED":
            if self._capture_evidence_matches(tx, unit):
                return {"id": order_id, "status": "COMPLETED", "verified_capture": True,
                        "capture_ids": [capture["id"] for capture in unit["payments"]["captures"]]}
            return {"id": order_id, "status": "UNKNOWN"}
        if order_status == "VOIDED":
            payments = unit.get("payments") if isinstance(unit, dict) else None
            captures = payments.get("captures", []) if isinstance(payments, dict) else []
            if not any(isinstance(c, dict) and c.get("status") == "COMPLETED" for c in captures):
                return {"id": order_id, "status": "FAILED"}
        return {"id": order_id, "status": "UNKNOWN"}

    def capture_order(
        self,
        tx: CanonicalTransaction,
        order_id: str,
        request_id: str,
        *,
        ledger: Ledger,
    ) -> Mapping[str, Any]:
        """Consume a durable TrustGuard reservation and verify approval before POST.

        The provider GET independently binds the exact order to the canonical
        transaction and must report APPROVED immediately before capture. A verified
        COMPLETED GET is returned without another POST. This method never retries.
        """
        if (not isinstance(tx, CanonicalTransaction) or not (tx.paypal_merchant_id or tx.payee)
                or not isinstance(order_id, str) or not order_id
                or not isinstance(request_id, str) or not request_id
                or not isinstance(ledger, Ledger)):
            raise ProviderDefinitiveError("canonical transaction, stable order identity, and durable capture ledger are required")
        self._check_transaction_mapping(tx)
        if not ledger.claim_capture_dispatch(tx, order_id, request_id):
            raise ProviderDefinitiveError("a matching unused durable TrustGuard capture reservation is required")
        preflight = dict(self.get_order_details(tx, order_id))
        if preflight.get("id") != order_id:
            raise ProviderAmbiguousError("PayPal approval preflight did not confirm the expected order", order_id)
        if preflight.get("status") == "COMPLETED" and preflight.get("verified_capture") is True:
            return preflight
        if preflight.get("status") != "APPROVED":
            raise ProviderAmbiguousError("PayPal order is not freshly verified as APPROVED; capture was not sent", order_id)
        if not ledger.capture_dispatch_claim_valid(tx, order_id, request_id):
            raise ProviderDefinitiveError("durable capture reservation changed before dispatch")
        token = self._oauth_token()
        try:
            response = self._session.post(
                self._provider_url(ORDERS_PATH + "/" + quote(order_id, safe="") + "/capture"),
                json={},
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                         "Accept": "application/json", "Prefer": "return=representation",
                         "PayPal-Request-Id": request_id},
                timeout=self._timeout, allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise ProviderAmbiguousError("PayPal capture outcome is unknown", order_id) from exc
        if not 200 <= response.status_code < 300:
            # Already-captured conflicts and all rejected capture attempts require GET.
            # Never release reserved spend merely because a capture POST failed.
            raise ProviderAmbiguousError("PayPal capture needs reconciliation", order_id)
        try:
            body = response.json()
        except (ValueError, AttributeError) as exc:
            raise ProviderAmbiguousError("PayPal capture response was malformed", order_id) from exc
        if not isinstance(body, dict) or body.get("id") != order_id or body.get("status") != "COMPLETED":
            raise ProviderAmbiguousError("PayPal capture was not confirmed", order_id)
        details = dict(self.get_order_details(tx, order_id))
        if details.get("status") != "COMPLETED" or details.get("verified_capture") is not True:
            raise ProviderAmbiguousError("PayPal completed capture evidence was not verified", order_id)
        return details
