"""Safe entry point for PayPal AI Trust Engine.

Importing this module performs no network calls and creates no orders.
No issuer trust material is bundled: configure it from the official KYAPay issuer.
"""
from __future__ import annotations

from typing import Any, Mapping
import math
import time

from trustguard_security import (
    PaymentResult,
    CanonicalTransaction,
    canonicalize_transaction,
    ReplayStore,
    authenticate_kyapay_jwt,
    authorize_delegated_transaction,
    verify_dpop_proof,
)
from paypal_rest import RestItemValidationError, normalize_rest_items
from spend_reservations import SQLiteSpendReservationStore


def process_payment_request(
    *,
    compact_token: str,
    compact_dpop_proof: str,
    transaction: Mapping[str, Any],
    replay_store: ReplayStore,
    paypal_api: Any | None = None,
    expected_method: str = "POST",
    expected_url: str,
    merchant_mapping: Mapping[str, str] | None = None,
    rest_items: list[Mapping[str, Any]] | None = None,
    spend_reservation_store: SQLiteSpendReservationStore | None = None,
    grant_id: str | None = None,
    reservation_idempotency_key: str | None = None,
    reservation_ttl_seconds: int = 300,
) -> PaymentResult:
    """Fail closed through authentication, DPoP, policy, then order creation only.

    Legacy result fields remain available. Explicit status fields independently
    report authentication, DPoP, authorization, order creation, and capture.
    This function never captures a payment. Provider dispatch additionally requires
    a durable spend reservation keyed by an authoritative grant id and stable request key.
    """
    def result(auth: str, dpop: str, authorization: str, order: str, reason: str) -> PaymentResult:
        return PaymentResult(
            authentication_status=auth,
            policy_status=authorization,
            delivery_status=order,
            reason=reason,
            dpop_status=dpop,
            authorization_status=authorization,
            order_status=order,
            capture_status="NOT_ATTEMPTED",
        )

    auth = authenticate_kyapay_jwt(compact_token)
    if not auth.authenticated or auth.claims is None:
        return result("FAILED", "NOT_RUN", "NOT_RUN", "NOT_ATTEMPTED", auth.reason)

    try:
        dpop = verify_dpop_proof(
            compact_dpop_proof,
            expected_method=expected_method,
            expected_url=expected_url,
            replay_store=replay_store,
            access_token_claims=auth.claims,
            access_token=compact_token,
        )
    except Exception:
        # Storage/verification failures must not escape into a dispatch path.
        return result("PASSED", "FAILED", "NOT_RUN", "NOT_ATTEMPTED", "DPoP verification or replay storage failed closed.")
    if not dpop.allowed:
        return result("PASSED", "FAILED", "NOT_RUN", "NOT_ATTEMPTED", dpop.reason)

    # Validate once, then carry the frozen canonical object through policy and payload.
    try:
        canonical = canonicalize_transaction(transaction, merchant_mapping=merchant_mapping or {})
    except (ValueError, TypeError):
        return result("PASSED", "PASSED", "FAILED", "NOT_ATTEMPTED", "Transaction validation failed closed.")

    try:
        policy = authorize_delegated_transaction(auth.claims, canonical, replay_store)
    except Exception:
        return result("PASSED", "PASSED", "FAILED", "NOT_ATTEMPTED", "Authorization or replay storage failed closed.")
    if not policy.allowed:
        return result("PASSED", "PASSED", "FAILED", "NOT_ATTEMPTED", policy.reason)

    if paypal_api is None:
        return result("PASSED", "PASSED", "PASSED", "NOT_ATTEMPTED", "No PayPal adapter supplied.")

    # The exact immutable canonical object checked by policy supplies the payload.
    purchase_unit = {
        "payee": {"merchant_id": canonical.paypal_merchant_id},
        "amount": {"currency_code": canonical.currency, "value": canonical.amount_text},
        "description": canonical.description,
    }
    if rest_items is not None:
        try:
            normalized_items, items_total = normalize_rest_items(
                rest_items, currency=canonical.currency, approved_amount=canonical.amount
            )
        except RestItemValidationError:
            return result(
                "PASSED", "PASSED", "FAILED", "NOT_ATTEMPTED",
                "PayPal line items do not match the approved transaction.",
            )
        purchase_unit["items"] = normalized_items
        purchase_unit["amount"]["breakdown"] = {
            "item_total": {
                "currency_code": canonical.currency,
                "value": canonical.amount_text,
            }
        }
    params = {"intent": "AUTHORIZE", "purchase_units": [purchase_unit]}

    # Do not call a generic adapter that cannot explicitly bind the stable request
    # key to PayPal's provider idempotency contract. This is a local adapter
    # interface; a real implementation must map request_id to PayPal-Request-Id.
    create_order_idempotently = getattr(paypal_api, "create_order_with_idempotency", None)
    if not callable(create_order_idempotently):
        return result(
            "PASSED", "PASSED", "PASSED", "NOT_ATTEMPTED",
            "PayPal adapter lacks the explicit provider-idempotency contract; dispatch failed closed.",
        )
    if not isinstance(reservation_idempotency_key, str) or not reservation_idempotency_key or len(reservation_idempotency_key) > 108:
        return result("PASSED", "PASSED", "PASSED", "NOT_ATTEMPTED", "Provider idempotency key is invalid.")

    # The issuer's grant identifier is not inferred from an unconfirmed claim name.
    # The integration layer must supply a stable authoritative identifier and
    # stable caller idempotency key. Without both, payment dispatch is disabled.
    if spend_reservation_store is None or not grant_id or not reservation_idempotency_key:
        return result(
            "PASSED", "PASSED", "PASSED", "NOT_ATTEMPTED",
            "Atomic cumulative-spend reservation is not configured; provider dispatch failed closed.",
        )
    if isinstance(reservation_ttl_seconds, bool) or not isinstance(reservation_ttl_seconds, int) or reservation_ttl_seconds < 1:
        return result("PASSED", "PASSED", "PASSED", "NOT_ATTEMPTED", "Reservation lease configuration is invalid.")

    grant = auth.claims.get("delegation_grant")
    token_exp = auth.claims.get("exp")
    grant_exp = grant.get("valid_until") if isinstance(grant, Mapping) else None
    if (
        not isinstance(grant, Mapping)
        or isinstance(token_exp, bool) or not isinstance(token_exp, (int, float)) or not math.isfinite(token_exp)
        or isinstance(grant_exp, bool) or not isinstance(grant_exp, (int, float)) or not math.isfinite(grant_exp)
    ):
        return result("PASSED", "PASSED", "PASSED", "NOT_ATTEMPTED", "Grant expiry evidence is invalid; reservation denied.")
    now = time.time()
    reservation_expires_at = min(float(token_exp), float(grant_exp), now + reservation_ttl_seconds)
    try:
        reservation = spend_reservation_store.reserve(
            grant_id=grant_id,
            max_spend=grant.get("max_spend"),
            amount=canonical.amount,
            currency=canonical.currency,
            idempotency_key=reservation_idempotency_key,
            expires_at=reservation_expires_at,
            now=now,
        )
        if reservation.status != "RESERVED":
            return result("PASSED", "PASSED", "PASSED", "NOT_ATTEMPTED", "Existing reservation is not dispatchable.")
        if reservation.dispatch_started:
            # A prior invocation may have reached the provider before crashing or
            # timing out. Do not retry, even with the same idempotency key, until
            # an authorized reconciliation process establishes the outcome.
            return result("PASSED", "PASSED", "PASSED", "UNKNOWN", "A prior dispatch attempt is recorded; no automatic retry was performed. Reconciliation is required.")
        spend_reservation_store.mark_dispatch_started(reservation.reservation_id)
    except Exception as exc:
        # The store is part of the security boundary; any storage or policy error
        # prevents the outbound provider request. Expose only the exception class,
        # never database paths, SQL, credentials, or provider details.
        return result("PASSED", "PASSED", "PASSED", "NOT_ATTEMPTED", f"Atomic spend reservation failed closed ({type(exc).__name__}).")

    try:
        response = create_order_idempotently(params=params, request_id=reservation_idempotency_key)
        if not isinstance(response, Mapping) or not isinstance(response.get("id"), str) or not response["id"]:
            spend_reservation_store.mark_unknown(reservation.reservation_id)
            return result("PASSED", "PASSED", "PASSED", "UNKNOWN", "PayPal adapter returned no verifiable order identifier; reconciliation is required.")
        try:
            spend_reservation_store.record_order_created(reservation.reservation_id, order_id=response["id"])
        except Exception:
            try:
                spend_reservation_store.mark_unknown(reservation.reservation_id)
            except Exception:
                pass  # The persisted dispatch-started reservation still consumes the grant budget.
            return result("PASSED", "PASSED", "PASSED", "UNKNOWN", "Order response was received but evidence persistence failed; reconciliation is required.")
        return result(
            "PASSED", "PASSED", "PASSED", "ORDER_CREATED",
            "PayPal order was created; spend remains reserved. Capture was not attempted and payment is not confirmed.",
        )
    except Exception:
        # The provider may have accepted the request before the transport failed.
        # Keep the reservation and prohibit automatic retries pending reconciliation.
        try:
            spend_reservation_store.mark_unknown(reservation.reservation_id)
        except Exception:
            pass  # Reservation was durably marked dispatch-started before provider I/O.
        return result("PASSED", "PASSED", "PASSED", "UNKNOWN", "PayPal order outcome is unknown; spend remains reserved. Do not retry automatically.")


def main() -> int:
    print("PayPal AI Trust Engine: safe entry point loaded.")
    print("No payment was sent. Configure official KYAPay issuer trust material before processing requests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
