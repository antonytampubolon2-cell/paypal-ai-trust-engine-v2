"""Safe entry point for PayPal AI Trust Engine.

Importing this module performs no network calls and creates no orders.
No issuer trust material is bundled: configure it from the official KYAPay issuer.
"""
from __future__ import annotations

from typing import Any, Mapping

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
) -> PaymentResult:
    """Fail closed through authentication, DPoP, policy, then order creation only.

    Legacy result fields remain available. Explicit status fields independently
    report authentication, DPoP, authorization, order creation, and capture.
    This function never captures a payment.
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
    try:
        response = paypal_api.run(method="create_order", params=params)
        if not isinstance(response, Mapping) or not isinstance(response.get("id"), str) or not response["id"]:
            return result("PASSED", "PASSED", "PASSED", "UNKNOWN", "PayPal adapter returned no verifiable order identifier.")
        return result(
            "PASSED", "PASSED", "PASSED", "ORDER_CREATED",
            "PayPal order was created; capture was not attempted and payment is not confirmed.",
        )
    except Exception:
        # A timeout or transport error may occur after the provider accepted the
        # request. Without a verified idempotency/reconciliation contract, report
        # an ambiguous outcome and never imply that no order was created.
        return result("PASSED", "PASSED", "PASSED", "UNKNOWN", "PayPal order outcome is unknown; provider details were redacted. Do not retry automatically.")


def main() -> int:
    print("PayPal AI Trust Engine: safe entry point loaded.")
    print("No payment was sent. Configure official KYAPay issuer trust material before processing requests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
