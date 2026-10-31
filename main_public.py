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
) -> PaymentResult:
    """Authenticate, authorize, and optionally dispatch the exact checked transaction.

    The transaction must be a canonical mapping with merchant, amount and currency.
    The PayPal adapter is injected by the caller, so tests can use a mock and imports
    never trigger a payment side effect. Delivery success is reported separately.
    """
    auth = authenticate_kyapay_jwt(compact_token)
    if not auth.authenticated or auth.claims is None:
        return PaymentResult("FAILED", "NOT_RUN", "NOT_ATTEMPTED", auth.reason)

    dpop = verify_dpop_proof(
        compact_dpop_proof,
        expected_method=expected_method,
        expected_url=expected_url,
        replay_store=replay_store,
        access_token_claims=auth.claims,
        access_token=compact_token,
    )
    if not dpop.allowed:
        return PaymentResult("PASSED", "FAILED", "NOT_ATTEMPTED", dpop.reason)

    # Validate once, then carry the frozen canonical object through policy and payload.
    try:
        canonical = canonicalize_transaction(transaction, merchant_mapping=merchant_mapping or {})
    except (ValueError, TypeError):
        return PaymentResult("PASSED", "FAILED", "NOT_ATTEMPTED", "Transaction validation failed closed.")

    policy = authorize_delegated_transaction(auth.claims, canonical, replay_store)
    if not policy.allowed:
        return PaymentResult("PASSED", "FAILED", "NOT_ATTEMPTED", policy.reason)

    if paypal_api is None:
        return PaymentResult("PASSED", "PASSED", "NOT_ATTEMPTED", "No PayPal adapter supplied.")

    # Build the outbound order amount/currency from the same checked canonical object.
    params = {
        "intent": "AUTHORIZE",
        "purchase_units": [{
            "payee": {"merchant_id": canonical.paypal_merchant_id},
            "amount": {"currency_code": canonical.currency, "value": canonical.amount_text},
            "description": canonical.description,
        }],
    }
    try:
        response = paypal_api.run(method="create_order", params=params)
        if not isinstance(response, Mapping) or not isinstance(response.get("id"), str) or not response["id"]:
            return PaymentResult("PASSED", "PASSED", "UNKNOWN", "PayPal adapter returned no verifiable order identifier.")
        return PaymentResult("PASSED", "PASSED", "ORDER_CREATED", "PayPal order was created; this does not mean payment was captured or completed.")
    except Exception:
        # Do not return raw provider exceptions or secrets to callers.
        return PaymentResult("PASSED", "PASSED", "FAILED", "PayPal order creation failed; provider details were redacted.")


def main() -> int:
    print("PayPal AI Trust Engine: safe entry point loaded.")
    print("No payment was sent. Configure official KYAPay issuer trust material before processing requests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
