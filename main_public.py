"""Safe entry point for PayPal AI Trust Engine.

Importing this module performs no network calls and creates no orders.
No issuer trust material is bundled: configure it from the official KYAPay issuer.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Mapping

from trustguard_security import (
    PaymentResult,
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
    )
    if not dpop.allowed:
        return PaymentResult("PASSED", "FAILED", "NOT_ATTEMPTED", dpop.reason)

    policy = authorize_delegated_transaction(auth.claims, transaction, replay_store)
    if not policy.allowed:
        return PaymentResult("PASSED", "FAILED", "NOT_ATTEMPTED", policy.reason)

    if paypal_api is None:
        return PaymentResult("PASSED", "PASSED", "NOT_ATTEMPTED", "No PayPal adapter supplied.")

    # Build the outbound order amount/currency from the same checked canonical object.
    amount = Decimal(str(transaction["amount"]))
    currency = str(transaction["currency"])
    merchant_id = str(transaction["merchant"])
    params = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "payee": {"merchant_id": merchant_id},
            "amount": {"currency_code": currency, "value": format(amount, ".2f")},
            "description": str(transaction.get("description", "Authorized transaction")),
        }],
    }
    try:
        paypal_api.run(method="create_order", params=params)
        return PaymentResult("PASSED", "PASSED", "SUCCEEDED", "PayPal create_order returned successfully.")
    except Exception:
        # Do not return raw provider exceptions or secrets to callers.
        return PaymentResult("PASSED", "PASSED", "FAILED", "PayPal order creation failed; provider details were redacted.")


def main() -> int:
    print("PayPal AI Trust Engine: safe entry point loaded.")
    print("No payment was sent. Configure official KYAPay issuer trust material before processing requests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
