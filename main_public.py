"""Deprecated public entry point: legacy mock verification and dispatch are disabled.

The previous implementation accepted dictionary-shaped synthetic KYAPay/DPoP
objects, printed them as verified, initialized PayPal Toolkit on import, and
attempted an order during module import with capture enabled. Those behaviors
were not a valid security boundary and could create external side effects.

Use the signed verifier path in main.py only after official KYAPay issuer and
delegation contracts, merchant mapping, and provider behavior are confirmed.
This legacy module intentionally exposes a blocking compatibility function.
"""


def execute_safe_payment(agent, token_payload, dpop_proof, method, url, currency, items):
    """Fail closed; this deprecated module cannot authorize external orders."""
    return {
        "status": "BLOCKED",
        "reason": (
            "Legacy mock verification disabled: signed KYAPay/DPoP validation "
            "and the official issuer contract are not established in this module."
        ),
    }


def main():
    print("[TrustGuard] Legacy public demo disabled; no PayPal toolkit is initialized.")
    print("[TrustGuard] No order or capture was attempted.")
    print("[TrustGuard] Run mock-only regression tests and resolve SECURITY_STATUS.md blockers.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
