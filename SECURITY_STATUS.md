# Security hardening status — review required

This branch is a defensive prototype, not production-ready. No live payment, Sandbox order, or capture is authorized by this document.

## Implemented on this branch

- Fail-closed signed-JWT verification adapter requiring explicit issuer, audience, public key, and algorithm configuration.
- DPoP JWT signature and public-JWK binding checks, method/target/time/token-hash checks, and proof-JTI replay claims.
- SQLite replay claims using an atomic insert within a transaction, with expiration cleanup. This is persistent only when the database file itself is on persistent storage and is suitable for a single host/shared local filesystem—not multi-instance distributed protection.
- Canonical immutable transaction objects used for both authorization checks and the outbound order payload.
- Independent result fields for authentication, DPoP, authorization, order creation, and capture. Legacy `policy_status` and `delivery_status` remain available for callers.
- Capture status is always `NOT_ATTEMPTED`; this dispatcher only calls `create_order` and does not capture.
- Synthetic regression tests use ephemeral signing keys, a local replay database, and a mocked PayPal adapter. Passing tests prove code behavior against those fixtures, not production integration.

## Critical blockers — do not enable production payment dispatch

1. **KYAPay issuer contract is absent.** No authoritative token format, issuer metadata, signing policy, JWKS/key-rotation policy, trusted issuer key, required nonce policy, or signed delegation schema is supplied. The adapter is a fail-closed integration boundary, not proof of official KYAPay interoperability.
2. **Delegation schema is unconfirmed.** The code expects `delegation_grant.allowed_merchants`, `max_spend`, `currency`, and numeric `valid_until`. These names and semantics must be confirmed against the issuer's signed schema.
3. **PayPal merchant mapping is unconfirmed.** The internal merchant-to-`purchase_units[].payee.merchant_id` mapping is injected configuration. Synthetic test IDs are not evidence of an actual merchant account or official mapping.
4. **Replay-store deployment is not configured for production.** SQLite atomically rejects duplicate namespace/JTI pairs and survives reinitialization when the same persistent file is reused. It is not distributed protection across independent hosts or ephemeral filesystems. Store failures must fail closed before order creation.
5. **Cumulative delegation spend is not protected.** The current `max_spend` check is per transaction. There is no atomic cumulative ledger/reservation spanning concurrent transactions, order failures, and retries. Do not describe this as a cumulative grant budget.
6. **Order idempotency is not implemented.** A provider timeout or ambiguous response followed by a retry could create a second order. No idempotency guarantee is claimed; do not automatically retry order creation without a verified provider idempotency contract and stable request key.
7. **No official end-to-end integration has been run.** Tests use synthetic cryptographic fixtures and a mock. No real or Sandbox order or capture was performed for verification.
8. **Protocol conformance remains unverified.** The DPoP verifier implements core signature/binding checks, but has not passed a full RFC 9449 interoperability suite. URI canonicalization, nonce requirements, key rotation, and issuer/client-specific rules require an authoritative integration review.

## Transaction result contract

- `authentication_status`: token authentication result.
- `dpop_status`: DPoP verification result.
- `authorization_status`: delegation/policy decision.
- `order_status`: `NOT_ATTEMPTED`, `FAILED`, `UNKNOWN`, or `ORDER_CREATED`.
- `capture_status`: always `NOT_ATTEMPTED` in this implementation.
- Compatibility fields `policy_status` and `delivery_status` remain available; `delivery_status` mirrors `order_status`.

`ORDER_CREATED` means only that the injected adapter returned a non-empty order identifier. It is not evidence of capture, settlement, fulfillment, or payment completion.

## Test procedure

Install dependencies from `requirements-security.txt`, then run:

```sh
python -m unittest -v security_tests
python -m unittest -v frontend_tests
python -m unittest -v frontend_browser_tests
python -m unittest -v pages_artifact_tests
python -m unittest -v workflow_validation_tests
```

A passing synthetic test suite does not resolve the issuer/schema/merchant/replay-store/cumulative-spend/idempotency blockers above.
