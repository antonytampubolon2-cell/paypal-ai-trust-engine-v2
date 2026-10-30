# Security hardening status — review required

This branch is a defensive prototype, not production-ready. No live payment or capture is authorized by this document.

## Implemented on this branch

- Removed import-time PayPal toolkit initialization and the placeholder assignments that overwrote `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET`.
- Added a signed-JWT verification adapter that fails closed unless the operator supplies `KYAPAY_ISSUER`, `KYAPAY_AUDIENCE`, `KYAPAY_PUBLIC_KEY_PEM`, and `KYAPAY_JWT_ALGORITHM`.
- Added signed DPoP JWT verification, public-JWK thumbprint binding, `htm`, canonical HTTPS `htu`, `iat`, `jti`, and access-token `ath` checks.
- Added SQLite atomic replay claims and transaction policy checks for allowed merchant, amount, currency, grant expiry, and token expiry.
- Separated authentication, policy, and delivery outcomes in `PaymentResult`.
- Added negative regression tests and a GitHub Actions test workflow. The tests use explicitly synthetic, ephemeral test fixtures only; they do not establish a real KYAPay issuer or production trust relationship.

## Critical blockers — do not enable payment dispatch

1. **KYAPay issuer contract is not present in the repository.** The project does not provide authoritative issuer documentation, token format, algorithm policy, JWKS endpoint/key rotation policy, or a trusted issuer public key. The JWT adapter is only a fail-closed integration boundary. Obtain and verify these details from the real issuer before configuring it. Do not use test fixtures in deployment.
2. **Delegation schema is unconfirmed.** The code expects `delegation_grant.allowed_merchants`, `max_spend`, `currency`, and numeric `valid_until`. These field names and semantics must be confirmed against the issuer's signed schema.
3. **PayPal merchant mapping is unconfirmed.** The adapter maps the allowlisted `transaction.merchant` to PayPal `purchase_units[].payee.merchant_id`. Verify that the issuer's merchant identifier is the exact PayPal merchant ID expected by the official Orders API before using a real adapter.
4. **No production replay-store deployment is configured.** SQLite provides atomic claims on a single host with a persistent database. Multi-host deployments require a shared store with an atomic insert-if-absent operation and defined availability/retention behavior.
5. **No official end-to-end integration has been run.** Only tests with synthetic cryptographic fixtures and mocked API adapters are permitted at this stage. No PayPal request, order creation, or capture should be performed during verification.
6. **RFC 9449 conformance needs issuer/client integration review.** The verifier implements core signature and binding checks but does not yet establish conformance against a full interoperability test suite or every deployment-specific replay/nonce policy.

## Test procedure

Install dependencies from `requirements-security.txt`, then run:

```sh
python -m unittest -v security_tests
```

The tests must pass in CI before review. A passing synthetic test suite does not resolve the issuer/schema/merchant/replay-store blockers above.
