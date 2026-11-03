# PayPal AI Trust Engine — TrustGuard prototype

TrustGuard is a security-focused prototype for authorization checks around AI-initiated payment orders. The current implementation is **fail-closed**: importing or running `main_public.py` makes no network calls, initializes no PayPal client, and creates no order. Real provider dispatch is disabled by default. The only provider included for automated tests is `MockProvider`.

## Security status and scope

The repository does not define an authoritative KYAPay grant claim schema or a trusted issuer/key contract. `TrustConfig` therefore requires explicit issuer, audience, trusted public keys, and the names of authenticated grant fields. Do not infer a grant identity from `sub`, `jti`, or a caller-supplied `grant_id`. Until the issuer publishes/configures a compatible signed grant claim contract and keys, authorization must remain unavailable.

The backend verifies signed JWT access tokens with a configured key ID and algorithm allowlist, verifies signed DPoP proofs and request binding, checks the DPoP key thumbprint and access-token hash, persists replay identifiers in SQLite, and atomically reserves grant spending. SQLite reservations treat `RESERVED`, dispatch-started, unresolved `UNKNOWN`, and created orders as spent/reserved. No automatic retry is performed for an ambiguous provider outcome.

An order-created response is not a captured payment. The implementation represents only an order creation result; it does not capture funds or claim payment success. There is no production PayPal provider adapter enabled by this project. The order payload builder is isolated and testable without making requests.

## Requirements and tests

Use Python 3.10+ and install dependencies in an isolated environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
pytest -q
```

The test suite generates local ephemeral signing keys and uses only temporary SQLite files and a mock provider. It does not require PayPal credentials, access the network, or call PayPal. Running `python main_public.py` only prints a fail-closed status message.

## Explicit trust configuration

Before constructing `TrustConfig.from_env()`, provide these settings through a secure environment/configuration mechanism:

- `TRUSTGUARD_ISSUER`: exact trusted JWT issuer.
- `TRUSTGUARD_AUDIENCE`: expected audience.
- `TRUSTGUARD_JWT_PUBLIC_KEYS_JSON`: JSON object mapping trusted `kid` values to public-key PEM strings.
- `TRUSTGUARD_JWT_ALGORITHMS`: comma-separated allowlist; supported values are `RS256`, `ES256`, or `EdDSA` (default `ES256`).
- `TRUSTGUARD_GRANT_ID_FIELD`: explicit field name inside the authenticated configured grant claim that identifies the grant.
- `TRUSTGUARD_GRANT_LIMIT_FIELD`: explicit grant field containing the maximum spend in integer minor units.
- `TRUSTGUARD_GRANT_CURRENCY_FIELD`: explicit grant currency field.
- `TRUSTGUARD_GRANT_PAYEES_FIELD`: explicit grant field containing the authorized payee identifiers as a list.

The default authenticated grant claim name is `delegation_grant`; a different contract requires configuring `token_grant_claim` explicitly in trusted application code. These names are configuration inputs, not assertions that the external KYAPay contract uses them. Missing trust or grant-field configuration fails closed. Amounts are parsed as `Decimal`; supported currencies are configured in `TrustConfig` and default to USD only.

The SQLite database path must be managed as durable application data and protected with appropriate filesystem permissions, backup, and operational recovery. For production use, additional operational controls such as key rotation, migrations, monitoring, and reconciliation are required.

## Important limitations before a real integration

- No actual PayPal provider integration or provider reconciliation is enabled. Do not turn on dispatch until a reviewed adapter, idempotency semantics, and UNKNOWN reconciliation procedure exist.
- The authenticated grant claim field names and semantics must be supplied from the issuer's verified contract; they are deliberately not guessed here.
- Authorization field values, including integer minor-unit maximum spend and payee identifiers, must match the issuer contract exactly.
- The example public dashboard is static demo UI, not a live backend or transaction evidence source. It labels controls as unverified by the demo and never represents sample values as verified PayPal success.
- The previous synthetic transaction references and “100% security” statistics have been removed.

## Dashboard

Open `dashboard_v2.html` using a local static file server if required by the browser. It labels itself **DEMO / SIMULATED**, does not claim security controls are operational, distinguishes `UNKNOWN`, and renders data via DOM text nodes rather than HTML interpolation. `hasil.json` contains no fabricated successful order or transaction statistics.

## Repository files

- `trustguard.py`: signed-token and DPoP verification, canonical transaction, SQLite ledger/state machine, payload builder, and mock-only dispatch boundary.
- `main_public.py`: harmless fail-closed entry point; no import-time provider setup.
- `tests/test_trustguard.py`: local security and persistence tests.
- `dashboard_v2.html`, `hasil.json`: explicitly simulated static dashboard.
