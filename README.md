# PayPal AI Trust Engine — TrustGuard prototype

TrustGuard is a fail-closed prototype for evaluating AI-initiated payment-order requests. Importing or running `main_public.py` makes no network calls and initializes no PayPal client. A separate PayPal REST Orders v2 adapter is available for the **Sandbox endpoint only**; it is disabled unless `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true` is explicitly set. The project does not contain a live-production endpoint or provider adapter.

## Security and transaction behavior

`TrustConfig` requires an explicitly trusted issuer, audience, key set, and configured authenticated grant-field names. The repository does not define the external KYAPay grant contract; the field names must come from its verified issuer contract and are not inferred from `sub`, `jti`, or a request-supplied `grant_id`. Missing issuer, audience, keys, or grant configuration fails closed.

The backend verifies signed access JWTs and DPoP proofs, binds DPoP to the access token and request, persists replay identifiers and spend reservations in SQLite, and atomically records `DISPATCH_STARTED` before a provider call. The provider payload is generated only from the canonical transaction object that has passed grant authorization and been reserved. The order request includes the same canonical idempotency key in `PayPal-Request-Id`.

The adapter uses OAuth2 Client Credentials and a fixed host of `https://api-m.sandbox.paypal.com`; redirects are disabled and connect/read timeouts are configured. Credentials are read from `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET` and are never logged. The adapter exposes Orders v2 create and GET-by-order-ID reconciliation. It does not issue capture requests.

Local transaction states are `CREATED`, `APPROVED`, `COMPLETED`, `FAILED`, and `UNKNOWN`, along with reservation/dispatch-in-progress states. An order-create response is never treated as a completed payment. `COMPLETED` is only allowed after GET reconciliation confirms a matching order, payee, currency, and amount and provides completed capture records whose amounts total the canonical amount. An ambiguous create timeout is kept `UNKNOWN`; the adapter does not automatically repeat creation. If no order ID was received, the record needs manual/provider-side investigation because GET-by-order-ID cannot locate it. Unknown/reconciliation failures remain unresolved and reserved against grant spend.

## Requirements and local tests

Use Python 3.10+ in an isolated environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
pytest -q
```

The tests use fake HTTP sessions/responses, ephemeral local signing keys, temporary SQLite databases, and `MockProvider`. They do not send HTTP requests to PayPal and do not require PayPal credentials. Running `python main_public.py` only prints a fail-closed message.

## Required trust configuration

Load these values through a secure environment/configuration service before calling `TrustConfig.from_env()`:

- `TRUSTGUARD_ISSUER`: exact trusted JWT issuer.
- `TRUSTGUARD_AUDIENCE`: expected audience.
- `TRUSTGUARD_JWT_PUBLIC_KEYS_JSON`: JSON object mapping trusted JWT `kid` values to public-key PEM strings.
- `TRUSTGUARD_JWT_ALGORITHMS`: comma-separated allowlist (`RS256`, `ES256`, or `EdDSA`; default `ES256`).
- `TRUSTGUARD_GRANT_ID_FIELD`: authenticated grant field containing its canonical identity.
- `TRUSTGUARD_GRANT_LIMIT_FIELD`: authenticated maximum spend in integer minor units.
- `TRUSTGUARD_GRANT_CURRENCY_FIELD`: authenticated currency field.
- `TRUSTGUARD_GRANT_PAYEES_FIELD`: authenticated list of allowed payee identifiers.

The default grant claim name is `delegation_grant`. A different issuer contract requires explicit configuration in trusted application code. These names and semantics must be confirmed against the issuer contract; the project does not assert that KYAPay uses them. Supported transaction currency defaults to USD.

## Enabling the Sandbox adapter

The Sandbox adapter requires the trust configuration above, both PayPal Sandbox credentials, and an explicit opt-in:

- `PAYPAL_CLIENT_ID`
- `PAYPAL_CLIENT_SECRET`
- `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true`

The adapter can be initialized in trusted application code as follows:

```python
trust = TrustConfig.from_env()
ledger = Ledger("/secure/durable/path/trustguard.sqlite")
provider = PayPalRestOrdersProvider.from_env(trust)
guard = TrustGuard(trust, ledger, provider)
```

The environment switch is checked during initialization and again before provider requests. Do not set it in CI or local tests; all automated HTTP behavior is mocked. Keep the database path private and durable. SQLite files are created owner-only, but deployments must also protect the containing directory, backups, and host.

Use `guard.reconcile(local_transaction_id)` to GET a previously recorded PayPal order and reconcile its state. Reconciliation does not create or redispatch orders. An `UNKNOWN` record without a PayPal order ID cannot be reconciled through GET-by-ID and must remain unresolved pending manual investigation.

## Remaining integration limitations

- Configure the actual KYAPay issuer/key/grant contract before accepting requests; this repository intentionally does not invent it.
- The adapter is Sandbox-only and uses the test endpoint. It must not be adapted to production without a separate review and explicit production-safety design.
- The code does not expose an HTTP server, application authentication boundary, job runner, or PayPal webhook consumer. Integrators must ensure that only trusted application code can construct canonical transactions and invoke dispatch/reconciliation.
- No automatic retry is allowed for `UNKNOWN`. Provider-side investigation may still be needed when the original response did not include an order ID.
- Order creation does not capture funds. Only a matching completed capture in the authenticated PayPal GET response can establish `COMPLETED` in the local state machine.
- The static dashboard is demo-only and not a live backend evidence source; it makes no claims that the controls are operational.

## Dashboard and files

`dashboard_v2.html` and `hasil.json` are explicitly simulated UI content, not PayPal transaction evidence. Untrusted JSON values are rendered using DOM text nodes.

- `trustguard.py`: token/DPoP verification, canonical transaction, durable ledger, dispatch state machine, and mock provider.
- `paypal_rest.py`: Sandbox-only PayPal Orders v2 OAuth/REST adapter and GET reconciliation.
- `main_public.py`: safe fail-closed entry point.
- `tests/`: local security, ledger, provider HTTP-mock, and reconciliation tests.
