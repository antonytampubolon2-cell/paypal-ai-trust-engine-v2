# PayPal AI Trust Engine — TrustGuard prototype

TrustGuard is a fail-closed prototype for authorization checks around AI-initiated payment orders. Importing or running `main_public.py` makes no network calls and initializes no PayPal client. A REST Orders v2 adapter exists for the **PayPal Sandbox endpoint only**. Provider use remains disabled unless `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true` is explicitly set; this project contains no live-production endpoint.

## Transaction and ledger safety

SQLite writes use explicit transactions, `BEGIN IMMEDIATE` for serialized reservations and state changes, a 10-second busy timeout, `synchronous=FULL`, and owner-only database-file permissions. Reservations, idempotency identity, state, and provider order ID survive process restarts. The cumulative spend query and insert run inside the same write transaction. Unresolved `UNKNOWN` and in-flight records remain reserved against spending.

Before the provider is invoked, the transition to `DISPATCH_STARTED` must commit. A database error aborts the request before the provider call. Once dispatch has started, duplicate invocations do not call create again; `CREATED`, `APPROVED`, `COMPLETED`, `FAILED`, `DISPATCH_STARTED`, and `UNKNOWN` states are not automatically redispatched. Provider timeouts and ambiguous results persist as `UNKNOWN`. `guard.reconcile(local_transaction_id)` performs a provider GET only for a record with a saved PayPal order ID; it never creates or retries an order.

The adapter builds the Orders v2 body solely from the authorized canonical transaction and sends its idempotency key as `PayPal-Request-Id`. An order creation response is not payment completion. Only a GET response with matching order, reference, payee, amount, currency, and completed capture records totaling the authorized amount can transition the ledger to `COMPLETED`. No capture endpoint is implemented.

## Exact environment variables

The following values are read by the current implementation. The issuer and grant-claim values must come from the actual trusted KYAPay/authorization contract. **Do not substitute examples, invent values, or run with guessed trust settings.** If required trust configuration is missing, `TrustConfig.from_env()` fails closed.

| Variable | Requirement | Purpose |
|---|---|---|
| `TRUSTGUARD_ISSUER` | Required for `TrustConfig.from_env()` | Exact trusted issuer value used to validate JWT `iss`. Obtain from the trusted issuer configuration. |
| `TRUSTGUARD_AUDIENCE` | Required for `TrustConfig.from_env()` | Expected JWT audience. Obtain from the trusted application/issuer contract. |
| `TRUSTGUARD_JWT_PUBLIC_KEYS_JSON` | Required for `TrustConfig.from_env()` | JSON object mapping trusted JWT `kid` values to public-key PEM strings. Supply only issuer-verified public keys, never private keys. |
| `TRUSTGUARD_JWT_ALGORITHMS` | Optional; defaults to `ES256` | Comma-separated JWT algorithm allowlist. Supported by the current code: `RS256`, `ES256`, `EdDSA`. Configure to match the trusted issuer’s actual signing contract. |
| `TRUSTGUARD_GRANT_ID_FIELD` | Required for `TrustConfig.from_env()` | Field name inside the authenticated grant claim that the issuer defines as the canonical grant identity. |
| `TRUSTGUARD_GRANT_LIMIT_FIELD` | Required for `TrustConfig.from_env()` | Field name inside the authenticated grant claim for the maximum spending limit, represented in integer minor units (for USD, cents). |
| `TRUSTGUARD_GRANT_CURRENCY_FIELD` | Required for `TrustConfig.from_env()` | Field name inside the authenticated grant claim for its currency. |
| `TRUSTGUARD_GRANT_PAYEES_FIELD` | Required for `TrustConfig.from_env()` | Field name inside the authenticated grant claim containing allowed payee identifiers as a list. |
| `PAYPAL_CLIENT_ID` | Required to construct the PayPal Sandbox adapter | PayPal **Sandbox** application client ID. Load via a local secret manager or protected environment, not source code or shell history. |
| `PAYPAL_CLIENT_SECRET` | Required to construct the PayPal Sandbox adapter | PayPal **Sandbox** application secret. Treat as confidential and never print, commit, or place in a shared log. |
| `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX` | Required to enable adapter; must equal `true` | Explicit opt-in gate checked when constructing the adapter and before OAuth/provider requests. Keep `false` for local tests and ordinary development. |

The grant claim name currently defaults in code to `delegation_grant`; it is not an environment variable. If the issuer uses another claim name, trusted application code must pass that documented value as `token_grant_claim`. The repository does not define KYAPay’s issuer, audience, signing keys, grant claim shape, or field names. Supported currencies are currently configured in `TrustConfig` code and default to `USD`; there is no supported-currencies environment variable.

## Safe local setup

1. Use Python 3.10+ in a virtual environment and install the declared dependencies:

   ```bash
   python -m venv .venv
   . .venv/bin/activate
   python -m pip install -r requirements.txt
   ```

2. Keep the Sandbox gate disabled. The test suite needs no PayPal credentials or issuer configuration:

   ```bash
   export TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false
   pytest -q
   ```

   All provider HTTP behavior in tests uses fake sessions/responses. Tests must not make network requests.

3. For configuration validation only, obtain the issuer, audience, key set, and authenticated grant field names from the actual trusted contract and provide them through a secure local environment/secret manager. Do not fill these settings with guessed or sample trust values. Keep private key material out of the repository; the verifier needs public keys only.

4. If Sandbox credentials are provisioned for a separate, explicitly authorized Sandbox exercise, load them securely into `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET`. For this task and ordinary local setup, **do not set** `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true`, do not construct the REST provider, and do not call `authorize_and_dispatch`. The README gives no command that sends a PayPal request. No live credentials or production endpoint are supported.

5. Provide a durable, private SQLite file path when constructing `Ledger`. Protect its parent directory and backups as well as the owner-only database file. Keep the file on storage with appropriate durability guarantees.

## Reconciliation and blockers

`PayPalRestOrdersProvider` uses OAuth2 Client Credentials, the fixed `https://api-m.sandbox.paypal.com` host, request timeouts, disabled redirects, and `PayPal-Request-Id`. The provider can create orders and GET order details; it has no capture operation.

An `UNKNOWN` transaction with a known PayPal order ID can be reconciled via `guard.reconcile(local_transaction_id)`. If a create request timed out before any order ID was received, the local transaction remains `UNKNOWN` and reserved; GET-by-ID cannot find it, so provider-side/manual investigation is required before any separate recovery action. The application deliberately does not retry.

Before any authorized Sandbox integration, the real issuer’s exact JWT issuer, audience, public signing keys, authenticated grant claim, and grant field names must be configured. The code does not invent or infer these values. The repository has no HTTP server, webhook consumer, or production adapter; trusted integration code is responsible for controlling access to authorization, dispatch, and reconciliation functions.

## Dashboard and files

`dashboard_v2.html` and `hasil.json` are simulated UI data, not a live backend or proof of a PayPal transaction. Untrusted JSON values are rendered as text.

- `trustguard.py`: signed-token and DPoP verification, canonical transaction, durable SQLite ledger/state machine, and mock provider.
- `paypal_rest.py`: Sandbox-only PayPal REST Orders v2 adapter and GET reconciliation.
- `main_public.py`: harmless fail-closed entry point.
- `tests/`: security, persistence, dispatch, and mocked provider tests.
