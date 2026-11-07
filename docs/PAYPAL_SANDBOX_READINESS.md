# PayPal Sandbox Readiness — Read-Only Preflight

**Status:** Not configured for a genuine Sandbox run in the inspected runtime. No API calls or transactions were made.
**Repository review baseline:** `c95a1b5cac9b81dcc01408a5a3c0259360ff622c`; branch `manus/trustguard-security-remediation-2026-11-12`.

## Existing implementation

`paypal_rest.py::PayPalRestOrdersProvider` is a REST Orders v2 adapter restricted to `https://api-m.sandbox.paypal.com`. It requires the exact Sandbox opt-in and PayPal REST application client credentials. `create_order()` validates the trusted merchant/service mapping and returned order, amount, currency, and payee bindings; `get_order_details()` reconciles provider state; `capture_order()` is a separate operation. OAuth REST credentials are not legacy NVP/SOAP credentials.

The separate `scripts/run_paypal_sandbox_demo.py` runner requires explicit local-Sandbox/demo gates, a file-backed SQLite ledger, mapped service and merchant identity, and PayPal REST app credentials. Its flow screens a synthetic transaction, creates an order only on `ALLOW`, requires the operator to match the returned order ID and type `APPROVE`, independently verifies buyer approval by provider status before capture, and reconciles afterward. Tests use mocked HTTP transports. They do not prove a real PayPal Sandbox order/capture.

The Skyfire Seller Service API remains separate: generated local claims in the demo are not Skyfire-issued tokens, and Skyfire account registration/profile evidence does not follow from a PayPal REST application.

## Presence-only configuration check

Presence was checked in the current runtime by testing variable presence only. No values, prefixes, or lengths were printed. All variables below were **ABSENT** at check time:

| Variable | Purpose | Runtime presence |
|---|---|---|
| `PAYPAL_CLIENT_ID` | PayPal REST Sandbox application client ID | Absent |
| `PAYPAL_CLIENT_SECRET` | PayPal REST Sandbox application secret | Absent |
| `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX` | Explicit adapter opt-in; must remain disabled for the API/offline demo | Absent |
| `TRUSTGUARD_LOCAL_SANDBOX_DEMO` | Explicit local synthetic-authorization demo gate | Absent |
| `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID` | Server-side mapping source service identifier | Absent |
| `TRUSTGUARD_PAYPAL_MERCHANT_ID` | Receiving Sandbox merchant identity | Absent |
| `TRUSTGUARD_DATABASE_PATH` | File-backed ledger path | Absent |

Reviewer settings were also absent, but they are not needed for a buyer's PayPal approval. No database file was created during this preflight. No path was configured, and no evidence establishes a persistent volume. The checkout filesystem being writable does not establish persistence across runtime teardown. Docker's `/data` volume declaration requires a separately configured persistent mount and does not itself provide backups/restore.

## Identity and operator prerequisites

- A receiving Sandbox merchant ID is not configured or confirmed. The code keeps it distinct from a Skyfire Seller Service ID; code-level mapping capability is not proof of an actual merchant mapping.
- The local runner may use an explicitly synthetic `LOCAL-TEST-ONLY` service identity. That identity is demo scaffolding, not the receiving PayPal merchant and not a verified Skyfire Seller Service.
- Access to a Sandbox Personal buyer account and an operator able to complete the approval step were not verified in this environment.
- No Skyfire Seller Service or account-specific token profile was verified by this preflight.
- A controlled test would require an operator-approved Sandbox app, securely injected REST credentials, confirmed receiving merchant identity, distinct documented service-to-merchant mapping, persistent writable SQLite storage, accessible buyer account/manual approval, and the explicit runner confirmation gate. Do not enable the API's PayPal dispatch.

## Decision

**SANDBOX PREFLIGHT: NOT READY.** Required variables were absent, no persistent database location or buyer/merchant account availability was evidenced, and no genuine transaction was attempted. A REST application configuration, if later supplied, is not the same as a completed Sandbox checkout. Do not request or place secrets in chat or source control. Inject them only through an approved secret mechanism after a separately authorized operator procedure. No PayPal or Skyfire API was contacted in this review.
