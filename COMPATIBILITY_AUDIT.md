# Stage 4 — repository compatibility audit

**Audited baseline:** `ac8466ab8bc5efa9e1ae94a2456941a00cb27fb3`  
**Branch:** `codex/pages-release-repair`  
**PR:** #3 — open, Draft, not merged  
**Scope:** source tree and workflow configuration at the audited baseline. This is a static compatibility audit plus synthetic mock tests; it is not a provider integration certification.

## Repository-wide inventory

The recursive Git tree at the baseline contains these files:

- `.github/workflows/deploy-pages.yml`
- `.github/workflows/security-tests.yml`
- `LICENSE`
- `README.md`
- `SECURITY_STATUS.md`
- `build_pages.py`
- `dashboard.html`
- `dashboard_v2.html`
- `deployment_probe.py`
- `frontend_browser_tests.py`
- `frontend_tests.py`
- `hasil.json`
- `main_public.py`
- `pages_artifact_tests.py`
- `requirements-security.txt`
- `security_tests.py`
- `trustguard_security.py`
- `workflow_validation_tests.py`

### Function and API call-site findings

- `process_payment_request()` is defined only in `main_public.py`. Its current signature is keyword-only:
  `compact_token`, `compact_dpop_proof`, `transaction`, `replay_store`, `expected_url` are required; `paypal_api`, `expected_method`, and `merchant_mapping` are optional/configurable.
- The only repository call site is in `security_tests.py`, using keyword arguments. No application route, script, workflow, dashboard, or other module calls it.
- `execute_safe_payment()` is not defined or referenced in the baseline tree. No legacy adapter is retained because no live repository dependency on that symbol exists. Old positional calls to the new function are rejected by Python's keyword-only signature; no compatibility shim may skip security inputs.
- `main_public.py` imports the security primitives from `trustguard_security.py`. No other runtime Python module imports the dispatcher or the security module.
- The only runtime order-creation dispatch is the injected `paypal_api.run(method="create_order", ...)` call inside `process_payment_request()`, after token authentication, DPoP verification, canonical transaction validation, authorization, and replay claims.
- No PayPal SDK/toolkit import, direct PayPal API client invocation, or capture call exists in the runtime Python files at this baseline. README references to the Toolkit and package installation are descriptive setup material, not executable call sites.
- GitHub Actions run artifact construction, workflow validation, security/frontend/browser tests, and an informational read-only public Pages probe. The manual deploy workflow is a separately gated workflow and was not run as part of this audit.
- Dashboards consume static `hasil.json`; they do not call the backend or authenticate backend telemetry. The source status remains `UNVERIFIED`, transaction statuses remain `UNKNOWN`, and transaction identifiers are absent.

## Compatibility matrix

| Component | Actual contract / call path | Status | Action |
|---|---|---|---|
| Application entry point | `main_public.py:main()` only prints safe-entry-point guidance; no payment request is dispatched from CLI | PASS for safe import/CLI behavior; BLOCKED for a production HTTP/application route because none exists | Keep fail-closed; do not invent a route or issuer config |
| Backend dispatcher | Keyword-only `process_payment_request(...)`; requires signed token, signed DPoP proof, transaction mapping, replay store, and expected URL | PASS for current function contract under synthetic tests | Keep keyword-only; use named arguments |
| Legacy entry point | `execute_safe_payment()` absent; no in-repository callers found | PASS for absence of internal dependency; BLOCKED if an external consumer still depends on it | Do not silently add an insecure alias; external consumers must migrate explicitly |
| Scripts | `build_pages.py` builds static files; `deployment_probe.py` performs read-only checks; neither calls payment dispatcher | PASS for no payment bypass | Keep scripts read-only; no credentials or order actions |
| Workflows | Security workflow invokes all five required test groups and informational Pages probe; deploy workflow is manual and gated to `main` plus explicit confirmation | PASS for static configuration; no deployment executed | Validate workflow contract in CI; do not trigger deployment |
| Tests | `security_tests.py` calls dispatcher with keyword arguments and mock PayPal adapter; other suites test UI/artifact/workflow contracts | PASS on the previously tested Stage 3 HEAD; Stage 4 must rerun all groups on its new HEAD | Add explicit signature/legacy rejection and bypass-scan tests |
| Dashboard/integration | Static HTML + `hasil.json`, source `UNVERIFIED`; no authenticated backend telemetry connector | PASS for conservative static claims; BLOCKED as proof of a verified transaction | Keep all values unknown/unverified absent authenticated backend evidence |

## Lifecycle and security invariants

1. Order creation occurs only after authentication, DPoP, canonical transaction validation, authorization, and replay-store claims pass.
2. The canonical immutable transaction supplies the policy decision and outbound order payload.
3. Invalid requests and failed security checks must yield zero mock adapter calls.
4. Successful order creation is only `ORDER_CREATED`; `capture_status` remains `NOT_ATTEMPTED`.
5. No tokens, private keys, or credential values should be written to logs. The current runtime modules contain no logging setup.
6. Synthetic keys, merchant identifiers, and mocked order IDs in tests are test fixtures only, never production configuration.

## Blockers preserved from Stage 3

- Official KYAPay issuer/token/delegation contract is not verified.
- Official PayPal merchant mapping is not verified.
- SQLite does not prove multi-instance/distributed replay protection.
- Cumulative spend has no atomic reservation/ledger.
- Order-creation idempotency is not guaranteed.
- Full DPoP RFC 9449 interoperability and actual provider integration remain unverified.

## Verification boundary

The repository's full test workflow must pass on the new Stage 4 HEAD, with no required suite skipped. This document does not claim official KYAPay interoperability, production readiness, a completed payment, or a public deployment.
