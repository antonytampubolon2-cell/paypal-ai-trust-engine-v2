# TrustGuard PayPal Sandbox Operator Runbook

**For human review only. This document does not authorize a checkout.** The command below can contact PayPal Sandbox and create a Sandbox order, and after buyer approval can capture it. Run it only on a trusted local machine after all preflight items are independently confirmed. Do not use production credentials or enable the public API for payment dispatch.

## What this runner is—and is not

`scripts/run_paypal_sandbox_demo.py` is a manually operated local CLI. The preferred gated entry point is `scripts/run_judge_demo.py`, whose default remains the provider-free offline demo. The Sandbox branch requires the additional `--mode sandbox --confirm-sandbox` acknowledgment. It is not a production payment route and does not validate a genuine Skyfire-issued token.

The runner creates synthetic ES256 access and DPoP credentials in memory for a single local demonstration. It displays `LOCAL TEST ONLY` and uses a localhost issuer and audience. The example transaction amount is fixed at USD 5.00, with a synthetic USD 100.00 grant. The PayPal item is a generic server-created `Authorized transaction` line, not an actual product catalog entry. The test therefore demonstrates an operator-controlled PayPal Sandbox checkout path with local TrustGuard authorization—not Skyfire onboarding or a genuine Skyfire token integration.

## Account roles to prepare separately

| Role | What it is used for | Required operator evidence |
| --- | --- | --- |
| PayPal Developer account / Sandbox REST app | The app provides the Sandbox REST application identifier (`PAYPAL_CLIENT_ID`) and secret (`PAYPAL_CLIENT_SECRET`) used for OAuth. The client ID is an application identifier, not the secret. | Confirm the app is Sandbox and both values came from the intended Sandbox app. Treat the client secret as confidential; do not send either value in chat or put them in the repository. |
| Sandbox business / seller account | Receives the Sandbox payment. Its merchant account ID is configured as the PayPal payee. | Confirm the exact Sandbox receiving merchant ID using the account/app configuration. It must differ from the selected local or Skyfire service identity. |
| Sandbox Personal / buyer account | Opens PayPal's returned approval URL and approves the test order. | Confirm the buyer can sign in to PayPal Sandbox. Never use a real production buyer account or payment instrument. |
| Skyfire Seller Service | Not used for genuine authorization in this local runner. | No Skyfire service or token is created by the runner. The normal Skyfire dashboard/account evidence remains a separate integration prerequisite. |

`PAYPAL_CLIENT_ID` is the REST app's application identifier; `PAYPAL_CLIENT_SECRET` is its confidential secret. Neither is the buyer credential, seller merchant ID, Seller Service ID, or legacy PayPal NVP/SOAP credential. The buyer account is used only in the browser approval step. The seller merchant ID is bound in the outgoing Orders v2 payee field.

## Exact environment configuration consumed

The runner's required-name tuple is defined in `scripts/run_paypal_sandbox_demo.py::REQUIRED_ENV`, with value checks in `validate_config`. Names and required values are:

| Environment variable | Required value or semantics | Category |
| --- | --- | --- |
| `TRUSTGUARD_LOCAL_SANDBOX_DEMO` | Must be `true`. Enables generated local authorization material and loopback callback mode. | Local runner opt-in; not production authorization. |
| `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX` | Must be `true`; separately required by `paypal_rest.py` before OAuth/provider requests. | Explicit dispatch opt-in to Sandbox only. |
| `PAYPAL_ENV` | Must be `sandbox`. Missing or any other value is rejected at provider initialization and before requests. | Environment guard. |
| `PAYPAL_CLIENT_ID` | Non-empty Sandbox REST app client ID; this is an application identifier, not a secret. | Application identifier. |
| `PAYPAL_CLIENT_SECRET` | Non-empty Sandbox REST app secret. | Secret. |
| `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID` | Must exactly equal the selected service identity (synthetic local ID or operator-supplied `SKYFIRE_SELLER_SERVICE_ID`). | Local account/service-to-merchant binding. |
| `TRUSTGUARD_PAYPAL_MERCHANT_ID` | Sandbox receiving merchant account ID; must differ from service identity. | Payee configuration. |
| `TRUSTGUARD_DATABASE_PATH` | Persistent file path; `:memory:` and directory-shaped paths are rejected. | Durable local ledger path. |

Additional identity selector behavior:

- Preferred pre-onboarding local mode: set `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` to a synthetic identifier beginning `LOCAL-TEST-ONLY-PAYPAL-` and no longer than 128 characters. Set the mapped service variable above to exactly the same string. This is not a Skyfire ID.
- Compatibility alternative: if `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` is absent, `validate_config` requires `SKYFIRE_SELLER_SERVICE_ID`, then requires the mapped service variable to equal it. This still does **not** make the generated token genuine Skyfire authorization; the runner still signs local tokens itself. Do not select this alternative unless the service ID is already authoritatively confirmed and you understand the local-only limitation.
- The runner itself generates both `return_url` and `cancel_url`; they are the same ephemeral `http://127.0.0.1:<port>/paypal/callback/<random-nonce>` URL. There are no operator-provided environment variables for either callback URL.
- Amount, currency, grant cap, token issuer/audience, and local keys are generated or fixed in code for this demonstration; they are not environment-variable settings.
- `TRUSTGUARD_ISSUER`, `TRUSTGUARD_AUDIENCE`, `TRUSTGUARD_JWT_PUBLIC_KEYS_JSON`, `TRUSTGUARD_JWT_ALGORITHMS`, and `TRUSTGUARD_GRANT_*` are for separate service/verifier configuration, not inputs used by this runner to establish genuine Skyfire trust. Do not populate them with invented Skyfire values for this CLI.

The repository contains both `requirements.txt` (the dependency manifest with version ranges/pins) and `requirements.lock` (the reviewed exact Python 3.12 package pins used for local verification and CI/Docker builds). Use the tracked `requirements.lock` when reproducing that pinned environment; do not assume some other lockfile exists. No `.env` loading package is declared, so a `.env` file is not automatically loaded by this runner.

## Credential and local-data handling

Use a trusted local workstation and an approved secret manager or secure environment-injection mechanism. Supply `PAYPAL_CLIENT_SECRET` and `PAYPAL_CLIENT_ID` through that mechanism; do not put their values in source files, shell command arguments, chat, tickets, screenshots, documentation, shell history, or a repository `.env` file. Avoid printing environment variables. Limit access to the local machine and clear the temporary credentials after the run according to your organization's policy. The runner uses the secret in memory for Basic-auth OAuth and does not print it.

The current `.gitignore` excludes `.env`, `.env.*`, `*.env`, `.envrc` variants, and SQLite runtime `*.db`, `*.sqlite`, and `*.sqlite3` files plus their `-wal`, `-shm`, and `-journal` sidecars. It keeps `.env.example` and intentional SQLite files under `tests/fixtures/` trackable. No `.env.example` is currently present. These rules reduce accidental Git adds, but **`.gitignore` does not secure files on disk, encrypt them, restrict who can read them, or replace OS access controls**. Keep the database and secure configuration in a restricted, user-owned directory outside the repository; verify directory/file permissions with the operating system. Before and after operator setup, inspect `git status --short` and never stage secret/config/database files.

The adapter does not log credentials or provider response bodies. The CLI allowlists printed result fields and suppresses exception details and tracebacks. OAuth tokens and signing private keys are held in memory, not written to the result report. The ledger is file-backed; its constructor creates/sets the main SQLite file to POSIX mode `0600`, and the stored provider evidence is normalized/allowlisted rather than a raw HTTP body. **On Windows, do not assume POSIX mode `0600` alone provides the intended ACL protection.** Store the database and any local secure configuration in a restricted, user-owned directory, and have the operator verify the effective NTFS permissions (including inherited ACLs) before use. The runner's callback handler suppresses request-line logging because callback query parameters contain order material.

However, the console intentionally displays PayPal's verified Sandbox approval URL and order/capture IDs as part of the operator flow. Treat the approval URL as sensitive checkout material: do not paste it into chat, issue trackers, public recordings, or saved logs. Keep terminal output private. Do not create screenshots or reports containing credentials, tokens, buyer account information, or live order links.

## Pre-run checklist

Complete `PAYPAL_SANDBOX_PREFLIGHT.md` first. In particular, confirm the app is Sandbox, credentials are retrievable through secure storage without exposing them, the seller merchant ID is correct, the buyer account is a Sandbox Personal account, all exact environment values pass `validate_config`, the ledger path is persistent and outside the repository, and there is no unresolved `UNKNOWN` order/capture from a previous run.

For the pre-onboarding synthetic identity example, the service ID may be any operator-chosen, clearly synthetic value matching the required prefix; no official Skyfire ID should be substituted. Values must be supplied through secure local configuration, not copied into this runbook. Do not run a preflight by executing the payment command: the command can contact the provider.

## Exact operator command and checkout sequence

From the repository root, after dependencies are installed and all settings are securely injected into the current process environment, use the launcher with its explicit Sandbox confirmation:

```bash
python scripts/run_judge_demo.py --mode sandbox --confirm-sandbox
```

This is not a dry-run. It may perform OAuth and create one PayPal Sandbox order. Do not use this command until the operator has decided to proceed. The direct runner entry point exists as `python scripts/run_paypal_sandbox_demo.py`, but the launcher command is preferred because its explicit flag makes the Sandbox action visible.

Expected flow:

1. The launcher requires `--confirm-sandbox`, then imports and runs the local Sandbox CLI. The CLI validates all required values before constructing its provider. Any missing/invalid setting stops before provider initialization.
2. TrustGuard locally creates a synthetic authorization and DPoP proof, performs the existing risk and authorization checks, persists the transaction, and—only if allowed—uses PayPal OAuth and the fixed Sandbox REST host `https://api-m.sandbox.paypal.com` to create an order. This step is a real Sandbox API call if configured; the previous tests used mocks only.
3. The terminal displays the returned, validated approval URL on `https://www.sandbox.paypal.com` and bound to the order token. Open that exact URL in a browser and sign in with the Sandbox Personal buyer. Review that this is a Sandbox checkout and approve only if the displayed order is expected. The callback return/cancel target is loopback on the operator's machine. No public URL, port forwarding, or callback server exposure is needed. The callback is informational and is not proof of approval; the runner does not wait on it to authorize capture.
4. Return to the terminal. Copy the order ID from the approval URL's `token` parameter (or the original runner output) and enter only the order ID at `Returned PayPal order ID (not a URL or JWT)`. The ID must match the persisted order exactly.
5. At `Type APPROVE to capture:`, type the literal `APPROVE` only if you intend to proceed. This is an operator confirmation—not provider evidence. The runner first performs TrustGuard reconciliation, which makes an authenticated PayPal GET and requires the exact bound order status `APPROVED`. The capture method performs its own fresh approved-state check and commits a durable one-time capture marker before the capture POST.
6. The adapter sends one capture POST with a stable idempotency request ID and no automatic retry. Then the runner performs final authenticated GET reconciliation. It reports `CAPTURE_COMPLETED` and `payment_completed: true` only if the provider GET shows exact transaction, merchant, currency and amount binding plus unique completed capture evidence totaling the canonical amount.
7. If any provider result is ambiguous or times out, the runner reports a safe failure/`UNKNOWN` and does not automatically retry. Stop. Preserve the SQLite database and do not rerun the CLI as a retry: each run creates a new transaction. Have an operator investigate/reconcile the existing order using a separate trusted procedure; do not improvise another capture.

A cancel or failed browser approval does not authorize capture. Return to the local terminal and do not type `APPROVE` unless you intend to proceed. If the callback page appears, it only says the callback was received; it is not proof of buyer approval and does not itself trigger capture. The terminal's authenticated GET checks are authoritative in this flow.

## Production and Skyfire boundaries

- The adapter's host is a source-code constant for PayPal Sandbox; the environment does not select a Live host. `PAYPAL_ENV` must explicitly be `sandbox`, and the dispatch opt-in is separately required. Never modify the constant or use Live credentials for this run.
- `app.py` declares provider-free API routes; it does not instantiate `PayPalRestOrdersProvider` or create/capture orders. The checkout client is imported by the local CLI after configuration checks. Do not deploy the local CLI, enable Sandbox flags in the API service, or expose/port-forward its callback listener.
- TrustGuard's official Skyfire verifier rejects the `LOCAL-TEST-ONLY-PAYPAL-` namespace. When the runner selects that identity, the PayPal adapter additionally requires local-demo mode and a loopback issuer plus the local-only audience. Thus the generated local token is not accepted as genuine Skyfire authorization and is not a shortcut for the public verifier.
- No genuine Skyfire issuer, JWKS, Seller Service registration, KYAPay token, or account-specific service binding is established by this runner. Do not describe the Sandbox operation as a genuine Skyfire-to-PayPal transaction.

## Stop conditions

Do not proceed if the account role, Sandbox environment, merchant identity, secure credential provision, or database persistence is uncertain. Stop immediately on a HOLD, `UNKNOWN`, order-ID mismatch, unexpected amount/currency/merchant, non-Sandbox approval URL, database error, or unexpected provider state. Never rerun automatically after an ambiguous result and never enable production payment functionality.
