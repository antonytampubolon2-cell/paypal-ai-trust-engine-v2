# TrustGuard PayPal Sandbox Operator Preflight

**Decision: BLOCKED — do not start checkout yet.** This checklist reflects repository evidence at commit `abf5458cab2629f3c12e4fc4aee3920db8a7c54f` and the presence-only check recorded in `TrustGuard_PAYPAL_SANDBOX_INTEGRATION_REPORT.md`. No provider API was called for this preflight, and no real credentials were inspected or printed.

Status meanings: **PASS** means repository behavior or documentation was verified. **BLOCKED** means an operator fact/configuration is absent or has not been independently confirmed. A code PASS does not imply live PayPal account verification.

## Current preflight status

| Check | Status | Evidence / operator action |
| --- | --- | --- |
| Correct local branch and exact implementation commit | PASS | Branch is `manus/paypal-sandbox-integration`; HEAD is the expected `abf5458cab2629f3c12e4fc4aee3920db8a7c54f`. The current working tree has an uncommitted `.gitignore` change and the two untracked operator documents; these are not part of the implementation commit. |
| `PAYPAL_ENV=sandbox` enforced | PASS | Adapter constructor and request gate reject missing/non-sandbox values; `SANDBOX_BASE_URL` is fixed to `https://api-m.sandbox.paypal.com`. Regression test rejects a changed environment before any request. |
| Explicit dispatch gate | PASS | Runner and adapter require `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true`; runner separately requires `TRUSTGUARD_LOCAL_SANDBOX_DEMO=true`. Missing gates fail before provider construction. |
| Gated command | PASS | Preferred command is `python scripts/run_judge_demo.py --mode sandbox --confirm-sandbox`. Launcher defaults offline and refuses Sandbox without the explicit confirmation flag. This command can create an order; it is not a dry run. |
| Test evidence | PASS (mock-only) | The prior recorded verification is 113 focused tests and 334 full-suite tests passing with Sandbox disabled. Provider HTTP was intercepted by test doubles. No live interoperability is established. |
| PayPal Sandbox REST app and credentials | BLOCKED | The prior presence-only inventory recorded `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET` absent. `PAYPAL_CLIENT_ID` is the Sandbox REST application's identifier; `PAYPAL_CLIENT_SECRET` is its confidential secret. Operator must obtain them from the intended Sandbox REST app and inject them via approved secure environment/secret storage. Do not share values. |
| Seller Sandbox business account and merchant ID | BLOCKED | `TRUSTGUARD_PAYPAL_MERCHANT_ID` was absent in the prior presence-only inventory. Operator must confirm the receiving Sandbox business account and its exact merchant ID independently. It must not equal the selected service identity. |
| Sandbox Personal buyer account | BLOCKED | No account availability or login verification is recorded. Operator must confirm a Sandbox Personal account can complete the approval flow. Do not use a production buyer account. |
| Synthetic service identity and explicit mapping | BLOCKED | `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` was not in the recorded absent list, so its current presence/value is **not inspected**. For pre-onboarding local mode, operator may choose a synthetic `LOCAL-TEST-ONLY-PAYPAL-...` identifier (<=128 characters) and set `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID` to the exact same value. Both must be locally checked before running. Do not present this as a Skyfire service ID. |
| Optional actual `SKYFIRE_SELLER_SERVICE_ID` | BLOCKED / NOT REQUIRED for synthetic mode | Its value was not inspected. It is used only if `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` is omitted. This runner still generates fake local tokens in that branch; using a real ID does not establish Skyfire authorization. Prefer synthetic mode unless an operator has an explicit reason and authoritative service evidence. |
| Persistent local SQLite path | BLOCKED | `TRUSTGUARD_DATABASE_PATH` was absent in the prior presence-only inventory. Operator must choose a writable file path outside the repository. `:memory:` is rejected; preserve the file if any outcome is ambiguous. |
| Local demo and PayPal gates configured | BLOCKED | `TRUSTGUARD_LOCAL_SANDBOX_DEMO` and `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX` were absent in the prior presence-only inventory. Do not enable until human review authorizes an actual Sandbox checkout; then set only in the isolated local CLI environment, never the API deployment. |
| Secure secret storage | BLOCKED | No credential manager/configuration is recorded. Use an approved secret manager or secure local environment injector. Do not put credentials in source, chat, shell arguments/history, README, `.env` in the repository, screenshots, reports, or logs. Git ignore rules do not secure local files; verify OS access controls. On Windows, do not rely on POSIX mode `0600`; require a restricted user-owned directory and verified NTFS permissions. |
| `.gitignore` accidental-add protections | PASS (rules verified) | Current working-tree `.gitignore` excludes `.env`, `.env.*`, `*.env`, `.envrc` variants, and SQLite `*.db`, `*.sqlite`, `*.sqlite3` files plus WAL/SHM/journal sidecars. `.env.example` and SQLite fixtures under `tests/fixtures/` remain trackable. `git check-ignore -v` verified representative paths. This is only Git exclusion: it does not secure files on disk or replace OS access controls. Keep secrets/database outside the repository; on Windows require a restricted user-owned directory and operator verification of effective NTFS permissions. |
| Local credentials are genuine Skyfire credentials | BLOCKED / FALSE | The runner explicitly generates synthetic ES256 access/DPoP credentials in memory with a loopback issuer and local-only audience. It is not a Skyfire token flow. Skyfire account dashboard previously showed no Seller Service record; this runner neither creates nor registers one. |
| Public API can dispatch PayPal | PASS (not exposed) | `app.py` routes are separate and provider-free; there is no public create/capture route. The adapter is imported by the local CLI after validation. Do not run or deploy with Sandbox gates enabled in the API process. |
| Return/cancel URLs | PASS (code behavior) | Runner creates one ephemeral loopback URL and passes it as both return and cancel URL. No public callback URL or port forwarding is required. Callback receipt is not proof of approval and does not trigger capture. |
| Existing unresolved `UNKNOWN` checkout | BLOCKED until checked locally | The operator must check the persistent ledger for prior `UNKNOWN` or dispatch-started state before any run. This document does not inspect local databases. Never rerun the CLI to retry; each run creates a new transaction. |
| Genuine end-to-end PayPal Sandbox result | BLOCKED | No order, approval, capture, or provider reconciliation has been performed. Do not claim a completed PayPal transaction until a human operator has executed and retained appropriate redacted evidence of the complete flow. |

## Exact required names to confirm locally

Required by `scripts/run_paypal_sandbox_demo.py::REQUIRED_ENV`:

- `TRUSTGUARD_LOCAL_SANDBOX_DEMO=true`
- `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true`
- `PAYPAL_ENV=sandbox`
- `PAYPAL_CLIENT_ID` (Sandbox app client ID)
- `PAYPAL_CLIENT_SECRET` (secret)
- `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID` (must exactly match chosen service identity)
- `TRUSTGUARD_PAYPAL_MERCHANT_ID` (receiving Sandbox merchant ID)
- `TRUSTGUARD_DATABASE_PATH` (persistent file outside repository)

Additionally, select exactly one identity source: `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` (recommended synthetic local identifier) or `SKYFIRE_SELLER_SERVICE_ID` (optional compatibility alternative). The mapping variable is required in either case. `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` must have prefix `LOCAL-TEST-ONLY-PAYPAL-`, maximum length 128, and requires local demo mode. The `SKYFIRE_SELLER_SERVICE_ID` alternative does not make this runner use Skyfire-issued tokens.

There are no environment variables for callback URLs. The runner binds an ephemeral callback listener to `127.0.0.1` and supplies its generated URL as both `return_url` and `cancel_url`.

## Manual checks before the command

1. Confirm the PayPal Developer account/app and credentials are Sandbox—not Live—and securely inject them without displaying their values.
2. Confirm the seller is the intended Sandbox business account and the configured merchant ID is exact. Confirm a separate Sandbox Personal buyer account is available.
3. Choose a synthetic local service ID and set its exact mapping; use no invented official Skyfire identity. Keep `TRUSTGUARD_LOCAL_SANDBOX_DEMO=true` and both payment flags confined to the local terminal session.
4. Select a persistent SQLite database location outside the repository, verify its parent is writable, and check for unresolved prior dispatch/`UNKNOWN` records using the project's approved local procedure.
5. Verify the secure configuration is present without printing values. Do not include values in command-line arguments. Check the repository working tree and ensure no configuration/database file has been staged.
6. Read the whole [operator runbook](PAYPAL_SANDBOX_OPERATOR_RUNBOOK.md). The expected checkout amount is USD 5.00; the command may contact PayPal Sandbox and create an order.
7. Obtain explicit human approval to proceed with a Sandbox order and capture. Without it, stop here.

## Decision gate

Proceed only when every account/configuration item above is PASS and a human operator explicitly authorizes the actual Sandbox test. If any required fact is uncertain, the result is **BLOCKED**. No item in this checklist authorizes production mode. The only permitted command for this local flow is:

```bash
python scripts/run_judge_demo.py --mode sandbox --confirm-sandbox
```

After a run, disable/unset both opt-in variables and the synthetic service ID. Preserve the SQLite ledger and investigate any `UNKNOWN` outcome instead of rerunning. A successful mocked test suite is not evidence of a live Sandbox transaction.
