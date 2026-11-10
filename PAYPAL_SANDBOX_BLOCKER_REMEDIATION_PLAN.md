# PayPal Sandbox Blocker Remediation Plan

**Date:** November 9, 2026  
**Repository:** `antonytampubolon2-cell/paypal-ai-trust-engine-v2`  
**Branch / HEAD:** `manus/paypal-sandbox-integration` / `abf5458cab2629f3c12e4fc4aee3920db8a7c54f`  
**Scope:** Diagnostic and remediation planning only. No application, test, dependency, configuration, or prior operator-document files were changed. No credentials were accessed and no PayPal/Skyfire call or payment action occurred.

## 1. Three reported failing tests: root cause and reproduction

The three exact node IDs reported by the prior audit were reproduced in the minimal isolated `uv` environment used for that report. Each returned `HOLD` instead of reaching its expected provider-flow outcome:

| Node ID | Expected | Actual in minimal environment | Classification |
|---|---|---|---|
| `tests/test_paypal_rest.py::test_trustguard_sandbox_create_and_reconcile_full_flow` | `CREATED` | `HOLD` | Environment/dependency issue |
| `tests/test_paypal_rest.py::test_trustguard_oauth_failure_is_failed_without_order_request` | `FAILED` | `HOLD` | Environment/dependency issue |
| `tests/test_paypal_rest.py::test_trustguard_order_timeout_persists_unknown_and_never_retries` | `UNKNOWN` | `HOLD` | Environment/dependency issue |

The minimal test invocation supplied pytest, Requests, PyJWT, cryptography, and Pydantic, but omitted the model dependencies from the project lock. A package probe confirmed NumPy was present and `sklearn` was absent in that isolated invocation. The tests instantiate `TrustGuard` without an injected risk scorer, so the default `SyntheticIsolationForestScorer` is used. `risk_scoring.py::_fit_model` imports `sklearn.ensemble.IsolationForest` (lines 43–49). `assess_reserved_transaction` catches inference exceptions and persists a fail-closed assessment with `score=None` and `decision="HOLD"` ( `trustguard.py:625–653`). `TrustGuard.authorize_and_dispatch` returns `HOLD` before transitioning to `DISPATCH_STARTED` or calling the provider (`trustguard.py:811–827`). Consequently none of the three tests reaches its fake OAuth/order branch in that incomplete environment.

This is **not** a reason to relax risk policy, alter a threshold, change production behavior, or rewrite the expectations. The tests are not stale or invalid: under the complete pinned runtime they pass.

### Reproduction in the complete temporary test environment

The existing temporary venv used for this audit is Python 3.12.3 and has the relevant lock-matching versions: pytest 8.4.2, Requests 2.34.2, PyJWT 2.15.1, cryptography 50.0.2, Pydantic 2.14.3, scikit-learn 1.6.1, and NumPy 2.5.4. With `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false` in the shell, the three exact node IDs passed: **3 passed**. The four requested modules also passed: `tests/test_checkout.py`, `tests/test_paypal_rest.py`, `tests/test_sandbox_demo.py`, and `tests/test_trustguard.py` — **113 passed**. These tests use fakes/local SQLite; this is not PayPal interoperability evidence and is not a full-repository test-suite claim.

### Reproducible isolated test setup

Use a fresh temporary environment and the repository's exact lock rather than an ad-hoc partial `uv --with` list. This does not modify global Python or project dependency files:

```bash
TEST_ENV_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trustguard-sandbox-test.XXXXXX")"
python3 -m venv "$TEST_ENV_DIR/venv"
"$TEST_ENV_DIR/venv/bin/python" -m pip install -r requirements.lock
TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false \
  "$TEST_ENV_DIR/venv/bin/python" -m pytest -q -p no:cacheprovider \
  tests/test_checkout.py tests/test_paypal_rest.py \
  tests/test_sandbox_demo.py tests/test_trustguard.py
```

The exact preceding command was not rerun from a newly created venv during this task; the tests were run in the existing temporary venv whose core package versions match the lock. The command above describes how to reproduce in a fresh isolated environment. No PayPal/Skyfire provider calls are part of these tests.

## 2. TLS and injected-session boundary

**Finding: FAIL for the general provider constructor/factory boundary; the normal local CLI path currently uses the default Requests session.**

`PayPalRestOrdersProvider.__init__` accepts `session: Any | None` and stores `session or requests.Session()` without checking session type, TLS verification, mounted adapters, proxy behavior, or endpoint integrity (`paypal_rest.py:34–36,57–60`). `from_env` also accepts and forwards an arbitrary session (`paypal_rest.py:101–110`). The adapter passes a fixed Sandbox URL and `allow_redirects=False` for each request (`paypal_rest.py:118–125,221–233,297–302,345–352`), and does not expose a configurable base URL. Those controls do **not** secure a caller-supplied transport: a standard `requests.Session` with `verify=False` disables certificate validation, and an arbitrary session/adapter can rewrite or route the fixed URL elsewhere. Thus a caller can bypass TLS verification or introduce a non-PayPal endpoint through the injectable session seam. This is a source-level risk; it was not exercised with any real network session.

The documented runner constructs the adapter without a custom session (`scripts/run_paypal_sandbox_demo.py:339–346`), so its ordinary path receives a default Requests session whose certificate verification is enabled by default. This reduces exposure in that single path but does not make the public constructor or `from_env(session=...)` safe for real credentials.

### Smallest safe design

1. Make the production factory create and own a standard Requests session internally; do not allow a caller-supplied session on the real-credential `from_env` path. Keep the Sandbox URL constant and redirects disabled.
2. Preserve fake transport injection through an explicitly test-only seam (for example, a private test factory/constructor used by tests). Do not make production construction silently accept arbitrary transports merely to retain test convenience.
3. Ensure the production session uses certificate verification and the standard HTTPS adapter; fail closed if configuration attempts to disable verification or substitute transport adapters. If environment proxies are supported operationally, document that trust boundary and retain TLS verification to the fixed hostname.

### Required regression tests

- Production factory rejects any injected custom transport before credentials or HTTP are used.
- Production session has TLS verification enabled; disabling it or mounting a transport that changes the destination is rejected.
- Test-only fake sessions remain injectable and all requests still assert the fixed Sandbox URL, HTTPS scheme, timeout, and `allow_redirects=False`.
- Constructor/factory test proves there is no caller-controlled API base URL or Live host selection.

## 3. Timeout validation

Current validation at `paypal_rest.py:55–56` accepts a two-element tuple whose elements are `int`/`float` and satisfy `x > 0`. It does not call `math.isfinite`, set an upper bound, or exclude booleans (which are Python integers). Request methods reuse this tuple at lines 123, 231, 300, and 351.

| Input component | Current behavior | Reason |
|---|---|---|
| `NaN` | **Accepted** | `NaN <= 0` is false |
| Positive infinity | **Accepted** | It is positive and no finite check exists |
| Negative infinity | Rejected | It is `<= 0` |
| Zero | Rejected | It is `<= 0` |
| Negative finite value | Rejected | It is `<= 0` |
| Excessively large positive finite value, e.g. `1e300` | **Accepted** | No upper bound exists |
| `True` | **Accepted** | `bool` subclasses `int`, and `True > 0` |
| `False` | Rejected | It compares as zero |

There are tests asserting the ordinary default timeout and checking timeout outcomes (`tests/test_paypal_rest.py:162–170,245–251`), but no constructor validation tests were found for these edge values.

### Minimal validation proposal

Require a tuple of exactly two numeric, non-boolean values; require each component to be finite and in a documented positive range. A concrete proposal is `0 < timeout_component <= 60.0` seconds, with a named maximum and the existing `(3.05, 15.0)` default unchanged. The 60-second cap is a proposed policy value for engineering approval, not an existing source fact. Reject NaN, `+inf`, `-inf`, zero, negatives, values above the cap, booleans, wrong tuple length, and nonnumeric types before any network-capable session is used.

### Required regression tests

Parameterize each connect/read position over `NaN`, `+inf`, `-inf`, `0`, `-1`, `1e300`, `True`, and `False`; test wrong tuple lengths and string values; test accepted values at documented positive boundaries and at the maximum; assert rejection happens before any fake-session call. Keep the default timeout assertion.

## 4. Buyer-approval trust boundary

`TrustGuard.capture_approved_order(transaction_id, buyer_approved=...)` requires the boolean to be exactly `True` (`trustguard.py:890–898`), checks durable `ALLOW` and an eligible order state (`901–903`), and refuses a prior capture attempt (`912–913`). It then calls `reconcile(transaction_id)`, which reads the provider order ID from the durable ledger and reconstructs the canonical transaction from the same ledger record (`trustguard.py:849–865`). It proceeds only if that authenticated provider GET returns `APPROVED` (`914–924`). The adapter's GET validation checks the returned order ID and binds reference/transaction ID, merchant, currency, amount and canonical itemization (`paypal_rest.py:142–189,290–329`). The capture marker is persisted before the capture POST (`trustguard.py:924–926`); capture completion is accepted only after provider GET validates exact completed capture evidence (`paypal_rest.py:331–368; trustguard.py:931–937`).

The boolean and the runner's typed `APPROVE` are **operator-intent gates, not evidence that PayPal approved the order**. The code correctly performs fresh provider-state retrieval and binding checks before capture; the browser callback is explicitly non-authoritative. The runner compares the supplied order ID with the persisted provider order ID, performs reconciliation, and only then calls capture (`scripts/run_paypal_sandbox_demo.py:376–405`). No public capture route was found: the public app's screening endpoint is provider-free, and the runner is a local CLI (`app.py:280–327,336–416`; `scripts/run_paypal_sandbox_demo.py:314–346`). Therefore a remote untrusted API caller cannot currently reach this method through the reviewed public routes. A caller inside the process (or a future endpoint that exposes the method) could pass `True`; that value still cannot make the provider GET report `APPROVED`, but it could initiate capture for a ledger-bound order which PayPal already reports as approved.

### Minimal safe decision

- Keep server-side PayPal retrieval as the authoritative approval check; it is already implemented and binds provider order ID to the durable canonical transaction, payee/merchant, amount, currency, and `APPROVED` state.
- Do not document or treat `buyer_approved=True`, the browser redirect, or local CLI input as approval evidence. Consider renaming the argument to `operator_confirmed` or removing it; if retained, define it only as a local human-intent check.
- Keep the capture operation local/internal unless a future route has explicit authentication and authorization for the capture action. Never accept a client boolean as provider proof.

### Required regression tests

1. `buyer_approved=True` plus provider GET `CREATED`/`PAYER_ACTION_REQUIRED` does not issue capture POST.
2. `buyer_approved=True` plus provider GET unknown/error does not issue capture POST.
3. A mismatched order ID, reference, merchant, amount, currency, or item in GET response does not issue capture POST.
4. A matching ledger-bound GET `APPROVED` permits only one persisted capture attempt; replay is reconciliation-only.
5. Keep existing false/missing-confirmation, HOLD/review, wrong-order-ID, capture timeout, and final completed-evidence tests.

Existing relevant tests include `tests/test_checkout.py::test_missing_explicit_buyer_approval_makes_no_provider_calls` (489–505), `test_authorize_low5_grant100_then_explicit_capture_verifies_get_and_is_idempotent` (299–345), `test_hold_and_review_released_never_checkout_or_capture` (431–453), `test_capture_timeout_becomes_unknown_and_reconcile_approved_never_retries` (455–486), and `test_capture_status_marker_is_persisted_before_capture_post` (348–375). The proposed positive-boolean/unapproved-provider-state cases are explicit additional coverage to add with any future authorized implementation change.

## 5. Prioritized minimal remediation plan

| Priority | Action | Files that would need changes | Security impact / acceptance criteria |
|---|---|---|---|
| P0 | Keep the correct lock-based test invocation; no risk-policy or test expectation change is needed for the three failures. | None for source; test setup/CI invocation only if an incomplete ad-hoc command is being used. | All four requested modules run with scikit-learn/NumPy from `requirements.lock`; three reported tests reach fake provider branches and pass. Missing model dependencies continue to fail closed as HOLD. |
| P1 | Separate production transport construction from test session injection and enforce verified TLS to the fixed Sandbox host. | `paypal_rest.py`; `tests/test_paypal_rest.py`. | Real-credential construction cannot receive `verify=False`, custom adapters, or arbitrary destinations; test fakes remain available only through a test-specific seam. |
| P1 | Reject non-finite, boolean, zero/negative, and over-limit timeouts. | `paypal_rest.py`; `tests/test_paypal_rest.py`. | Invalid settings fail before OAuth/order/GET/capture calls; bounded defaults remain unchanged. |
| P2 | Clarify human intent versus provider approval; retain the fresh ledger-bound GET gate. | `trustguard.py`; `tests/test_checkout.py`; only if runner wording/inputs change, `scripts/run_paypal_sandbox_demo.py`. | A true operator flag cannot substitute for provider state; non-APPROVED/mismatched GET never reaches capture; public API remains provider-free. |
| P2 | After approved code changes, rerun the four relevant modules under the exact lock and preserve the output. | No additional dependency changes; report/test evidence only. | Record actual results. Mock success is still not PayPal interoperability. |

**No V3/V4, production scoring model, threshold, dispatch policy, dependency specification, or source code has been changed as part of this plan.** Do not weaken HOLD or ALLOW behavior to make an incomplete environment appear successful.

## 6. Operator prerequisites before any Sandbox credential configuration

Credentials remain unconfigured/unverified for this plan; no environment values were inspected. Keep the operator prerequisites in `PAYPAL_SANDBOX_PREFLIGHT.md` marked BLOCKED until independently confirmed:

- Only a PayPal Sandbox REST application/client ID and its corresponding secret; never Live credentials.
- The Sandbox seller business account and exact PayPal merchant ID, distinct from the service identity.
- A Sandbox Personal buyer account.
- Secure secret injection outside source, shell arguments/history, reports and logs; do not treat `.gitignore` as filesystem security.
- A persistent SQLite path outside the repository, with restricted OS permissions; on Windows verify effective NTFS ACLs, since POSIX `0600` is not an ACL guarantee.
- Exact runner variables verified from `scripts/run_paypal_sandbox_demo.py::REQUIRED_ENV`: `TRUSTGUARD_LOCAL_SANDBOX_DEMO`, `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX`, `PAYPAL_ENV`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID`, `TRUSTGUARD_PAYPAL_MERCHANT_ID`, and `TRUSTGUARD_DATABASE_PATH`; identity selection uses `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` or the `SKYFIRE_SELLER_SERVICE_ID` fallback.
- The confirmed local CLI command is `python scripts/run_judge_demo.py --mode sandbox --confirm-sandbox`; this is a live Sandbox operation, not a dry run. Do not execute it as part of this diagnostic. The generated return and cancel URLs are loopback and callback receipt is not approval evidence.
- The local demo's generated credentials are LOCAL TEST ONLY, not genuine Skyfire authorization. Skyfire protocol/account onboarding remains separate and unverified.

## 7. Decision

**BLOCKED — do not configure Sandbox credentials or perform an operator checkout until the P1 TLS/session and timeout concerns have been remediated and independently reviewed, the capture trust boundary is documented/tested as above, and the exact locked test procedure is retained.** The three prior test failures themselves are explained by an incomplete test environment and are not a reason to weaken security or edit the expectations. The four relevant modules pass under the locked core dependencies, but no live PayPal/Skyfire integration was tested.

## Repository state

At completion of the diagnostic, verify the branch and HEAD remain `manus/paypal-sandbox-integration` / `abf5458cab2629f3c12e4fc4aee3920db8a7c54f`. Preserve the pre-existing modified `.gitignore` and untracked operator documents; only this requested remediation-plan Markdown file is added. No files are staged, committed, pushed, merged, or deployed.
