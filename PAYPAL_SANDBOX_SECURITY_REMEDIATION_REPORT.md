# PayPal Sandbox Capture-Boundary Security Remediation Report

**Repository:** `antonytampubolon2-cell/paypal-ai-trust-engine-v2`
**Branch:** `manus/paypal-sandbox-integration`
**HEAD:** `abf5458cab2629f3c12e4fc4aee3920db8a7c54f` (unchanged)
**Scope:** Sandbox-only transport hardening and defense-in-depth at the PayPal capture boundary. No provider interoperability test, credential use, order creation, payment capture, deployment, commit, or push was performed.

## Decision

**Implemented controls: PASS for the reviewed TrustGuard-to-PayPal path; live Sandbox execution: NOT AUTHORIZED / NOT VERIFIED. Stop for human engineering review.** The focused suite passed 160 tests and the full offline suite passed 381 tests. Tests use deterministic provider doubles, not PayPal. The remaining internal-API caveat and provider-state time-of-check/time-of-use window are documented below; do not configure live credentials or execute checkout on the basis of these test results alone.

## Capture call graph

The only non-test flow which requests capture is:

1. `scripts/run_paypal_sandbox_demo.py::run_demo` checks the operator-supplied PayPal order ID, asks for an explicit `APPROVE`, reconciles the order, and calls `TrustGuard.capture_approved_order` (`scripts/run_paypal_sandbox_demo.py:392-405`).
2. `TrustGuard.capture_approved_order` requires `operator_confirmed is True`, durable risk `ALLOW`, and a valid ledger order state; it reconciles from PayPal and requires `APPROVED`, writes the durable capture reservation with `Ledger.begin_capture`, then calls the provider (`trustguard.py:976-1026`).
3. `PayPalRestOrdersProvider.capture_order` requires the canonical transaction, stable order ID, and the same durable ledger; it atomically claims the one-shot reservation, retrieves the order again, validates exact order and transaction bindings and `APPROVED`, rechecks the claim, then issues one capture POST and verifies the response plus a final GET (`paypal_rest.py:378-434`).
4. Any uncertain or unverified result is recorded as `UNKNOWN`; capture is not retried. Completion requires independently verified capture evidence (`trustguard.py:1015-1025`; `paypal_rest.py:419-434`).

The inspected FastAPI routes are `/healthz`, `/v1/agent/authorize`, `/v1/agent/screen-transaction`, and `/v1/admin/transactions/{transaction_id}/review` (`app.py:249-253, 280-287, 316-336, 418-430`). The screen route is explicitly provider-free, and the review route is not a PayPal operation (`app.py:320-327, 383-426, 443-453`). No HTTP route initializes the PayPal adapter or calls either capture function. The only additional non-test provider method is the adapter definition itself. `main_public.py` remains a provider-free entrypoint. Therefore, **no untrusted HTTP caller or other production route bypass was found**.

## Security controls and evidence

### Sandbox origin, TLS, and timeout bounds

- `_new_sandbox_session` creates the adapter-owned `requests.Session`, sets `verify=True`, and sets `trust_env=False` (`paypal_rest.py:31-36`). The production provider constructor does not accept a caller-supplied session; tests install fake transports via a pytest-scoped monkeypatch of the private session factory. `trust_env=False` disables ambient proxy and CA-bundle overrides; deployments needing a corporate proxy/custom CA require a separately reviewed explicit design.
- `_provider_url` pins requests to HTTPS at the exact `api-m.sandbox.paypal.com` host, default/443 port, and the expected path, rejecting credentials, query/fragment, and unexpected path prefixes (`paypal_rest.py:143-157`). OAuth, order create, retrieval, and capture use this helper and disable redirects (`paypal_rest.py:159-172, 258-280, 337-349, 409-418`). The Live host cannot be selected through the adapter URL configuration.
- `_validated_timeout` rejects booleans, NaN, infinities, nonpositive values, unsupported shapes, and values above 60 seconds; scalar and two-element connect/read timeouts are supported (`paypal_rest.py:39-56`). The regression set accepts a 60.0-second component and rejects 60.0001 (`tests/test_paypal_rest.py:231-242`), alongside invalid-value/shape cases (`tests/test_paypal_rest.py:210-229`).

### Canonical order and provider evidence

- `_validate_order_binding` requires one purchase unit and binds the returned order to the canonical transaction reference, merchant/payee, Decimal amount and currency, and the fixed server-generated item, quantity, unit amount, and `item_total` (`paypal_rest.py:190-236`). `get_order_details` also checks the exact requested provider order ID and only returns `APPROVED` after that full binding succeeds (`paypal_rest.py:337-376`).
- Capture response acceptance requires the exact order ID and `COMPLETED`; final GET reconciliation must independently return verified completion and capture evidence whose unique capture IDs are `COMPLETED` and whose Decimal amounts sum to the canonical amount in the canonical currency (`paypal_rest.py:311-335, 425-434`).
- Order creation keeps the canonical create idempotency key in `PayPal-Request-Id` (`paypal_rest.py:258-280`). Capture uses the ledger-derived stable capture request ID in its own `PayPal-Request-Id` (`trustguard.py:663-683; paypal_rest.py:409-418`). No blind retry was added for create or capture. Ambiguous and failed capture paths remain reconciliation-only.

### Durable authorization and direct-adapter defense

- `Ledger.begin_capture` runs under `BEGIN IMMEDIATE`; it requires the existing transaction to be `APPROVED`, the exact stored order ID, a canonical merchant, durable ML `ALLOW`, and no prior capture attempt. It records a stable request ID, inserts a one-shot attempt, and moves the transaction to `DISPATCH_STARTED` before provider mutation (`trustguard.py:663-688`). The attempt table has a unique transaction binding; legacy attempts are upgraded as already consumed to prevent replay (`trustguard.py:281-299`).
- `_capture_record_matches` verifies the ledger row against the supplied canonical transaction, order ID, deterministic request ID, durable `ALLOW`, `DISPATCH_STARTED` state, and claim bit (`trustguard.py:591-630`). `claim_capture_dispatch` atomically consumes the unused reservation using an immediate write transaction (`trustguard.py:632-653`); `capture_dispatch_claim_valid` rechecks it before the POST (`trustguard.py:655-661`).
- The adapter requires the ledger parameter and refuses an absent or mismatched reservation before provider access (`paypal_rest.py:378-400`). It consumes the reservation once, performs a fresh bound GET, refuses to POST unless status is `APPROVED`, and revalidates the reservation immediately before dispatch (`paypal_rest.py:397-418`). If a completed order is independently verified by the preflight GET, it returns that evidence without another capture POST (`paypal_rest.py:400-406`).
- `TrustGuard.capture_approved_order` does not accept transaction terms from the caller, reconstructs the canonical transaction from the ledger, requires the operator-intent flag, and makes an independent provider reconciliation before reserving capture (`trustguard.py:976-1014`). The flag is local operator intent only; the PayPal GET is the buyer-approval evidence.

### Regression evidence

- Direct adapter capture with absent ledger/reservation and a forged `operator_confirmed` keyword makes no provider calls (`tests/test_checkout.py:379-391`).
- Direct adapter preflight rejects pending state, wrong order ID, wrong merchant, amount/currency/reference mismatch, and missing purchase unit without a capture POST (`tests/test_checkout.py:394-418`).
- Valid direct-adapter capture checks two order GETs before the single POST, a final GET after POST, and one-shot reservation consumption (`tests/test_checkout.py:421-443`).
- A provider state change between TrustGuard's first check and the adapter's fresh check prevents capture POST (`tests/test_checkout.py:445-464`).
- Existing TrustGuard success, durable marker ordering, idempotency, timeout-to-UNKNOWN/no-retry, and ledger-reopen evidence remain covered (`tests/test_checkout.py:321-377, 481-507, 588-620, 692-760`).
- The runner covers success, mismatched completion evidence, UNKNOWN, capture timeout, and the non-approved case without relying on a browser redirect as approval (`tests/test_sandbox_demo.py:309-379`). Public-route tests prohibit provider dispatch (`tests/test_skyfire_api.py:445-463, 601-614, 750-765`).
- Timeout boundary coverage: `tests/test_paypal_rest.py:210-242`.

## Residual risks and test gaps

1. **In-process operator-intent caveat.** The public Python method `Ledger.begin_capture` can be called by trusted in-process code that already holds the ledger and provider. For a transaction already in durable `APPROVED`/`ALLOW`, such code could create the reservation and invoke the adapter directly, thereby bypassing the `operator_confirmed` check in `TrustGuard.capture_approved_order` (`trustguard.py:663-683, 984-1002`; `paypal_rest.py:397-408`). This is not reachable through the reviewed HTTP routes and still cannot bypass canonical binding, one-shot persistence, or fresh PayPal `APPROVED` verification. If the requirement is that *only* the TrustGuard façade may authorize operator capture even against other in-process callers, reservation issuance needs a capability-restricted boundary and a dedicated rejection test before that stronger guarantee can be claimed. Current tests intentionally exercise the adapter with a prepared ledger reservation.
2. **Provider-state race.** The adapter checks PayPal immediately before POST, but PayPal may change order state between the GET and capture POST. No conditional provider-version precondition is available in this implementation. This residual TOCTOU is inherent to the current API sequence; the implementation fails closed on stale/mismatched GET results and does not retry.
3. **Conservative availability tradeoff.** The durable dispatch claim is consumed before the adapter preflight GET. A failed/ambiguous GET therefore leaves the attempt consumed and the transaction reconciliation-only, even if no capture POST reached PayPal. This is deliberate fail-closed behavior; it may need manual ledger/operator resolution.
4. **Targeted test omissions.** The direct-adapter negative matrix does not separately exercise a transport exception or non-2xx/malformed response specifically at the new preflight GET, nor every tampered persisted reservation field. The code maps these paths to ambiguous/unknown and uses the ledger matcher, but dedicated tests would improve evidence before any live checkout.
5. **No live PayPal/Skyfire verification.** OAuth credentials, seller/buyer accounts, merchant mapping, the actual Skyfire Seller Service profile, and real provider interoperability remain unverified. No credentials were accessed and no provider API was called.

## Protected model, V3/V4, and configuration

- `ANOMALY_THRESHOLD` remains `0.65` (`risk_scoring.py:22`). V3 model/evaluator/report files matched baseline `c137519b0bf3cc0c78e79e98841257761b49e29f` byte-for-byte. No V3/V4 benchmark output or `NO_VALID_CANDIDATE` result is used for payment authorization.
- The separate V4 worktree remains clean on `manus/trustguard-v4-evaluation` at `66a789db4cd9d0bcdbb0d8a5ba5bb49bf5a32e2c`. The preserved report SHA-256 is `85c367a4300873716762db801e83d493e25fe3787ddebcc7fc66881c711ffe80`; the preserved freeze SHA-256 is `da29739cee7f2c02d460b06caa19fc1c66e6a882713c7ee0e3716c867e2353d1`.
- No PayPal/Skyfire secret values were read or printed. Test fixture values are synthetic and provider requests were intercepted by doubles.

## Verification

The tested environment is the existing temporary environment installed from `requirements.lock`: Python 3.12.3, `pytest 8.4.2`, `requests 2.34.2`, `PyJWT 2.15.1`, `cryptography 50.0.2`, `pydantic 2.14.3`, `scikit-learn 1.6.1`, and `numpy 2.5.4`.

Focused command and result:

```bash
TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false \
  /tmp/trustguard-validation-venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_paypal_rest.py tests/test_checkout.py \
  tests/test_sandbox_demo.py tests/test_trustguard.py
# 160 passed in 8.07s
```

Full repository command and result:

```bash
TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false \
  /tmp/trustguard-validation-venv/bin/python -m pytest -q -p no:cacheprovider
# 381 passed in 218.95s (0:03:38)
```

`py_compile` passed for the changed Python modules and `git diff --check` passed. These are local regression checks only; no provider interoperability was tested.

## Changed files and Git state

The current cumulative application/test change set is:

- `paypal_rest.py`
- `scripts/run_paypal_sandbox_demo.py`
- `tests/test_checkout.py`
- `tests/test_paypal_rest.py`
- `tests/test_sandbox_demo.py`
- `trustguard.py`

The modified `.gitignore` and the pre-existing untracked `PAYPAL_SANDBOX_BLOCKER_REMEDIATION_PLAN.md`, `PAYPAL_SANDBOX_OPERATOR_RUNBOOK.md`, `PAYPAL_SANDBOX_PREFLIGHT.md`, and `PAYPAL_SANDBOX_SOURCE_CODE_AUDIT.md` were preserved. This remediation report is also untracked. At final verification, no files were staged; no commit, push, merge, deployment, credential access, or provider call was made. HEAD remains `abf5458cab2629f3c12e4fc4aee3920db8a7c54f`.

## Recommendation

**READY FOR HUMAN ENGINEERING REVIEW; NOT READY FOR LIVE SANDBOX CHECKOUT.** Review the in-process reservation/intent boundary and the identified test gaps before configuring credentials. Then independently verify the operator preflight and account prerequisites. Do not enable or execute provider dispatch until that review explicitly authorizes it.
