# TrustGuard Skyfire Seller Service backend

This repository includes a FastAPI service for validating Skyfire KYAPay tokens. Token validation is not PayPal authorization: the API does not initialize the PayPal adapter, create an order, capture funds, or report PayPal payment success. Keep `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX` unset or `false`; the HTTP API never invokes the adapter.

**Demo limitation:** no actual Skyfire-issued Sandbox token has been verified by this project, and no PayPal Sandbox order/capture success is claimed or shown. Tests use generated tokens and mock provider responses only. Confirm Skyfire onboarding metadata before accepting real tokens.

The API accepts `skyfire-pay-id` as requested. Skyfire currently documents `kyapay-token` as preferred and `skyfire-pay-id` as deprecated; this service retains the latter for compatibility. [Skyfire Seller Services](https://docs.skyfire.xyz/docs/seller-services)

## HTTP endpoints

- `GET /healthz`: `200` when the required configuration and durable SQLite ledger are ready; otherwise `503`.
- `GET /openapi.json`: generated OpenAPI document only when `TRUSTGUARD_OPENAPI_ENABLED=true`; publication is disabled by default. Its configured path defaults to `/openapi.json` and may be changed with `TRUSTGUARD_OPENAPI_PATH`. Interactive `/docs` and `/redoc` are disabled. No public server URL is embedded. The current header/claim contract is unresolved for the actual Skyfire account; do not treat this schema as approved interoperability.
- `POST /v1/agent/authorize`: validates the signed token and returns a minimized claim projection. The response explicitly says `paypal_payment_status: NOT_STARTED` and `paypal_payment_authorized: false`.
- `POST /v1/agent/screen-transaction`: requires a valid Skyfire PAY/KYA-PAY token, validates a canonical request, durably reserves it against an identity derived from verified token claims, and invokes the existing local IsolationForest scorer. It returns `ALLOW` or `HOLD`, a reason code, and persisted model metadata. This route has no provider dependency and never creates or captures a PayPal order.
- `POST /v1/admin/transactions/{transaction_id}/review`: when separately configured, records `KEEP_HOLD` or `RELEASE_RESERVATION` with a review reason. Release marks only a still-undispatched HOLD as `REVIEW_RELEASED`; it does not authorize payment.

The API does not use `jti` as a request id or one-use replay key. The verifier requires a UUID-format `jti` as the token identifier, but repeated presentation of the same valid token is permitted until its expiration. The API does not persist `jti`, the raw token, or `sti`. A repeated token is not itself a second PayPal operation: actual dispatch de-duplication remains tied to TrustGuard's separate canonical application `transaction_id` and `idempotency_key`, recorded atomically by its SQLite ledger. The `/v1/agent/authorize` endpoint itself initiates no payment operation. The separate legacy TrustGuard DPoP/access-token path retains its own replay checks; it is not used by this Skyfire endpoint.

The response may include `sub`, `aud`, `tsi`, `tdm` (only when configured), `amt`, and `cur`. It never returns the token, `sti`, or `val`; it does not log or persist token contents or settlement information. A Skyfire PAY or KYA-PAY token is only a signed Skyfire token signal and does not authorize a PayPal debit.

## Local ML anomaly screening (not a production fraud detector)

The repository now contains real local scikit-learn inference in the `RiskScreeningPipeline` shared with `TrustGuard.authorize_and_dispatch` (`trustguard.py`), using `SyntheticIsolationForestScorer` in `risk_scoring.py`. `POST /v1/agent/screen-transaction` verifies the Skyfire token first and then invokes that provider-free pipeline. `POST /v1/agent/authorize` only validates Skyfire claims; it does **not** call transaction scoring. The static dashboards do not run inference either.

The estimator is `sklearn.ensemble.IsolationForest`, versioned as `trustguard-isolation-forest-synthetic-v1`. Its deterministic configuration is 128 trees, `max_samples=256`, `contamination=0.04`, `random_state=20261104`, and `n_jobs=1`. It is lazily fitted from 768 synthetic routine-like feature rows generated with NumPy seed `20261104`; the documented feature distributions are amount/grant ratio `Beta(2,4) × 0.70`, cumulative utilization `Beta(1.5,3) × 0.82`, recent velocity `Beta(1.2,8)`, and new-payee indicator `Binomial(1,0.25)`. No real customer, merchant, or payment data is used. The declared dependency is pinned to `scikit-learn==1.6.1`.

Immediately after signed access-token and DPoP verification, authenticated grant currency/payee/limit checks, and the durable spending reservation—and before persisting `DISPATCH_STARTED` or calling any provider—the guard derives four features from the canonical transaction and existing ledger: `amount_to_grant_ratio`, `cumulative_spending_ratio`, `recent_velocity_ratio` (prior active transactions in the preceding ten minutes, normalized/capped at five), and `new_payee`. No caller-supplied risk feature is accepted. The model's IsolationForest margin is sigmoid-mapped to a 0–1 **anomaly ranking score**, with `HOLD` at score ≥0.65. This is not a calibrated probability of fraud, and this synthetic model is not validated for production or payment authorization.

The static `dashboard_v2.html` can display the `risk_assessment.explanation` returned with sample data or a locally selected screening response. It also accepts the complete JSON report emitted by the offline judge demo and renders scenario decisions, scores, durable states and the `SIMULATED` / `NOT_DISPATCHED` labels. Imported files are explicitly presented as local, unverified evidence; the dashboard does not connect to the backend, run inference, or represent a real Sandbox transaction. Explanation fields are deterministic rule annotations describing scored signals; they are **not causal feature attribution** from the IsolationForest. They cannot override a persisted decision or authorize, release, or dispatch payment. Invalid or unrelated imported JSON is rejected, and displayed fields use text rendering rather than HTML interpretation.

The screening route binds currency to the signed token and obtains Skyfire `tsi` only from verified claims. The request body has no payee or merchant-ID field. Signed `amt` is treated as the maximum authorized amount. Requests above that cap are rejected; lower amounts remain within the signed ceiling. A deterministic grant-ledger identity is derived from verified issuer, subject, audience, and service ID. The screen-only state `SCREENED_ALLOW` is distinct from provider dispatch. HOLD and ALLOW reservations remain counted against cumulative ledger limits unless an authenticated reviewer releases a still-undispatched HOLD as `REVIEW_RELEASED`. Release only abandons the reservation; it never changes the ML HOLD decision into ALLOW, authorizes payment, or starts dispatch. Risk evidence is persisted in SQLite. The screening route never constructs a provider and reports `paypal_dispatch: DISABLED_NOT_CALLED`. PayPal Sandbox dispatch remains opt-in and disabled by default elsewhere.

Skyfire `tsi` and PayPal merchant ID are separate identifier namespaces and are persisted separately as `skyfire_service_id` and `paypal_merchant_id`. The trusted server-side mapping requires `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID` (must exactly equal `SKYFIRE_SELLER_SERVICE_ID`) and `TRUSTGUARD_PAYPAL_MERCHANT_ID`. Neither value is accepted from the screening request. If mapping values are missing or inconsistent, the response says `paypal_integration_status: NOT_CONFIGURED` and the ledger stores no PayPal merchant ID. A configured mapping says only `CONFIGURED`; it does not enable or invoke PayPal.

Administrative review is disabled unless both `TRUSTGUARD_REVIEWER_ID` and `TRUSTGUARD_REVIEWER_CREDENTIAL` are present. Reviewer identity is server-configured; the credential is compared in constant time and never returned or logged. The durable audit records reviewer ID, decision, reason, and timestamp. Only an exact repeat of the same authenticated decision/reason is idempotent; conflicting later reviews are rejected. `UNKNOWN`, `DISPATCH_STARTED`, any non-HOLD state, and any row with a provider order ID cannot be released. Keep the reviewer credential in a secret manager/environment injection, never in source, README examples, or shell history.

## Public API security and deployment controls

The FastAPI process applies a 1 MiB request-body limit by default, counting received ASGI body chunks even when `Content-Length` is absent. The limit is configurable with `TRUSTGUARD_MAX_REQUEST_BODY_BYTES` (1 KiB–10 MiB). Admission is bounded to 16 concurrent requests by default (`TRUSTGUARD_MAX_CONCURRENT_REQUESTS`, 1–256), and a 30-second ASGI request deadline is applied (`TRUSTGUARD_REQUEST_TIMEOUT_SECONDS`, 1–300). A timed-out synchronous worker-thread operation cannot be forcibly killed by Python; the concurrency bound still caps outstanding work, and the host ingress should enforce its own connection and response deadlines. These values are operational safeguards, not Skyfire protocol settings; adjust only after workload review. Keep one Uvicorn worker with SQLite.

A process-local fixed-window limiter defaults to 120 requests per direct socket peer per 60 seconds. It never trusts `X-Forwarded-For` or similar caller-provided headers. Behind a reverse proxy, the app therefore sees the proxy as the peer; configure rate limits and connection/body/time limits at the trusted ingress as well. Do not make the app trust forwarded client-IP headers without a separately reviewed trusted-proxy configuration. A service host must configure ingress limits; app-level limits alone are not a substitute for volumetric DDoS protection.

`TRUSTGUARD_ALLOWED_HOSTS` is an explicit comma-separated allowlist; absent configuration permits only local/test hostnames, not an arbitrary public hostname. Set the actual assigned deployment host before public exposure; no hostname is assumed here. CORS remains disabled because this is server-to-server. Do not enable wildcard credentialed CORS. `GET /healthz` remains minimal and reports only readiness status.

The image preserves UID/GID 10001 and defaults `PORT` to 8000; Uvicorn and the Docker health check use the same `PORT` value. `TRUSTGUARD_DATABASE_PATH` defaults to `/data/trustguard.sqlite3`, and `/data` is declared as a Docker volume. **A Docker `VOLUME` declaration alone does not provide durable host storage, backups, or restore capability.** Mount a persistent host volume at `/data`, confirm UID 10001 can write it, and keep one instance/worker. Persistence tests only verify reopening the same local file; they do not verify any provider backup/restore service.

Use the exact Python 3.12 pins in `requirements.lock` for Docker and CI (`python -m pip install -r requirements.lock`). `requirements.txt` remains the direct dependency declaration; dependency refreshes must be reviewed and update the lock coherently. OpenAPI 3.1.0 documents are formally validated in tests/CI with `openapi-spec-validator`. Authentication profile semantics deliberately remain unmodeled as an OpenAPI security scheme until Skyfire confirms the account's actual protocol; no security scheme or public server URL is guessed.

## Reproducible offline synthetic model evaluation

After installing the exact pins from `requirements.lock`, run from the repository root:

```bash
python scripts/evaluate_risk_model.py
```

This atomically writes `evaluation/synthetic_report.json`. To reproduce the JSON byte-for-byte in the same dependency environment, supply a fixed UTC run timestamp and an output path:

```bash
python scripts/evaluate_risk_model.py --timestamp 2026-11-04T17:15:00Z --output /tmp/trustguard-synthetic-report.json
```

The benchmark calls the existing `SyntheticIsolationForestScorer.score` and uses the unchanged **0.65** HOLD threshold. It never imports the authentication/payment pipeline, creates ledger transactions, contacts providers, tunes the threshold, or changes runtime model behavior. Training uses the existing seed `20261104`; independent validation and holdout evaluation use `20261105` and `20261106`. Exact feature-vector fingerprints are checked for overlap across training, validation and evaluation. Validation is reported separately and is not used for fitting, model selection, or threshold selection.

The holdout contains deterministic labeled normal and anomalous scenarios: routine known payee, routine new payee, high grant utilization, elevated velocity, new payee with high utilization, and combined extreme features. **A new payee alone is labeled normal.** Labels come from predefined synthetic scenario definitions, not from model predictions. They are benchmark anomaly labels, not observed fraud labels. The report includes dataset/model IDs, split seeds and fingerprints, sample counts, threshold, timestamp, confusion matrix, precision, recall, F1, false-positive rate, ROC-AUC, average precision, per-scenario results, and per-sample holdout results. Undefined metrics are recorded as JSON `null` with reasons rather than fabricated values.

**All reported metrics are synthetic benchmark results—not real-world fraud detection performance.** Generator labels, class balance and easy extreme patterns can make metrics optimistic or unrepresentative. Separate seeds and row-overlap checks prevent sample leakage, but do not make this benchmark representative of real transactions. The anomaly score is a ranking signal, not a calibrated fraud probability. Real labeled data, independent validation and operational false-positive analysis remain necessary before any production use.

### Validation-only threshold calibration (candidate only)

The separate calibration command uses only the validation split (`20261105`) to select a candidate. It does **not** activate it or change production decisions:

```bash
python scripts/calibrate_risk_threshold.py --max-validation-fpr 0.01
```

This writes `evaluation/calibration_report.json`. `--max-validation-fpr` is a fraction (0.01 means 1%); `--output` selects a different report path and `--timestamp` supplies a fixed UTC timestamp for reproducibility in the same dependency environment. No provider credentials are needed.

Candidate thresholds cover the validation scores and their immediate floating-point boundary successors for the unchanged `score >= threshold` HOLD rule. The selector maximizes validation recall subject to the configured empirical FPR ceiling, breaking ties by lower FPR and then higher threshold. Neither training labels nor locked holdout labels enter selection. If no candidate has defined recall/FPR and satisfies the ceiling, the report explicitly records `NO_VALID_CANDIDATE` and a null candidate; it does not fall back to a fabricated or production threshold.

Selection is frozen before accessing the locked holdout (`20261106`). Its feature fingerprint must match the existing benchmark, and each holdout row is scored once per calibration run. Baseline 0.65 and the candidate are compared using those same cached scores; the holdout is never searched for thresholds or used to retune a disappointing result. The report includes the full validation tradeoff table, selected threshold and validation metrics, baseline/candidate holdout metrics, scenario-level comparisons, dataset fingerprints, timestamps and methodology. Ranking ROC-AUC and average precision use the same scores and therefore are unchanged by a threshold change.

**Production remains at 0.65.** These are synthetic benchmark results, not fraud-detection guarantees or calibrated probabilities. The 1% ceiling constrains observed validation FPR, not a statistical upper bound or production FPR. With 80 normal validation examples, one false positive already exceeds 1%, so the default constraint permits zero validation false positives. The holdout was previously inspected for baseline performance; this calibration enforces validation-only selection rather than claiming a previously unseen external validation dataset. Any deployment/policy change would require a separate authorized task and representative labeled-data validation.

### IsolationForest v2 candidate (offline only)

```bash
python scripts/evaluate_candidate_v2.py --max-validation-fpr 0.01
```

The command writes `evaluation/synthetic_v2_candidate_report.json` and `evaluation/synthetic_v2_candidate_metadata.json`. `--output`, `--metadata-output` and `--timestamp` support alternate paths and fixed-time reproducibility. No credentials or real transactions are involved.

The fixed candidate design is `trustguard-isolation-forest-synthetic-v2-candidate`, representation `trusted-upper-tail-marginals-v2`. It learns upper-tail offsets/scales from the existing training rows only for amount/grant ratio, cumulative utilization and velocity, preserves the trusted binary new-payee signal, and fits four independent one-feature IsolationForests. Its maximum marginal anomaly ranking lets an isolated signal contribute without dilution by otherwise routine features. The representation and forest parameters are fixed before validation; no validation or holdout labels are passed to fitting. This is a genuine sklearn inference ensemble, not a deterministic fraud rule or a calibrated probability.

Validation seed `20261105` compares production v1 at 0.65, validation-calibrated v1, and the candidate. The predeclared selection gate requires observed validation FPR at most 1%, better overall recall, and better isolated utilization and velocity recall than calibrated v1. Eighty normal validation samples mean one false positive already exceeds 1%. A failing candidate is rejected explicitly; production is never switched to it.

The candidate model metadata and validation-selected threshold are frozen before fresh holdout seed `20261107` is generated/scored. The previously disclosed `20261106` split is not used for v2 fitting, selection, or tuning. All comparisons on the fresh holdout reuse cached per-model scores, with overall and scenario-level confusion matrices, precision, recall, F1, FPR, ROC-AUC and average precision. Independent split fingerprints and the frozen candidate fingerprint are recorded. Repeated deterministic test runs verify reproducibility; they do not initiate further tuning from holdout results.

**These are synthetic benchmark results, not real-world fraud-detection guarantees.** Validation has already informed previous work, so results still require genuinely independent representative data and a separate authorized review before any production integration. Production remains the existing v1 scorer at threshold **0.65**, with all authentication, reservation, reviewer and payment safeguards unchanged.

### Synthetic Benchmark v3 — separate offline research

```bash
python scripts/evaluate_benchmark_v3.py --max-validation-fpr 0.01
```

Outputs are `evaluation/synthetic_v3_research_report.json` and `evaluation/synthetic_v3_research_freeze.json`. The freeze artifact is written before final holdout generation. `--output`, `--metadata-output` and a fixed UTC `--timestamp` support reproducible research runs; the runner rejects attempts to overwrite existing non-v3 repository artifacts. No production configuration or provider credentials are required.

**Historical context:** the v2 read-only audit reproduced perfect synthetic scores without direct label/scenario inputs to fitting. However, its labels were recoverable by cumulative utilization ≥0.8 OR velocity ≥0.8, its training support differed from ledger features, and feature provenance mixed the raw-schema identifier `trusted-risk-features-v1` with transform identifier `trusted-upper-tail-marginals-v2`. Its 0/160 observed false positives had a one-sided 95% binomial upper bound of about 1.855%, not a ≤1% population guarantee. V1/v2 code, thresholds, metadata and historical reports remain unchanged.

V3 uses the same four canonical signals from `Ledger.risk_features` (`trustguard.py`): exact minor-unit amount/grant ratio; cumulative active spending including the current transaction; active ten-minute transaction count normalized/capped at five; and binary payee history. Histories respect currency/grant filters, active states, current-transaction exclusion, positive integer minor units, cumulative utilization ≥amount utilization, and velocity values `{0,0.2,0.4,0.6,0.8,1}`. Tests compare offline features with the real extractor on equivalent temporary synthetic ledger histories. No runtime feature is added.

The explicit v3 feature identifier is **`trustguard-canonical-ledger-v3-research`**. It binds this canonical input contract and research provenance, not a new live schema. Internal raw/interaction representations are separately named model configurations. V3 rejects incompatible feature/model metadata, including either historical v2 identifier; it never silently falls back. Historical raw-schema versus transformed-representation names are explained here rather than rewriting frozen v2 artifacts.

The generator includes benign high utilization, benign high velocity, benign new payees, abusive counterparts with overlapping feature support, low-signal anomalies and smooth interaction scenarios. Labels are stochastic synthetic latent-context outcomes, not simple utilization/velocity threshold labels. Scenario descriptions, latent context and `hidden_label` remain outside the scorer matrix. Within-split equal-feature/opposite-label examples explicitly demonstrate irreducible ambiguity; they are not copied across splits. The training mixture is fit as unlabeled feature data, without filtering on hidden targets.

Data-generation seeds are training `20261110`, validation `20261111`, final holdout `20261112`, and diagnostics `20261113`; forest random states use separate identifiers. Two predeclared IsolationForest configurations (raw and interaction representation) are fitted on training only. Validation selects the candidate/threshold for maximum observed recall under the empirical FPR ceiling with deterministic ties. Source/data/model/threshold fingerprints are frozen before holdout generation. The holdout includes known scenarios and predeclared previously unseen feature combinations. A freeze digest documents in-run ordering; it is not independent external proof that no earlier experiments occurred.

The report records confusion matrices, precision, recall, F1, ROC-AUC, average precision, known/unseen and per-scenario false positives/negatives, nominal confidence intervals and one-sided 95% upper FPR bounds. Robustness checks cover ablation, supported perturbations, boundaries, training-range OOD flags and unsupported inputs. Counterfactual ablations retain original synthetic labels and are reliance diagnostics, not causal attribution. Binomial/bootstrap intervals are synthetic reference summaries with stated independence assumptions; matched examples and scenario strata limit interpretation. **Neither observed synthetic FPR nor its interval is a real-world population guarantee.** Production remains v1 at 0.65; v3 is not integrated into authorization or payment dispatch.

## Required environment variables

The API fails closed unless these variables are set:

- `SKYFIRE_ISSUER`: trusted issuer origin. For the only supported configuration in this version, set it to `https://app-sandbox.skyfire.xyz`.
- `SKYFIRE_JWKS_URL`: trusted key-set URL. For this supported Sandbox configuration, set it to `https://app-sandbox.skyfire.xyz/.well-known/jwks.json`.
- `SKYFIRE_EXPECTED_ENVIRONMENT`: expected token `env`; this Sandbox-only implementation requires `sandbox`.
- `SKYFIRE_SELLER_AGENT_ACCOUNT_ID`: configured Seller Agent Account ID; must exactly match `aud`.
- `SKYFIRE_SELLER_SERVICE_ID`: configured Seller Service ID; must exactly match draft-03 `tsi` (Target Service ID). Legacy `ssi` is not accepted as a substitute.
- `TRUSTGUARD_DATABASE_PATH`: durable SQLite file path used by the TrustGuard transaction ledger. `:memory:` is rejected. The container sets `/data/trustguard.sqlite3` and the `/data` volume should be persistent.

Optional integration-specific variable:

- `SKYFIRE_TARGET_DOMAIN`: set only when this integration identifies its target by domain. When set, token `tdm` must exactly match this value. When unset, `tdm` is not required or returned.

Optional trusted Skyfire-to-PayPal mapping (both must be set; otherwise `paypal_integration_status` is `NOT_CONFIGURED` and no merchant ID is stored; neither enables PayPal dispatch):

- `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID`: source Skyfire Seller Service ID for the mapping; must exactly equal `SKYFIRE_SELLER_SERVICE_ID`, otherwise the mapping is treated as inconsistent.
- `TRUSTGUARD_PAYPAL_MERCHANT_ID`: PayPal merchant account identity mapped to that service ID; must differ from the Skyfire service ID; never accepted from an HTTP request.

Optional administrative HOLD review (both must be set; otherwise the review endpoint returns `503` and performs no action):

- `TRUSTGUARD_REVIEWER_ID`: server-configured reviewer identity recorded in the audit trail.
- `TRUSTGUARD_REVIEWER_CREDENTIAL`: reviewer secret compared in constant time against the `x-trustguard-reviewer-credential` header; keep it in secret storage and never print, log, or commit it.

The implementation accepts only the documented Sandbox issuer/JWKS pair above, requires HTTPS, checks that JWKS is the well-known URI formed from the configured issuer, and never derives a URL from the token's untrusted `iss`. The configured expected environment must be `sandbox`. It uses ES256 only; requires `kid` and `typ` (`kya+jwt`, `pay+jwt`, or `kya-pay+jwt`); validates signature, `iss`, `aud`, `env`, `tsi`, `iat`, `exp`, and UUID `jti`; and caches validated public keys for 300 seconds. The cache does not refresh on attacker-supplied unknown `kid` values. For PAY/KYA-PAY, it additionally validates positive `amt`/`val`, `cur=USD`, `stp` in `coin`/`card`/`bank`, and `sti.verified=true` without returning or storing `sti`.

### Sandbox issuer/JWKS source and limits

Skyfire's official verification guide lists `https://app-sandbox.skyfire.xyz/.well-known/jwks.json` as the Sandbox JWKS endpoint (the production key URL is separate). KYAPay Internet-Draft version 03 specifies that the JWKS URI is formed from the trusted `iss` origin by appending `/.well-known/jwks.json`. Together these official sources support the configured Sandbox pair `https://app-sandbox.skyfire.xyz` plus its documented JWKS URL. The implementation requires both values explicitly and rejects other pairs. [Skyfire Verify and Extract Data](https://docs.skyfire.xyz/docs/verify-and-extract-data-from-tokens) [KYAPay Internet-Draft](https://datatracker.ietf.org/doc/draft-skyfire-oauth-kyapay-token/)

The code has not inspected an actual Sandbox-issued token. Before accepting tokens outside local tests, compare the token's actual `iss`, `env`, `aud`, and `tsi` with the configured Sandbox values and confirm the Skyfire onboarding service identifier. If Skyfire's actual Sandbox metadata differs, stop and obtain confirmation before changing the allowlisted pair; do not substitute a guessed issuer or key URL. `https://api-qa.skyfire.xyz/api/v1/tokens` is a token-creation API, not a JWKS endpoint, and is not used here.

## Other environment variables in existing code

These are not consumed by the FastAPI Skyfire verifier; they remain for the separate legacy `TrustConfig.from_env()` helper in `trustguard.py`:

- `TRUSTGUARD_ISSUER`: issuer for that legacy helper.
- `TRUSTGUARD_AUDIENCE`: audience for that helper.
- `TRUSTGUARD_JWT_PUBLIC_KEYS_JSON`: JSON map of `kid` to trusted public PEM.
- `TRUSTGUARD_JWT_ALGORITHMS`: optional comma-separated algorithm allowlist; defaults to `ES256`.
- `TRUSTGUARD_GRANT_ID_FIELD`: authenticated grant identity field name.
- `TRUSTGUARD_GRANT_LIMIT_FIELD`: authenticated grant spending-limit field name.
- `TRUSTGUARD_GRANT_CURRENCY_FIELD`: authenticated grant currency field name.
- `TRUSTGUARD_GRANT_PAYEES_FIELD`: authenticated grant payee-list field name.

Do not invent legacy issuer, audience, signing-key, or grant-claim values. The Skyfire API does not consume or infer them.

These optional variables apply only to the separate PayPal Sandbox adapter, not the FastAPI endpoint:

- `PAYPAL_CLIENT_ID`: Sandbox app client ID, needed only to construct the separate provider.
- `PAYPAL_CLIENT_SECRET`: Sandbox app secret; load securely and never print or commit it.
- `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX`: must be exactly `true` for the separate adapter to issue Sandbox calls. It is disabled by default and set to `false` in the Docker image. Do not enable for the API service.

## Operator-run LOCAL SANDBOX checkout (not verified Skyfire integration)

The unified launcher routes only to the separate, explicitly acknowledged localhost Sandbox CLI; it does not add a public FastAPI payment endpoint. The existing `scripts/run_paypal_sandbox_demo.py` workflow shows its allowlisted model decision/score/explanation, creates an order only after `ALLOW`, labels `ORDER_CREATED`, then requires manual order-ID matching, the operator's explicit `APPROVE` entry, and a PayPal GET that independently verifies `APPROVED` before capture. It reports `CAPTURE_COMPLETED` only after final verified reconciliation; ambiguous outcomes remain `UNKNOWN` with no automatic retry. A callback is not used as proof. Tests use mocked HTTP responses only; no genuine Sandbox order or capture is claimed by this repository.

Install the reviewed exact pins from `requirements.lock`, then securely inject all of these settings on your own local machine (never paste secrets into source, logs, command history, or this README):

| Variable | Purpose |
| --- | --- |
| `TRUSTGUARD_LOCAL_SANDBOX_DEMO=true` | Explicit opt-in to generated LOCAL TEST ONLY authorization and localhost callbacks; unset by default. |
| `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true` | Separate explicit opt-in for calls only to `https://api-m.sandbox.paypal.com`. |
| `PAYPAL_CLIENT_ID` | Sandbox application client ID. |
| `PAYPAL_CLIENT_SECRET` | Sandbox application secret, securely injected. |
| `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` | Pre-onboarding synthetic identity; must start with `LOCAL-TEST-ONLY-PAYPAL-` (maximum 128 characters). Never put it in official Skyfire settings. |
| `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID` | Explicit mapping source; must exactly equal the chosen synthetic local identity. |
| `TRUSTGUARD_PAYPAL_MERCHANT_ID` | Operator-confirmed receiving Sandbox merchant account ID; distinct from the service ID. |
| `TRUSTGUARD_DATABASE_PATH` | Persistent file-backed SQLite ledger retained for ambiguous-outcome reconciliation. |

For a separately gated, operator-controlled actual PayPal Sandbox checkout, explicitly select Sandbox mode and acknowledge that it may create a Sandbox order:

```bash
python scripts/run_judge_demo.py --mode sandbox --confirm-sandbox
```

For example, these **non-secret synthetic test settings** need no official Skyfire onboarding:

```bash
export TRUSTGUARD_LOCAL_SANDBOX_DEMO=true
export TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true
export TRUSTGUARD_LOCAL_TEST_SERVICE_ID=LOCAL-TEST-ONLY-PAYPAL-DEMO-SERVICE
export TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID=LOCAL-TEST-ONLY-PAYPAL-DEMO-SERVICE
```

Securely inject your actual Sandbox `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, receiving `TRUSTGUARD_PAYPAL_MERCHANT_ID`, and persistent `TRUSTGUARD_DATABASE_PATH` separately. Those values are not invented by the runner. `SKYFIRE_SELLER_SERVICE_ID` is **not required** for synthetic local mode. As a compatibility alternative, omit `TRUSTGUARD_LOCAL_TEST_SERVICE_ID` and supply an actual confirmed `SKYFIRE_SELLER_SERVICE_ID` with matching mapping source. Do not silently substitute a real service ID for a synthetic one; the selected identity is bound into the canonical ledger transaction.

The CLI retains an optional callback listener bound only to literal `127.0.0.1` on an ephemeral port; it never waits for a callback to allow manual approval. No public callback, port forwarding, or listening address other than loopback is needed. Do not deploy or expose it publicly. The Docker API image does not include the scripts. Missing gates or mapping values fail before contacting PayPal. Generated ES256 access credentials and DPoP proofs stay in memory and are labelled **LOCAL TEST ONLY**; their issuer is the localhost demo origin, not Skyfire. Synthetic mapping is rejected unless the local-demo opt-in is true; the adapter additionally requires loopback local authorization configuration. The production Skyfire settings reject the reserved `LOCAL-TEST-ONLY-PAYPAL-` namespace regardless of the demo flag. Official issuer/JWKS discovery and JWT validation are unchanged. Local credentials never become authentic Skyfire authorization, and the Sandbox host cannot be configured to a production payment host.

The canonical demonstration amount is **USD 5.00**, screened by the existing IsolationForest against a synthetic local USD 100.00 grant. The configured service and merchant remain separate persisted fields. HOLD and REVIEW_RELEASED cannot proceed to checkout. Only the actual Sandbox buyer approval URL returned by PayPal, bound to the order ID, is displayed; no order or capture IDs are invented. Open it with a Sandbox Personal account. After approving, copy the PayPal order ID from the returned URL's `token` parameter (or the original displayed order result) into the terminal's **Returned PayPal order ID** prompt. Enter the ID only, not the URL, a JWT, or a credential. The runner requires an exact match with the original persisted order. Then type literal `APPROVE`. Neither entered text nor an optional callback proves approval: authenticated GET must verify the exact bound order is `APPROVED` before the existing durable capture safeguards permit POST. A mismatch stops without capture; no automatic retry occurs.

Creating an order never reports a completed payment. Create dispatch is durable before its POST. Capture has a separate stable `PayPal-Request-Id` and a one-time durable marker committed before its POST; duplicate capture attempts are blocked even after restart. Completed capture requires authenticated GET evidence matching the canonical transaction reference, exact amount/currency, configured merchant, and completed capture IDs. Normalized evidence is persisted atomically with transaction state; raw provider bodies, OAuth tokens and settlement data are not stored. The CLI performs a final GET reconciliation and only reports success from verified evidence.

Any ambiguous create/capture outcome becomes `UNKNOWN` (or remains durably dispatch-started if the database fails after the call). Stop and preserve the ledger; **never rerun the demo as an automatic retry**. This CLI starts a new explicitly authorized demo transaction on each run, not recovery of an earlier one. For an existing order, use the separate `TrustGuard.reconcile(transaction_id)` operation with trusted configuration; an unknown create without a saved order ID requires manual provider investigation. If a capture marker exists, even a later `APPROVED` GET permits reconciliation only, never another capture POST. No public payment or capture endpoint is added.

All repository tests and CI use mocks and run without real provider credentials. The model is trained on synthetic data, not validated for production fraud detection. Real Skyfire onboarding/token metadata and any official merchant-to-service mapping still need operator confirmation; the synthetic test mapping deliberately proves neither. PayPal remains disabled by default everywhere outside this explicitly opted-in local operator flow. After your local run, unset both opt-in flags and `TRUSTGUARD_LOCAL_TEST_SERVICE_ID`.

## Safe local testing and run

Tests need no Skyfire or PayPal credentials. They generate ES256 keys and tokens, fake JWKS responses, and use temporary SQLite databases; they do not perform external HTTP requests.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
export TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false
pytest -q
```

### LOCAL TEST ONLY screening demonstration

After installing `requirements.lock`, the unified judge entry point runs the full offline demonstration by default:

```bash
python scripts/run_judge_demo.py --mode offline
```

To load the generated scenario evidence into the static dashboard, save the JSON output and open `dashboard_v2.html` locally:

```bash
python scripts/run_judge_demo.py --mode offline > /tmp/trustguard-judge-demo.json
```

The dashboard is only a local report viewer; imported rows stay labeled `SIMULATED` and `NOT_DISPATCHED`. The previous direct command, `python scripts/run_local_demo.py`, remains available.

Dependencies are the project's existing PyJWT/cryptography, FastAPI, requests, and scikit-learn (pinned to 1.6.1); the in-process ASGI HTTP test client uses only the Python standard library and requires no httpx or running server. Python 3.12 matches CI and Docker. No provider credentials or environment configuration are required for this runner.

The runner generates an ephemeral ES256 key and clearly synthetic Skyfire-like claims, injects a local public-only mock JWKS into the **unchanged** `SkyfireTokenVerifier`, and uses the actual FastAPI screening/review routes. It creates an isolated application with a temporary SQLite ledger and an ephemeral reviewer credential held only in memory. It clears ambient configuration for the duration of the run, explicitly disables PayPal dispatch, and restores the caller's environment afterwards. Provider spies and outbound-network guards are active throughout. No token, private key, settlement claim, or reviewer credential is printed or saved. The temporary database is removed after reopening it and verifying restart evidence.

Output is JSON with a prominent `LOCAL TEST ONLY` disclaimer, scenario records, HTTP route names, an actual model-inference count, and provider/network counters. All scenario outcomes are labelled `SIMULATED`; payment status is always `NOT_DISPATCHED`. Expected scenario results with the current pinned model are:

| Scenario | Transaction | Risk decision | Anomaly score (approximately) | Durable state / evidence |
| --- | --- | --- | --- | --- |
| A — low risk | `LOCAL-TEST-ONLY-LOW` | ALLOW | 0.415589 | Valid simulated screening; `SCREENED_ALLOW` |
| B — high risk | `LOCAL-TEST-ONLY-HIGH` | HOLD | 0.698450 | `HOLD`, `ANOMALY_THRESHOLD_EXCEEDED` |
| C — review | `LOCAL-TEST-ONLY-HIGH` | remains HOLD | 0.698450 | `REVIEW_RELEASED`, `RELEASE_RESERVATION`; reservation abandoned, not payment-approved |
| D — durability | both records | unchanged | unchanged | restart persistence; identical screen request is idempotent; released transaction cannot be re-reserved |
| E — provider safety | none | no payment authorization | n/a | provider invocations 0; external network attempts 0; `DISABLED_NOT_CALLED` |
| F — token authorization only | no transaction | valid synthetic token | n/a | `NOT_STARTED`; PayPal payment authorization is false |
| G — invalid authentication | synthetic invalid token | DENY / HTTP 401 | n/a | No ledger record or risk inference |
| H — identical screen request replay | `LOCAL-TEST-ONLY-LOW` | same prior ALLOW result | unchanged | Idempotent response; no second inference or ledger transaction. Skyfire screening does not reject repeats solely by token `jti`. |
| I — DPoP proof replay | synthetic proof | DENY | n/a | Durable DPoP replay-ID guard rejects a reused proof ID in the separate legacy TrustGuard auth flow |
| J — amount above signed authorization | `LOCAL-TEST-ONLY-OVER-CAP` | DENY / HTTP 403 | n/a | Amount exceeds synthetic signed cap; no ledger record or risk inference |
| K — cumulative grant limit | `LOCAL-TEST-ONLY-CUMULATIVE-CAP` | DENY / HTTP 409 | n/a | Existing active reservation plus requested amount would exceed the same verified grant; no row or inference |

Both inferred results report model version `trustguard-isolation-forest-synthetic-v1`; inference count is exactly two (retries reuse persisted assessments). The low/high cases use separate clearly synthetic buyer identities so cumulative limits do not obscure the anomaly comparison. Review only abandons a reservation; it does not overturn the ML HOLD or approve a payment. Missing merchant mapping is truthfully reported as `NOT_CONFIGURED`.

The DPoP replay case in `scripts/run_local_demo.py` invokes the existing proof verifier and durable replay-ID ledger primitive directly; it is not part of the Skyfire Seller Service bearer-token endpoint. Separately, `tests/test_trustguard.py::test_authorize_and_dispatch_rejects_reused_dpop_jti_after_hold_and_restart` exercises the complete legacy `TrustGuard.authorize_and_dispatch()` path: a correctly bound synthetic proof is durably consumed before a forced HOLD, then a fresh access token and newly signed proof with the same DPoP `jti` and a correct new `ath` are rejected after reopening SQLite. Provider methods and network entry points are fail-closed in that test. An identical Skyfire screening request is deliberately idempotent and may return its prior result; it is not described as a rejected token replay. These locally signed tokens are **not genuine Skyfire-issued tokens**. The injected local JWKS trusts their key only inside this isolated test application; no production verifier configuration is changed. The model uses synthetic training data, not validated customer fraud data. No Skyfire or PayPal provider call occurs, no PayPal order IDs are fabricated, and this demonstration does **not** prove real Sandbox integration or payment success. Do not export demo tokens or keys into a production/Sandbox service.

Focused automated demo checks: `pytest -q tests/test_local_demo.py`. Existing route tests remain available with `pytest -q tests/test_skyfire_api.py -k 'local_test_only'`.

For an actual configured service, the request contract is:

```http
POST /v1/agent/screen-transaction
skyfire-pay-id: <valid, issuer-signed PAY or KYA-PAY token>
Content-Type: application/json

{"transaction_id":"<unique-local-id>","idempotency_key":"<unique-idempotency-key>","amount":"<positive USD amount not above signed amt>","currency":"USD"}
```

The response reports authenticated `skyfire_service_id` separately from trusted `paypal_merchant_id` (or null if `NOT_CONFIGURED`). Do not include a merchant ID in the request; extra fields are rejected. An allowed screening is not PayPal authorization or an order; the response states that PayPal dispatch was not called. No HTTP route creates or captures orders.

For hold review, inject both reviewer variables from secure environment configuration, then send `POST /v1/admin/transactions/{transaction_id}/review` with `x-trustguard-reviewer-credential` and JSON such as `{"decision":"RELEASE_RESERVATION","reason":"reviewed under approved operational procedure"}`. The server uses the configured reviewer identity. This only releases a still-undispatched HOLD reservation; it never approves or dispatches payment. If reviewer configuration is missing, the endpoint returns service unavailable without reviewing anything.

The GitHub Actions workflow runs on pushes to the remediation branch, pull requests targeting `main`, and manual `workflow_dispatch`. It has `contents: read` permissions, uses Python 3.12 to match the Docker base image, runs syntax validation and all tests, and builds/runs a local container smoke test without publishing an image. Its smoke test uses synthetic non-secret seller identifiers and never requests provider credentials.

To run the API locally, provide the required variables from the authorized Sandbox onboarding/configuration, explicitly keep dispatch disabled, then use:

```bash
export TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false
export TRUSTGUARD_OPENAPI_ENABLED=true
export TRUSTGUARD_ALLOWED_HOSTS=127.0.0.1,localhost
uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

The OpenAPI environment switch above is for local inspection only. Open `http://127.0.0.1:8000/healthz` and `http://127.0.0.1:8000/openapi.json` only after the schema is deliberately enabled. Otherwise `/openapi.json`, `/docs`, and `/redoc` are disabled/not exposed. The service fetches the configured JWKS only when a token request requires a key-cache refresh; offline tests replace this fetcher and prohibit real network connections. Do not use real settlement tokens in an untrusted local environment. The Skyfire profile is still unresolved for this account.

## Container preparation

The non-root `Dockerfile` sets `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false`, defaults `PORT` to 8000 and the database to `/data/trustguard.sqlite3`, and disables OpenAPI publication by default. Build locally with `docker build -t trustguard-local .`. A Docker `VOLUME` declaration alone does not guarantee durable storage; the host must provide a persistent mount. To bind only to localhost, set actual authorized non-secret Sandbox values only when available, then run:

```bash
docker run --rm --name trustguard-local \
  -p 127.0.0.1:8000:8000 \
  --mount source=trustguard-data,target=/data \
  -e TRUSTGUARD_OPENAPI_ENABLED=true \
  -e TRUSTGUARD_ALLOWED_HOSTS=127.0.0.1,localhost \
  -e SKYFIRE_ISSUER="${SKYFIRE_ISSUER:?set the confirmed Sandbox issuer}" \
  -e SKYFIRE_JWKS_URL="${SKYFIRE_JWKS_URL:?set the documented Sandbox JWKS URL}" \
  -e SKYFIRE_EXPECTED_ENVIRONMENT="${SKYFIRE_EXPECTED_ENVIRONMENT:?set sandbox}" \
  -e SKYFIRE_SELLER_AGENT_ACCOUNT_ID="${SKYFIRE_SELLER_AGENT_ACCOUNT_ID:?set the authorized Seller Agent Account ID}" \
  -e SKYFIRE_SELLER_SERVICE_ID="${SKYFIRE_SELLER_SERVICE_ID:?set the authorized Seller Service ID}" \
  trustguard-local
```

The image provides `TRUSTGUARD_DATABASE_PATH=/data/trustguard.sqlite3` and disables PayPal Sandbox dispatch. The OpenAPI and host settings above are local-only examples, not deployment settings. Verify the local smoke endpoints with:

```bash
curl --fail http://127.0.0.1:8000/healthz
curl --fail http://127.0.0.1:8000/openapi.json | python -c 'import json,sys; assert "/v1/agent/authorize" in json.load(sys.stdin)["paths"]'
```

No image is published and no public endpoint or deployment is configured. Use HTTPS termination before accepting tokens over a network and do not register a Seller Service until an actual HTTPS URL and onboarding values have been confirmed. **PayPal Sandbox dispatch remains disabled by default; do not set the opt-in flag for this API.**

## Files

- `app.py`: FastAPI token-validation and provider-free ML screening routes; no PayPal calls.
- `skyfire_auth.py`: explicit Sandbox ES256/JWKS configuration and draft-03 claim validation.
- `trustguard.py`: SQLite ledger, transaction idempotency, shared risk-screening pipeline, and separate legacy dispatch primitives.
- `risk_scoring.py`: deterministic synthetic-data IsolationForest scorer; not production validated.
- `paypal_rest.py`: separate Sandbox-only Orders adapter, not called by the HTTP API.
- `Dockerfile`, `.dockerignore`: non-root container setup and build-context exclusions.
- `tests/test_skyfire_api.py`: generated tokens, fake JWKS, claim/config/repeated-token tests, and direct ASGI calls.
- `tests/test_trustguard.py`: auth/ledger/provider tests and ML allow/HOLD/failure/durability/reproducibility regression tests.
