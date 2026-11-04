# TrustGuard Skyfire Seller Service backend

This repository includes a FastAPI service for validating Skyfire KYAPay tokens. Token validation is not PayPal authorization: the API does not initialize the PayPal adapter, create an order, capture funds, or report PayPal payment success. Keep `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX` unset or `false`; the HTTP API never invokes the adapter.

**Demo limitation:** no actual Skyfire-issued Sandbox token has been verified by this project, and no PayPal Sandbox order/capture success is claimed or shown. Tests use generated tokens and mock provider responses only. Confirm Skyfire onboarding metadata before accepting real tokens.

The API accepts `skyfire-pay-id` as requested. Skyfire currently documents `kyapay-token` as preferred and `skyfire-pay-id` as deprecated; this service retains the latter for compatibility. [Skyfire Seller Services](https://docs.skyfire.xyz/docs/seller-services)

## HTTP endpoints

- `GET /healthz`: `200` when the required configuration and durable SQLite ledger are ready; otherwise `503`.
- `GET /openapi.json`: generated OpenAPI document. It marks `skyfire-pay-id` as a required request header.
- `POST /v1/agent/authorize`: validates the signed token and returns a minimized claim projection. The response explicitly says `paypal_payment_status: NOT_STARTED` and `paypal_payment_authorized: false`.
- `POST /v1/agent/screen-transaction`: requires a valid Skyfire PAY/KYA-PAY token, validates a canonical request, durably reserves it against an identity derived from verified token claims, and invokes the existing local IsolationForest scorer. It returns `ALLOW` or `HOLD`, a reason code, and persisted model metadata. This route has no provider dependency and never creates or captures a PayPal order.
- `POST /v1/admin/transactions/{transaction_id}/review`: when separately configured, records `KEEP_HOLD` or `RELEASE_RESERVATION` with a review reason. Release marks only a still-undispatched HOLD as `REVIEW_RELEASED`; it does not authorize payment.

The API does not use `jti` as a request id or one-use replay key. The verifier requires a UUID-format `jti` as the token identifier, but repeated presentation of the same valid token is permitted until its expiration. The API does not persist `jti`, the raw token, or `sti`. A repeated token is not itself a second PayPal operation: actual dispatch de-duplication remains tied to TrustGuard's separate canonical application `transaction_id` and `idempotency_key`, recorded atomically by its SQLite ledger. The `/v1/agent/authorize` endpoint itself initiates no payment operation. The separate legacy TrustGuard DPoP/access-token path retains its own replay checks; it is not used by this Skyfire endpoint.

The response may include `sub`, `aud`, `tsi`, `tdm` (only when configured), `amt`, and `cur`. It never returns the token, `sti`, or `val`; it does not log or persist token contents or settlement information. A Skyfire PAY or KYA-PAY token is only a signed Skyfire token signal and does not authorize a PayPal debit.

## Local ML anomaly screening (not a production fraud detector)

The repository now contains real local scikit-learn inference in the `RiskScreeningPipeline` shared with `TrustGuard.authorize_and_dispatch` (`trustguard.py`), using `SyntheticIsolationForestScorer` in `risk_scoring.py`. `POST /v1/agent/screen-transaction` verifies the Skyfire token first and then invokes that provider-free pipeline. `POST /v1/agent/authorize` only validates Skyfire claims; it does **not** call transaction scoring. The static dashboards do not run inference either.

The estimator is `sklearn.ensemble.IsolationForest`, versioned as `trustguard-isolation-forest-synthetic-v1`. Its deterministic configuration is 128 trees, `max_samples=256`, `contamination=0.04`, `random_state=20261104`, and `n_jobs=1`. It is lazily fitted from 768 synthetic routine-like feature rows generated with NumPy seed `20261104`; the documented feature distributions are amount/grant ratio `Beta(2,4) × 0.70`, cumulative utilization `Beta(1.5,3) × 0.82`, recent velocity `Beta(1.2,8)`, and new-payee indicator `Binomial(1,0.25)`. No real customer, merchant, or payment data is used. The declared dependency is pinned to `scikit-learn==1.6.1`.

Immediately after signed access-token and DPoP verification, authenticated grant currency/payee/limit checks, and the durable spending reservation—and before persisting `DISPATCH_STARTED` or calling any provider—the guard derives four features from the canonical transaction and existing ledger: `amount_to_grant_ratio`, `cumulative_spending_ratio`, `recent_velocity_ratio` (prior active transactions in the preceding ten minutes, normalized/capped at five), and `new_payee`. No caller-supplied risk feature is accepted. The model's IsolationForest margin is sigmoid-mapped to a 0–1 **anomaly ranking score**, with `HOLD` at score ≥0.65. This is not a calibrated probability of fraud, and this synthetic model is not validated for production or payment authorization.

The screening route binds currency to the signed token and obtains Skyfire `tsi` only from verified claims. The request body has no payee or merchant-ID field. Signed `amt` is treated as the maximum authorized amount. Requests above that cap are rejected; lower amounts remain within the signed ceiling. A deterministic grant-ledger identity is derived from verified issuer, subject, audience, and service ID. The screen-only state `SCREENED_ALLOW` is distinct from provider dispatch. HOLD and ALLOW reservations remain counted against cumulative ledger limits unless an authenticated reviewer releases a still-undispatched HOLD as `REVIEW_RELEASED`. Release only abandons the reservation; it never changes the ML HOLD decision into ALLOW, authorizes payment, or starts dispatch. Risk evidence is persisted in SQLite. The screening route never constructs a provider and reports `paypal_dispatch: DISABLED_NOT_CALLED`. PayPal Sandbox dispatch remains opt-in and disabled by default elsewhere.

Skyfire `tsi` and PayPal merchant ID are separate identifier namespaces and are persisted separately as `skyfire_service_id` and `paypal_merchant_id`. The trusted server-side mapping requires `TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID` (must exactly equal `SKYFIRE_SELLER_SERVICE_ID`) and `TRUSTGUARD_PAYPAL_MERCHANT_ID`. Neither value is accepted from the screening request. If mapping values are missing or inconsistent, the response says `paypal_integration_status: NOT_CONFIGURED` and the ledger stores no PayPal merchant ID. A configured mapping says only `CONFIGURED`; it does not enable or invoke PayPal.

Administrative review is disabled unless both `TRUSTGUARD_REVIEWER_ID` and `TRUSTGUARD_REVIEWER_CREDENTIAL` are present. Reviewer identity is server-configured; the credential is compared in constant time and never returned or logged. The durable audit records reviewer ID, decision, reason, and timestamp. Only an exact repeat of the same authenticated decision/reason is idempotent; conflicting later reviews are rejected. `UNKNOWN`, `DISPATCH_STARTED`, any non-HOLD state, and any row with a provider order ID cannot be released. Keep the reviewer credential in a secret manager/environment injection, never in source, README examples, or shell history.

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

## Safe local testing and run

Tests need no Skyfire or PayPal credentials. They generate ES256 keys and tokens, fake JWKS responses, and use temporary SQLite databases; they do not perform external HTTP requests.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false
pytest -q
```

### LOCAL TEST ONLY screening demonstration

After installing `requirements.txt`, run the full offline A–E demonstration from the repository root with one command:

```bash
python scripts/run_local_demo.py
```

Dependencies are the project's existing PyJWT/cryptography, FastAPI, requests, and scikit-learn (pinned to 1.6.1); the in-process ASGI HTTP test client uses only the Python standard library and requires no httpx or running server. Python 3.12 matches CI and Docker. No provider credentials or environment configuration are required for this runner.

The runner generates an ephemeral ES256 key and clearly synthetic Skyfire-like claims, injects a local public-only mock JWKS into the **unchanged** `SkyfireTokenVerifier`, and uses the actual FastAPI screening/review routes. It creates an isolated application with a temporary SQLite ledger and an ephemeral reviewer credential held only in memory. It clears ambient configuration for the duration of the run, explicitly disables PayPal dispatch, and restores the caller's environment afterwards. Provider spies and outbound-network guards are active throughout. No token, private key, settlement claim, or reviewer credential is printed or saved. The temporary database is removed after reopening it and verifying restart evidence.

Output is JSON with a prominent `LOCAL TEST ONLY` disclaimer, scenario records, HTTP route names, an actual model-inference count, and provider/network counters. Expected scenario results with the current pinned model are:

| Scenario | Transaction | Risk decision | Anomaly score (approximately) | Durable state / evidence |
| --- | --- | --- | --- | --- |
| A — low risk | `LOCAL-TEST-ONLY-LOW` | ALLOW | 0.415589 | `SCREENED_ALLOW` |
| B — high risk | `LOCAL-TEST-ONLY-HIGH` | HOLD | 0.698450 | `HOLD`, `ANOMALY_THRESHOLD_EXCEEDED` |
| C — review | `LOCAL-TEST-ONLY-HIGH` | remains HOLD | 0.698450 | `REVIEW_RELEASED`, `RELEASE_RESERVATION`; reserved minor units 5000 → 0 |
| D — durability | both records | unchanged | unchanged | low-screen retry and review retry are idempotent; released-screen retry rejected; two transactions and one audit |
| E — provider safety | none | no payment authorization | n/a | provider invocations 0; external network attempts 0; `DISABLED_NOT_CALLED` |

Both inferred results report model version `trustguard-isolation-forest-synthetic-v1`; inference count is exactly two (retries reuse persisted assessments). The low/high cases use separate clearly synthetic buyer identities so cumulative limits do not obscure the anomaly comparison. Review only abandons a reservation; it does not overturn the ML HOLD or approve a payment. Missing merchant mapping is truthfully reported as `NOT_CONFIGURED`.

These locally signed tokens are **not genuine Skyfire-issued tokens**. The injected local JWKS trusts their key only inside this isolated test application; no production verifier configuration is changed. The model uses synthetic training data, not validated customer fraud data. No Skyfire or PayPal provider call occurs, no PayPal order IDs are fabricated, and this demonstration does **not** prove real Sandbox integration or payment success. Do not export demo tokens or keys into a production/Sandbox service.

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
uvicorn app:app --host 127.0.0.1 --port 8000 --no-access-log
```

Open `http://127.0.0.1:8000/healthz` and `http://127.0.0.1:8000/openapi.json`. The service fetches the configured JWKS only when a request requires a key cache refresh. Do not use real settlement tokens in an untrusted local environment.

## Container preparation

The non-root `Dockerfile` sets `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false`, defaults the database to `/data/trustguard.sqlite3`, and expects persistent storage. Build locally with `docker build -t trustguard-local .`. To bind only to localhost, set the actual authorized values in the shell, then run:

```bash
docker run --rm --name trustguard-local \
  -p 127.0.0.1:8000:8000 \
  --mount source=trustguard-data,target=/data \
  -e SKYFIRE_ISSUER="${SKYFIRE_ISSUER:?set the confirmed Sandbox issuer}" \
  -e SKYFIRE_JWKS_URL="${SKYFIRE_JWKS_URL:?set the documented Sandbox JWKS URL}" \
  -e SKYFIRE_EXPECTED_ENVIRONMENT="${SKYFIRE_EXPECTED_ENVIRONMENT:?set sandbox}" \
  -e SKYFIRE_SELLER_AGENT_ACCOUNT_ID="${SKYFIRE_SELLER_AGENT_ACCOUNT_ID:?set the authorized Seller Agent Account ID}" \
  -e SKYFIRE_SELLER_SERVICE_ID="${SKYFIRE_SELLER_SERVICE_ID:?set the authorized Seller Service ID}" \
  trustguard-local
```

The image provides `TRUSTGUARD_DATABASE_PATH=/data/trustguard.sqlite3` and disables PayPal Sandbox dispatch. Verify the local smoke endpoints with:

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
