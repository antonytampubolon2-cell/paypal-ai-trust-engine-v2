# TrustGuard Skyfire Seller Service backend

This repository includes a FastAPI service for validating Skyfire KYAPay tokens. Token validation is not PayPal authorization: the API does not initialize the PayPal adapter, create an order, capture funds, or report PayPal payment success. Keep `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX` unset or `false`; the HTTP API never invokes the adapter.

The API accepts `skyfire-pay-id` as requested. Skyfire currently documents `kyapay-token` as preferred and `skyfire-pay-id` as deprecated; this service retains the latter for compatibility. [Skyfire Seller Services](https://docs.skyfire.xyz/docs/seller-services)

## HTTP endpoints

- `GET /healthz`: `200` when the required configuration and durable SQLite ledger are ready; otherwise `503`.
- `GET /openapi.json`: generated OpenAPI document. It marks `skyfire-pay-id` as a required request header.
- `POST /v1/agent/authorize`: validates the signed token and returns a minimized claim projection. The response explicitly says `paypal_payment_status: NOT_STARTED` and `paypal_payment_authorized: false`.

The API does not use `jti` as a request id or one-use replay key. The verifier requires a UUID-format `jti` as the token identifier, but repeated presentation of the same valid token is permitted until its expiration. The API does not persist `jti`, the raw token, or `sti`. A repeated token is not itself a second PayPal operation: actual dispatch de-duplication remains tied to TrustGuard's separate canonical application `transaction_id` and `idempotency_key`, recorded atomically by its SQLite ledger. The `/v1/agent/authorize` endpoint itself initiates no payment operation. The separate legacy TrustGuard DPoP/access-token path retains its own replay checks; it is not used by this Skyfire endpoint.

The response may include `sub`, `aud`, `tsi`, `tdm` (only when configured), `amt`, and `cur`. It never returns the token, `sti`, or `val`; it does not log or persist token contents or settlement information. A Skyfire PAY or KYA-PAY token is only a signed Skyfire token signal and does not authorize a PayPal debit.

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

To run the API, provide the required variables from the authorized Sandbox onboarding/configuration, then use:

```bash
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

The image provides `TRUSTGUARD_DATABASE_PATH=/data/trustguard.sqlite3` and disables PayPal Sandbox dispatch. No public endpoint or deployment is configured. Use HTTPS termination before accepting tokens over a network and do not register a Seller Service until an actual HTTPS URL and onboarding values have been confirmed.

## Files

- `app.py`: FastAPI routes and sanitized response model; no PayPal calls.
- `skyfire_auth.py`: explicit Sandbox ES256/JWKS configuration and draft-03 claim validation.
- `trustguard.py`: existing SQLite ledger, transaction idempotency, and separate dispatch primitives.
- `paypal_rest.py`: separate Sandbox-only Orders adapter, not called by the HTTP API.
- `Dockerfile`, `.dockerignore`: non-root container setup and build-context exclusions.
- `tests/test_skyfire_api.py`: generated tokens, fake JWKS, claim/config/repeated-token tests, and direct ASGI calls.
