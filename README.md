# TrustGuard Skyfire Seller Service backend

This repository now includes a minimal FastAPI backend that validates Skyfire KYAPay JWTs. Token validation is not PayPal authorization: the API does not initialize the PayPal adapter, create a PayPal order, capture funds, or report PayPal payment success. Keep `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX` unset or `false` for local work. No production PayPal endpoint is implemented.

The API accepts the requested `skyfire-pay-id` header. Skyfire currently documents `kyapay-token` as the preferred header and `skyfire-pay-id` as deprecated; this implementation accepts `skyfire-pay-id` for compatibility with the integration requirement. [Skyfire Seller Services](https://docs.skyfire.xyz/docs/seller-services)

## HTTP endpoints

- `GET /healthz` returns `200` when required environment configuration and the replay database are ready; otherwise it returns `503`.
- `GET /openapi.json` serves the FastAPI-generated OpenAPI document, including the `skyfire-pay-id` request header.
- `POST /v1/agent/authorize` validates the token, atomically records its `jti` for replay prevention, and returns a minimal claim projection. Invalid, missing, or previously used tokens receive a generic `401`; replay-store failures receive `503`.

The authorization response may include `sub`, `aud`, `ssi`, `amt`, and `cur`. It never returns the raw token, `sti`, or `val`. It explicitly says `paypal_payment_status: NOT_STARTED` and `paypal_payment_authorized: false`. No token text or settlement information is logged or stored. The replay database stores the normalized UUID `jti` and expiration, not the JWT.

`jti` is enforced as single-use by this API. Skyfire documentation notes that some valid tokens may be presented more than once; this service deliberately chooses the stricter replay policy required for this implementation. [Skyfire Common Token Claims](https://docs.skyfire.xyz/docs/common-token-claims)

## Environment variables

The API fails closed unless all three required variables are configured:

- `SKYFIRE_SELLER_AGENT_ACCOUNT_ID`: expected Seller Agent Account ID; must exactly match the token's `aud`.
- `SKYFIRE_SELLER_SERVICE_ID`: expected Seller Service ID; must exactly match the token's `ssi` claim.
- `TRUSTGUARD_DATABASE_PATH`: durable file path for SQLite replay prevention. `:memory:` is rejected. In the container image this defaults to `/data/trustguard.sqlite3`; mount persistent storage at `/data`.

The Skyfire verifier pins these settings in code (they are not environment variables): issuer `https://app.skyfire.xyz`, JWKS URL `https://app.skyfire.xyz/.well-known/jwks.json`, algorithm `ES256`, expected `env` value `sandbox`, allowed JWT types `kya+jwt`, `pay+jwt`, and `kya-pay+jwt`, and a 300-second JWKS cache. JWKS requests use HTTPS, a bounded timeout, and redirects are disabled. The key cache is in memory and refreshes when expired or when a `kid` is not found.

For PAY and KYA-PAY tokens, the verifier checks positive `amt` and `val`, `cur=USD`, an allowed `stp` value (`coin`, `card`, or `bank`), and `sti.verified=true`. It only returns the amount and currency. KYA tokens do not require payment claims. `sub` is treated as the buyer-agent identifier, not as a grant identifier. `jti` is only used for UUID validation and replay prevention. No `grant_id` claim is assumed or created.

### Other environment variables in existing code

These are not consumed by the new FastAPI Skyfire API, but remain used by the separate legacy `TrustConfig.from_env()` helper in `trustguard.py`:

- `TRUSTGUARD_ISSUER`: issuer configured for that legacy TrustGuard helper.
- `TRUSTGUARD_AUDIENCE`: audience for that helper.
- `TRUSTGUARD_JWT_PUBLIC_KEYS_JSON`: JSON map of `kid` to trusted public PEM.
- `TRUSTGUARD_JWT_ALGORITHMS`: optional comma-separated JWT allowlist; defaults to `ES256`.
- `TRUSTGUARD_GRANT_ID_FIELD`: trusted authenticated-grant identity field name.
- `TRUSTGUARD_GRANT_LIMIT_FIELD`: trusted authenticated-grant spending-limit field name.
- `TRUSTGUARD_GRANT_CURRENCY_FIELD`: trusted authenticated-grant currency field name.
- `TRUSTGUARD_GRANT_PAYEES_FIELD`: trusted authenticated-grant payee-list field name.

Do not set guessed legacy issuer, audience, keys, or grant-field values. The Skyfire API does not consume or invent those KYAPay grant values.

These optional variables apply only to the separate PayPal Sandbox adapter, not to this API's token validation:

- `PAYPAL_CLIENT_ID`: Sandbox app client ID, needed only to construct the separate provider.
- `PAYPAL_CLIENT_SECRET`: Sandbox app secret, needed only to construct that provider; load from a secure secret store and never print or commit it.
- `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX`: must be exactly `true` for the separate adapter to issue Sandbox requests. It is unset/disabled by default and set to `false` in the Docker image. The FastAPI endpoints do not use the adapter even if credentials are configured.

## Safe local test setup

Use Python 3.10+ and a virtual environment. No Skyfire or PayPal credentials are needed for tests; the JWT signer, JWKS response, replay database, and HTTP requests in tests are local/fake.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false
pytest -q
```

Tests use generated local identities, fake JWKS, and temporary SQLite databases; they do not require or read real Skyfire configuration. The app will remain unready until the three required environment variables are supplied from an authorized Skyfire test configuration.

To run the API locally after configuring real authorized IDs:

```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --no-access-log
```

Then inspect `http://127.0.0.1:8000/healthz` and `http://127.0.0.1:8000/openapi.json`. The API performs a remote JWKS fetch only when a token is verified and the in-memory key cache needs refresh. Do not send real settlement tokens to an untrusted local environment.

## Container preparation

The repository includes a non-root `Dockerfile`. It sets `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false`, defaults the database file to `/data/trustguard.sqlite3`, and expects persistent storage to be mounted there. Build locally with `docker build -t trustguard-local .`. To run only on the local machine, supply actual authorized Skyfire IDs through the environment and mount a persistent volume:

```bash
docker run --rm --name trustguard-local \
  -p 127.0.0.1:8000:8000 \
  --mount source=trustguard-data,target=/data \
  -e SKYFIRE_SELLER_AGENT_ACCOUNT_ID="${SKYFIRE_SELLER_AGENT_ACCOUNT_ID:?set actual authorized Seller Agent Account ID}" \
  -e SKYFIRE_SELLER_SERVICE_ID="${SKYFIRE_SELLER_SERVICE_ID:?set actual authorized Seller Service ID}" \
  trustguard-local
```

The image supplies `TRUSTGUARD_DATABASE_PATH=/data/trustguard.sqlite3` and `TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false`. No public endpoint is defined here. Put the service behind an HTTPS termination layer before accepting Skyfire tokens. Do not deploy or register a Seller Service until an actual HTTPS URL and actual Seller Agent Account ID/Seller Service ID are provisioned and verified.

## Important configuration blockers

The implementation follows the requested production-host issuer and JWKS constants while requiring `env=sandbox`. Skyfire's current verification guide documents separate production and Sandbox JWKS hosts. Its current common-claims page calls `ssi` optional, while the current Skyfire-authored IETF draft uses the claim name `tsi` for Target Service ID. This API intentionally requires the user-specified `ssi` claim. Confirm the actual Sandbox issuer/JWKS pairing and exact service-ID claim key with Skyfire before accepting Sandbox tokens; do not silently substitute values. [Skyfire Verify and Extract Data](https://docs.skyfire.xyz/docs/verify-and-extract-data-from-tokens) [Skyfire Common Token Claims](https://docs.skyfire.xyz/docs/common-token-claims) [KYAPay Token Draft](https://datatracker.ietf.org/doc/draft-skyfire-oauth-kyapay-token/)

The service has not been deployed. No public URL, Seller Service registration, or production PayPal integration is configured. `kya-pay` payment claims are only a signed Skyfire authorization signal; a separate PayPal checkout approval process would still be required, and this API does not start one.

## Files

- `app.py`: FastAPI routes and sanitized response model.
- `skyfire_auth.py`: Skyfire ES256/JWKS verification, claim checks, and minimized validated claim projection.
- `trustguard.py`: existing SQLite ledger, replay prevention, and separate TrustGuard dispatch primitives.
- `paypal_rest.py`: preserved Sandbox-only PayPal Orders adapter, not called by the HTTP API.
- `Dockerfile`: non-root, container-ready local deployment configuration.
- `tests/test_skyfire_api.py`: generated ES256 tokens, fake JWKS, direct ASGI calls, and local SQLite tests.
