import asyncio
import concurrent.futures
import json
import os
import time
import uuid
from decimal import Decimal

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app import create_app
from skyfire_auth import (
    DOCUMENTED_SANDBOX_ISSUER,
    DOCUMENTED_SANDBOX_JWKS_URL,
    EXPECTED_SANDBOX_ENVIRONMENT,
    PROFILE_DRAFT,
    PROFILE_LEGACY,
    SkyfireSettings,
    SkyfireTokenError,
    SkyfireTokenVerifier,
)
from trustguard import Ledger
from risk_scoring import ANOMALY_THRESHOLD, MODEL_VERSION, TRAINING_DATASET_ID


SELLER_ID = "seller-agent-test"
SERVICE_ID = "seller-service-test"


class FakeVerifier:
    def __init__(self, result):
        self.result = result
        self.values = []

    def verify(self, token):
        self.values.append(token)
        result = dict(self.result)
        result.setdefault("service_id", result.get("tsi"))
        result.setdefault("sub_semantics", "LOCAL TEST ONLY synthetic subject")
        return result


def settings(tmp_path, *, target_domain=None, issuer=DOCUMENTED_SANDBOX_ISSUER,
             jwks_url=DOCUMENTED_SANDBOX_JWKS_URL, expected_environment=EXPECTED_SANDBOX_ENVIRONMENT):
    return SkyfireSettings(
        issuer, jwks_url, expected_environment, SELLER_ID, SERVICE_ID,
        str(tmp_path / "skyfire.sqlite3"), target_domain,
        protocol_profile=PROFILE_DRAFT, expected_audience=SELLER_ID,
        account_configuration_confirmed=True,
    )


def signing_material():
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "skyfire-test-key", "alg": "ES256", "use": "sig"})
    return private, jwk


def make_token(private, *, typ="kya-pay+jwt", overrides=None, jti=None):
    now = int(time.time())
    claims = {
        "iss": DOCUMENTED_SANDBOX_ISSUER,
        "sub": "buyer-agent-account",
        "aud": SELLER_ID,
        "iat": now - 5,
        "exp": now + 600,
        "jti": jti or str(uuid.uuid4()),
        "env": EXPECTED_SANDBOX_ENVIRONMENT,
        "tsi": SERVICE_ID,
        "amt": "1.25",
        "cur": "USD",
        "val": "1250000",
        "stp": "card",
        "sti": {
            "type": "visa_vic",
            "payment_token": "0000000000000000",
            "token_expiration_month": "12",
            "token_expiration_year": "2030",
            "token_security_code": "000",
            "verified": True,
            "verification_id": "LOCAL-TEST-ONLY-SENSITIVE-MARKER",
        },
    }
    claims.update(overrides or {})
    return jwt.encode(claims, private, algorithm="ES256", headers={"kid": "skyfire-test-key", "typ": typ})


def verifier(settings_, jwk, *, ttl=300, fetcher=None):
    return SkyfireTokenVerifier(
        settings_,
        jwks_fetcher=fetcher or (lambda: {"keys": [jwk]}),
        cache_ttl_seconds=ttl,
    )


def asgi_request(app, method, path, *, headers=None, body=b"", body_chunks=None, host="testserver", client_ip="127.0.0.1"):
    """Invoke the ASGI app directly; this harness performs no network I/O."""
    messages = []
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
        "headers": [(b"host", host.encode()), *[(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]],
        "server": (host.split(":", 1)[0], 80), "client": (client_ip, 12345),
    }
    chunks = list(body_chunks) if body_chunks is not None else [body]
    sent_chunks = 0

    async def receive():
        nonlocal sent_chunks
        if sent_chunks < len(chunks):
            index = sent_chunks
            sent_chunks += 1
            return {"type": "http.request", "body": chunks[index], "more_body": sent_chunks < len(chunks)}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), body


def local_screening_app(tmp_path, *, amount="50.00", risk_scorer_marker="real"):
    """LOCAL TEST ONLY: generated signing key/token and fake JWKS, never production credentials."""
    private, jwk = signing_material()
    test_settings = settings(tmp_path)
    signed_verifier = verifier(test_settings, jwk)
    db_path = tmp_path / "screening.sqlite3"
    kwargs = {"settings": test_settings, "ledger": Ledger(db_path), "verifier": signed_verifier}
    if risk_scorer_marker != "real":
        kwargs["risk_scorer"] = risk_scorer_marker
    token = make_token(private, overrides={"amt": amount, "val": str(int(Decimal(amount) * 1_000_000))})
    return create_app(**kwargs), token, db_path


def submit_local_screening(app, token, *, transaction_id="screen-tx-1", idempotency_key="screen-idem-1", amount="5.00", currency="USD", paypal_merchant_override=None):
    payload = {
        "transaction_id": transaction_id,
        "idempotency_key": idempotency_key,
        "amount": amount,
        "currency": currency,
    }
    if paypal_merchant_override is not None:
        payload["paypal_merchant_id"] = paypal_merchant_override
    body = json.dumps(payload).encode()
    return asgi_request(
        app, "POST", "/v1/agent/screen-transaction",
        headers={"KYAPay-Token": token, "content-type": "application/json"},
        body=body,
    )


def test_explicit_documented_sandbox_pair_loads_from_environment(monkeypatch, tmp_path):
    env = {
        "SKYFIRE_ISSUER": DOCUMENTED_SANDBOX_ISSUER,
        "SKYFIRE_JWKS_URL": DOCUMENTED_SANDBOX_JWKS_URL,
        "SKYFIRE_EXPECTED_ENVIRONMENT": "sandbox",
        "SKYFIRE_PROTOCOL_PROFILE": PROFILE_DRAFT,
        "SKYFIRE_EXPECTED_AUDIENCE": SELLER_ID,
        "SKYFIRE_ACCOUNT_CONFIGURATION_CONFIRMED": "true",
        "SKYFIRE_SELLER_AGENT_ACCOUNT_ID": SELLER_ID,
        "SKYFIRE_SELLER_SERVICE_ID": SERVICE_ID,
        "TRUSTGUARD_DATABASE_PATH": str(tmp_path / "configured.sqlite3"),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    loaded = SkyfireSettings.from_env()
    assert loaded.issuer == DOCUMENTED_SANDBOX_ISSUER
    assert loaded.jwks_url == DOCUMENTED_SANDBOX_JWKS_URL
    assert loaded.expected_environment == "sandbox"
    assert loaded.database_path == env["TRUSTGUARD_DATABASE_PATH"]


def test_mismatched_sandbox_pairs_and_unconfirmed_account_fail_closed(tmp_path):
    with pytest.raises(SkyfireTokenError):
        settings(tmp_path, issuer="https://app.skyfire.xyz", jwks_url=DOCUMENTED_SANDBOX_JWKS_URL)
    with pytest.raises(SkyfireTokenError):
        settings(tmp_path, jwks_url="https://api-qa.skyfire.xyz/api/v1/tokens")
    with pytest.raises(SkyfireTokenError):
        settings(tmp_path, expected_environment="production")
    unconfirmed = SkyfireSettings(
        DOCUMENTED_SANDBOX_ISSUER, DOCUMENTED_SANDBOX_JWKS_URL, "sandbox", SELLER_ID,
        SERVICE_ID, str(tmp_path / "unconfirmed.sqlite3"), protocol_profile=PROFILE_DRAFT,
        expected_audience=SELLER_ID, account_configuration_confirmed=False,
    )
    app = create_app(settings=unconfirmed, ledger=Ledger(tmp_path / "unconfirmed.sqlite3"),
                     verifier=FakeVerifier({}))
    assert asgi_request(app, "GET", "/healthz")[0] == 503


def test_valid_es256_tokens_and_all_supported_types(tmp_path):
    private, jwk = signing_material()
    check = verifier(settings(tmp_path), jwk)
    for typ in ("kya+jwt", "pay+jwt", "kya-pay+jwt", "application/kya-pay+jwt"):
        claims = check.verify(make_token(private, typ=typ))
        assert claims["token_type"] == typ.removeprefix("application/")
        assert claims["aud"] == SELLER_ID
        assert claims["service_id"] == SERVICE_ID
    kya = check.verify(make_token(private, typ="kya+jwt", overrides={"amt": None, "cur": None, "val": None, "stp": None, "sti": None}))
    assert kya["amount"] is None and kya["currency"] is None


@pytest.mark.parametrize("overrides,typ", [
    ({"iss": "https://attacker.example"}, "kya-pay+jwt"),
    ({"aud": "another-seller"}, "kya-pay+jwt"),
    ({"env": "production"}, "kya-pay+jwt"),
    ({"tsi": "another-service"}, "kya-pay+jwt"),
    ({"exp": int(time.time()) - 10}, "kya-pay+jwt"),
    ({"iat": "__FUTURE_IAT__"}, "kya-pay+jwt"),
    ({"jti": ""}, "kya-pay+jwt"),
    ({"amt": "not-money"}, "pay+jwt"),
    ({"amt": "0"}, "pay+jwt"),
    ({"cur": "usd"}, "pay+jwt"),
    ({"cur": "USDD"}, "pay+jwt"),
    ({"val": "0"}, "pay+jwt"),
    ({"stp": "other"}, "pay+jwt"),
])
def test_invalid_claims_rejected(tmp_path, overrides, typ):
    # Calculate future timestamps at test execution time.
    if overrides.get("iat") == "__FUTURE_IAT__":
        overrides = {**overrides, "iat": int(time.time()) + 360}
    private, jwk = signing_material()
    with pytest.raises(SkyfireTokenError):
        verifier(settings(tmp_path), jwk).verify(make_token(private, typ=typ, overrides=overrides))


def test_legacy_ssi_does_not_substitute_for_required_tsi(tmp_path):
    private, jwk = signing_material()
    token = make_token(private, overrides={"tsi": None, "ssi": SERVICE_ID})
    with pytest.raises(SkyfireTokenError):
        verifier(settings(tmp_path), jwk).verify(token)


def test_tdm_is_checked_when_target_domain_is_configured(tmp_path):
    private, jwk = signing_material()
    check = verifier(settings(tmp_path, target_domain="merchant.example"), jwk)
    token = make_token(private, overrides={"tdm": "merchant.example"})
    assert check.verify(token)["tdm"] == "merchant.example"
    wrong = make_token(private, overrides={"tdm": "attacker.example"})
    with pytest.raises(SkyfireTokenError):
        check.verify(wrong)


def test_invalid_signature_and_unknown_kid_rejected(tmp_path):
    private, jwk = signing_material()
    other = ec.generate_private_key(ec.SECP256R1())
    fetches = []
    check = verifier(settings(tmp_path), jwk, fetcher=lambda: (fetches.append(1) or {"keys": [jwk]}))
    with pytest.raises(SkyfireTokenError):
        check.verify(make_token(other))
    wrong_kid_token = jwt.encode(
        {"iss": DOCUMENTED_SANDBOX_ISSUER, "sub": "buyer", "aud": SELLER_ID, "iat": int(time.time()) - 1,
         "exp": int(time.time()) + 100, "jti": str(uuid.uuid4()), "env": "sandbox", "tsi": SERVICE_ID},
        private, algorithm="ES256", headers={"kid": "untrusted-key", "typ": "kya+jwt"},
    )
    with pytest.raises(SkyfireTokenError):
        check.verify(wrong_kid_token)
    assert len(fetches) == 1


def test_jwks_private_key_material_is_rejected(tmp_path):
    private, jwk = signing_material()
    compromised_jwk = {**jwk, "d": "not-logged-private-value"}
    token = make_token(private)
    with pytest.raises(SkyfireTokenError):
        verifier(settings(tmp_path), compromised_jwk).verify(token)


def test_wrong_token_type_and_algorithm_rejected(tmp_path):
    private, jwk = signing_material()
    check = verifier(settings(tmp_path), jwk)
    with pytest.raises(SkyfireTokenError):
        check.verify(make_token(private, typ="JWT"))
    hs_token = jwt.encode(
        {"iss": DOCUMENTED_SANDBOX_ISSUER}, "x" * 32, algorithm="HS256",
        headers={"kid": "skyfire-test-key", "typ": "kya+jwt"},
    )
    with pytest.raises(SkyfireTokenError):
        check.verify(hs_token)


def test_jwks_cache_is_bounded_and_reused(tmp_path):
    private, jwk = signing_material()
    fetches = []
    def fetch():
        fetches.append(1)
        return {"keys": [jwk]}
    check = verifier(settings(tmp_path), jwk, ttl=60, fetcher=fetch)
    check.verify(make_token(private))
    check.verify(make_token(private))
    assert len(fetches) == 1
    with pytest.raises(SkyfireTokenError):
        verifier(settings(tmp_path), jwk, ttl=3601)


def test_required_configuration_fails_closed(monkeypatch):
    for name in (
        "SKYFIRE_ISSUER", "SKYFIRE_JWKS_URL", "SKYFIRE_EXPECTED_ENVIRONMENT",
        "SKYFIRE_PROTOCOL_PROFILE", "SKYFIRE_EXPECTED_AUDIENCE",
        "SKYFIRE_ACCOUNT_CONFIGURATION_CONFIRMED",
        "SKYFIRE_SELLER_AGENT_ACCOUNT_ID", "SKYFIRE_SELLER_SERVICE_ID", "TRUSTGUARD_DATABASE_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(SkyfireTokenError):
        SkyfireSettings.from_env()
    app = create_app()
    status, _, _ = asgi_request(app, "GET", "/healthz")
    assert status == 503
    status, _, _ = asgi_request(app, "POST", "/v1/agent/authorize", headers={"KYAPay-Token": "not-stored"})
    assert status == 503


def test_api_openapi_health_and_header_documentation(tmp_path):
    fake = FakeVerifier({"jti": "unused", "exp": int(time.time()) + 300, "token_type": "kya+jwt", "sub": "buyer", "aud": SELLER_ID, "tsi": SERVICE_ID, "tdm": None, "amount": None, "currency": None})
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "api.sqlite3"), verifier=fake, openapi_enabled=True)
    status, _, body = asgi_request(app, "GET", "/healthz")
    assert status == 200 and json.loads(body)["status"] == "ok"
    status, _, body = asgi_request(app, "GET", "/openapi.json")
    assert status == 200
    spec = json.loads(body)
    assert "/v1/agent/authorize" in spec["paths"]
    parameters = spec["paths"]["/v1/agent/authorize"]["post"]["parameters"]
    assert any(p["in"] == "header" and p["name"] == "KYAPay-Token" and p["required"] is True for p in parameters)


def test_publication_policy_and_formal_openapi_validation(tmp_path):
    from openapi_spec_validator import validate

    configured = settings(tmp_path)
    disabled = create_app(settings=configured, ledger=Ledger(tmp_path / "metadata-off.sqlite3"), verifier=FakeVerifier({}))
    assert asgi_request(disabled, "GET", "/openapi.json")[0] == 404
    assert asgi_request(disabled, "GET", "/docs")[0] == 404
    assert asgi_request(disabled, "GET", "/redoc")[0] == 404

    published = create_app(
        settings=configured, ledger=Ledger(tmp_path / "metadata-on.sqlite3"), verifier=FakeVerifier({}),
        openapi_enabled=True, openapi_path="/registration/schema.json",
    )
    status, _, body = asgi_request(published, "GET", "/registration/schema.json")
    assert status == 200
    spec = json.loads(body)
    assert spec["openapi"].startswith("3.1.")
    validate(spec)
    assert set(spec["paths"]) == {
        "/healthz", "/v1/agent/authorize", "/v1/agent/screen-transaction",
        "/v1/admin/transactions/{transaction_id}/review",
    }
    assert "servers" not in spec
    assert "securitySchemes" not in spec.get("components", {})
    assert asgi_request(published, "GET", "/docs")[0] == 404
    cors_status, cors_headers, _ = asgi_request(published, "GET", "/healthz", headers={"origin": "https://untrusted.example"})
    assert cors_status == 200
    assert b"access-control-allow-origin" not in cors_headers


def test_request_body_limit_counts_chunked_body_without_content_length(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTGUARD_MAX_REQUEST_BODY_BYTES", "1024")
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "body-limit.sqlite3"), verifier=FakeVerifier({}))
    status, _, body = asgi_request(
        app, "POST", "/v1/agent/authorize", headers={"KYAPay-Token": "LOCAL-TEST-token"},
        body_chunks=[b"a" * 600, b"b" * 600],
    )
    assert status == 413
    assert b"request body too large" in body


def test_request_body_limit_rejects_oversized_content_length(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTGUARD_MAX_REQUEST_BODY_BYTES", "1024")
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "body-length.sqlite3"), verifier=FakeVerifier({}))
    status, _, _ = asgi_request(app, "POST", "/v1/agent/authorize", headers={"content-length": "1025"})
    assert status == 413


def test_request_guard_bounds_concurrency_and_times_out_without_external_io():
    from api_security import RequestGuardMiddleware

    async def downstream(scope, receive, send):
        await asyncio.sleep(0.04)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    async def invoke(guard):
        messages = []
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        async def send(message):
            messages.append(message)
        scope = {"type": "http", "method": "GET", "headers": [], "client": ("127.0.0.1", 1)}
        await guard(scope, receive, send)
        return next(message["status"] for message in messages if message["type"] == "http.response.start")

    async def run_concurrency():
        guard = RequestGuardMiddleware(downstream, max_concurrent_requests=1, rate_limit_requests=10)
        return await asyncio.gather(invoke(guard), invoke(guard))

    statuses = asyncio.run(run_concurrency())
    assert sorted(statuses) == [200, 503]

    async def run_timeout():
        guard = RequestGuardMiddleware(downstream, request_timeout_seconds=0.001, rate_limit_requests=10)
        return await invoke(guard)

    assert asyncio.run(run_timeout()) == 504


def test_trusted_host_and_direct_peer_rate_limit(tmp_path, monkeypatch):
    app = create_app(
        settings=settings(tmp_path), ledger=Ledger(tmp_path / "host-limit.sqlite3"), verifier=FakeVerifier({}),
        allowed_hosts=["trustguard.test"],
    )
    assert asgi_request(app, "GET", "/healthz", host="attacker.test")[0] == 400

    monkeypatch.setenv("TRUSTGUARD_RATE_LIMIT_REQUESTS", "1")
    limited = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "rate-limit.sqlite3"), verifier=FakeVerifier({}))
    first = asgi_request(limited, "GET", "/healthz", headers={"x-forwarded-for": "198.51.100.9"}, client_ip="127.0.0.1")
    second = asgi_request(limited, "GET", "/healthz", headers={"x-forwarded-for": "203.0.113.8"}, client_ip="127.0.0.1")
    assert first[0] == 200
    assert second[0] == 429


def test_request_validation_error_redacts_token_and_body_from_response_and_logs(tmp_path, caplog):
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "redaction.sqlite3"), verifier=FakeVerifier({}))
    marker_header = "LOCAL-TEST-RAW-JWT-DO-NOT-ECHO"
    marker_body = "LOCAL-TEST-REVIEWER-SECRET-DO-NOT-ECHO"
    status, _, body = asgi_request(
        app, "POST", "/v1/agent/screen-transaction",
        headers={"KYAPay-Token": marker_header, "content-type": "application/json"},
        body=json.dumps({"transaction_id": marker_body, "unknown": marker_header}).encode(),
    )
    assert status == 422
    assert b"request validation failed" in body
    assert marker_header not in body.decode()
    assert marker_body not in body.decode()
    assert marker_header not in caplog.text
    assert marker_body not in caplog.text


def test_v1_threshold_remains_unchanged():
    assert ANOMALY_THRESHOLD == 0.65


def test_screening_route_remains_provider_free_and_ledger_survives_reopen(tmp_path, monkeypatch):
    from trustguard import TrustGuard
    from paypal_rest import PayPalRestOrdersProvider

    def forbidden(*_args, **_kwargs):
        raise AssertionError("HTTP screening must not invoke payment dispatch or reconciliation")

    monkeypatch.setattr(TrustGuard, "authorize_and_dispatch", forbidden)
    monkeypatch.setattr(TrustGuard, "reconcile", forbidden)
    monkeypatch.setattr(PayPalRestOrdersProvider, "create_order", forbidden)
    monkeypatch.setattr(PayPalRestOrdersProvider, "capture_order", forbidden, raising=False)
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "false")
    app, token, database = local_screening_app(tmp_path, amount="50.00")
    status, _, body = submit_local_screening(app, token, transaction_id="persistent-screen", idempotency_key="persistent-screen-idem")
    assert status == 200
    result = json.loads(body)
    assert result["paypal_dispatch"] == "DISABLED_NOT_CALLED"
    reopened = Ledger(database)
    assert reopened.get("persistent-screen")["status"] == result["transaction_state"]
    assert reopened.get("persistent-screen")["risk_model_version"]


def test_repeated_token_is_accepted_and_never_persisted_or_exposed(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "false")
    private, jwk = signing_material()
    token_id = str(uuid.uuid4())
    token = make_token(private, jti=token_id)
    check = verifier(settings(tmp_path), jwk)
    database = tmp_path / "api-secure.sqlite3"
    app = create_app(settings=settings(tmp_path), ledger=Ledger(database), verifier=check)
    for _ in range(2):
        status, _, body = asgi_request(app, "POST", "/v1/agent/authorize", headers={"KYAPay-Token": token})
        assert status == 200
        result = json.loads(body)
        assert result["valid"] is True
        assert result["skyfire_payment_authorization"] == {
            "status": "TOKEN_AUTHORIZATION_SIGNAL_ONLY", "amount": "1.25", "currency": "USD",
        }
        assert result["paypal_payment_status"] == "NOT_STARTED"
        assert result["paypal_payment_authorized"] is False
        assert "LOCAL-TEST-ONLY-SENSITIVE-MARKER" not in body.decode()
        assert token not in body.decode()
    assert "LOCAL-TEST-ONLY-SENSITIVE-MARKER" not in caplog.text
    assert token not in caplog.text
    raw_db = database.read_bytes()
    assert token.encode() not in raw_db
    assert token_id.encode() not in raw_db
    assert b"LOCAL-TEST-ONLY-SENSITIVE-MARKER" not in raw_db


def test_missing_header_and_database_startup_failure_fail_closed(tmp_path):
    fake = FakeVerifier({"jti": "unused", "exp": int(time.time()) + 300, "token_type": "kya+jwt", "sub": "buyer", "aud": SELLER_ID, "tsi": SERVICE_ID, "tdm": None, "amount": None, "currency": None})
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "missing.sqlite3"), verifier=fake)
    status, _, _ = asgi_request(app, "POST", "/v1/agent/authorize")
    assert status == 401

    def failing_ledger(_path):
        raise OSError("local database unavailable")
    app_with_bad_store = create_app(settings=settings(tmp_path), verifier=fake, ledger_factory=failing_ledger)
    status, _, body = asgi_request(app_with_bad_store, "POST", "/v1/agent/authorize", headers={"KYAPay-Token": "opaque-local-test-token"})
    assert status == 503
    assert b"opaque-local-test-token" not in body


def test_concurrent_repeated_jti_presentations_are_not_request_replays(tmp_path):
    token_id = str(uuid.uuid4())
    fake = FakeVerifier({
        "jti": token_id, "exp": int(time.time()) + 300, "token_type": "kya+jwt",
        "sub": "buyer", "aud": SELLER_ID, "tsi": SERVICE_ID, "tdm": None, "amount": None, "currency": None,
    })
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "concurrent-api.sqlite3"), verifier=fake)
    def submit(_):
        status, _, _ = asgi_request(
            app, "POST", "/v1/agent/authorize",
            headers={"KYAPay-Token": "LOCAL-TEST-ONLY.a.b"},
        )
        return status
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(submit, range(8)))
    assert statuses == [200] * 8


def test_openapi_documents_provider_free_transaction_screening():
    app = create_app()
    spec = app.openapi()
    operation = spec["paths"]["/v1/agent/screen-transaction"]["post"]
    assert "LOCAL TEST ONLY" in operation["description"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("TransactionScreenResponse")
    assert "PayPal" in spec["info"]["description"]


def test_local_test_only_valid_low_risk_request_runs_real_isolation_forest_and_persists(tmp_path):
    app, token, db_path = local_screening_app(tmp_path, amount="50.00")
    status, _, body = submit_local_screening(app, token, amount="5.00")
    result = json.loads(body)
    assert status == 200
    assert result["status"] == "ALLOW"
    assert result["transaction_state"] == "SCREENED_ALLOW"
    assert result["reason_code"] == "ANOMALY_BELOW_THRESHOLD"
    assert result["risk_assessment"]["model_version"] == MODEL_VERSION
    assert result["risk_assessment"]["training_dataset_id"] == TRAINING_DATASET_ID
    assert result["risk_assessment"]["anomaly_score"] < 0.65
    from risk_scoring import SyntheticIsolationForestScorer
    assert isinstance(app.state.screening.scorer, SyntheticIsolationForestScorer)

    restarted = Ledger(db_path).get("screen-tx-1")
    assert restarted["status"] == "SCREENED_ALLOW"
    assert restarted["risk_decision"] == "ALLOW"
    assert restarted["risk_model_version"] == MODEL_VERSION
    assert restarted["risk_scored_at"] == result["risk_assessment"]["scored_at"]
    assert restarted["anomaly_score"] == result["risk_assessment"]["anomaly_score"]


def test_local_test_only_high_anomaly_returns_hold(tmp_path):
    app, token, db_path = local_screening_app(tmp_path, amount="50.00")
    status, _, body = submit_local_screening(app, token, amount="50.00")
    result = json.loads(body)
    assert status == 200
    assert result["status"] == "HOLD"
    assert result["transaction_state"] == "HOLD"
    assert result["reason_code"] == "ANOMALY_THRESHOLD_EXCEEDED"
    assert result["risk_assessment"]["anomaly_score"] >= 0.65
    assert Ledger(db_path).get("screen-tx-1")["risk_decision"] == "HOLD"


def test_screening_rejects_invalid_skyfire_signature(tmp_path):
    app, _, db_path = local_screening_app(tmp_path)
    status, _, body = submit_local_screening(app, "not-a-signed-token")
    assert status == 401
    assert b"not-a-signed-token" not in body
    assert Ledger(db_path).get("screen-tx-1") is None


@pytest.mark.parametrize("overrides", [
    {"amount": "50.01"},
    {"currency": "EUR"},
])
def test_screening_rejects_amount_or_currency_mismatch(tmp_path, overrides):
    app, token, db_path = local_screening_app(tmp_path, amount="50.00")
    status, _, body = submit_local_screening(app, token, **overrides)
    assert status == 403
    assert b"not-a-signed-token" not in body
    assert Ledger(db_path).get("screen-tx-1") is None


def test_screening_model_failure_returns_persisted_hold(tmp_path):
    app, token, db_path = local_screening_app(tmp_path, amount="50.00", risk_scorer_marker=None)
    status, _, body = submit_local_screening(app, token)
    result = json.loads(body)
    assert status == 200
    assert result["status"] == "HOLD"
    assert result["reason_code"] == "MODEL_UNAVAILABLE"
    assert result["risk_assessment"]["anomaly_score"] is None
    assert Ledger(db_path).get("screen-tx-1")["status"] == "HOLD"


def test_screening_never_invokes_paypal_or_provider_dispatch(tmp_path, monkeypatch):
    from trustguard import TrustGuard
    from paypal_rest import PayPalRestOrdersProvider

    def forbidden(*_args, **_kwargs):
        raise AssertionError("screening must never invoke provider dispatch")

    monkeypatch.setattr(TrustGuard, "authorize_and_dispatch", forbidden)
    monkeypatch.setattr(PayPalRestOrdersProvider, "create_order", forbidden)
    app, token, _ = local_screening_app(tmp_path, amount="50.00")
    status, _, body = submit_local_screening(app, token)
    assert status == 200
    assert json.loads(body)["paypal_dispatch"] == "DISABLED_NOT_CALLED"


def test_screening_duplicate_reuses_one_reservation_and_one_assessment(tmp_path):
    app, token, db_path = local_screening_app(tmp_path, amount="50.00")
    first = submit_local_screening(app, token, transaction_id="duplicate-screen", idempotency_key="duplicate-screen-key", amount="5.00")
    second = submit_local_screening(app, token, transaction_id="duplicate-screen", idempotency_key="duplicate-screen-key", amount="5.00")
    assert first[0] == second[0] == 200
    assert json.loads(first[2])["status"] == json.loads(second[2])["status"] == "ALLOW"
    conflict = submit_local_screening(app, token, transaction_id="duplicate-screen", idempotency_key="different-key", amount="5.00")
    assert conflict[0] == 409
    with Ledger(db_path)._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM transactions WHERE transaction_id='duplicate-screen'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM risk_assessments WHERE transaction_id='duplicate-screen'").fetchone()[0] == 1


def test_screening_fails_closed_without_skyfire_configuration(monkeypatch, tmp_path):
    for name in (
        "SKYFIRE_ISSUER", "SKYFIRE_JWKS_URL", "SKYFIRE_EXPECTED_ENVIRONMENT",
        "SKYFIRE_PROTOCOL_PROFILE", "SKYFIRE_EXPECTED_AUDIENCE",
        "SKYFIRE_ACCOUNT_CONFIGURATION_CONFIRMED",
        "SKYFIRE_SELLER_AGENT_ACCOUNT_ID", "SKYFIRE_SELLER_SERVICE_ID", "TRUSTGUARD_DATABASE_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    app = create_app()
    status, _, _ = submit_local_screening(app, "synthetic-local-token")
    assert status == 503


TEST_PAYPAL_MERCHANT = "LOCAL-TEST-PAYPAL-MERCHANT-01"
TEST_REVIEWER_ID = "LOCAL-TEST-REVIEWER-01"
TEST_REVIEWER_CREDENTIAL = "local-test-only-review-credential-not-a-secret"


def configure_test_mapping(monkeypatch, *, service_id=SERVICE_ID, merchant_id=TEST_PAYPAL_MERCHANT):
    monkeypatch.setenv("TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID", service_id)
    monkeypatch.setenv("TRUSTGUARD_PAYPAL_MERCHANT_ID", merchant_id)


def configure_test_reviewer(monkeypatch):
    monkeypatch.setenv("TRUSTGUARD_REVIEWER_ID", TEST_REVIEWER_ID)
    monkeypatch.setenv("TRUSTGUARD_REVIEWER_CREDENTIAL", TEST_REVIEWER_CREDENTIAL)


def submit_review(app, transaction_id, *, decision="RELEASE_RESERVATION", reason="LOCAL TEST ONLY synthetic HOLD review", credential=TEST_REVIEWER_CREDENTIAL):
    body = json.dumps({"decision": decision, "reason": reason}).encode()
    return asgi_request(
        app, "POST", f"/v1/admin/transactions/{transaction_id}/review",
        headers={"x-trustguard-reviewer-credential": credential, "content-type": "application/json"},
        body=body,
    )


def clear_test_mapping(monkeypatch):
    monkeypatch.delenv("TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID", raising=False)
    monkeypatch.delenv("TRUSTGUARD_PAYPAL_MERCHANT_ID", raising=False)


def clear_test_reviewer(monkeypatch):
    monkeypatch.delenv("TRUSTGUARD_REVIEWER_ID", raising=False)
    monkeypatch.delenv("TRUSTGUARD_REVIEWER_CREDENTIAL", raising=False)


def test_skyfire_service_id_and_paypal_merchant_are_distinct_server_mapped_fields(tmp_path, monkeypatch):
    configure_test_mapping(monkeypatch)
    app, token, db_path = local_screening_app(tmp_path, amount="50.00")
    status, _, body = submit_local_screening(app, token, amount="5.00")
    result = json.loads(body)
    record = Ledger(db_path).get("screen-tx-1")
    assert status == 200
    assert result["skyfire_service_id"] == SERVICE_ID
    assert result["paypal_merchant_id"] == TEST_PAYPAL_MERCHANT
    assert result["paypal_integration_status"] == "CONFIGURED"
    assert result["skyfire_service_id"] != result["paypal_merchant_id"]
    assert record["skyfire_service_id"] == SERVICE_ID
    assert record["paypal_merchant_id"] == TEST_PAYPAL_MERCHANT


def test_missing_or_inconsistent_merchant_mapping_is_not_configured(tmp_path, monkeypatch):
    clear_test_mapping(monkeypatch)
    app, token, db_path = local_screening_app(tmp_path, amount="50.00")
    status, _, body = submit_local_screening(app, token)
    result = json.loads(body)
    record = Ledger(db_path).get("screen-tx-1")
    assert status == 200
    assert result["paypal_integration_status"] == "NOT_CONFIGURED"
    assert result["paypal_merchant_id"] is None
    assert record["skyfire_service_id"] == SERVICE_ID
    assert record["paypal_merchant_id"] is None

    other = tmp_path / "mismatch"
    configure_test_mapping(monkeypatch, service_id="different-skyfire-service")
    app_bad, token_bad, db_bad = local_screening_app(other, amount="50.00")
    status, _, body = submit_local_screening(app_bad, token_bad)
    result = json.loads(body)
    assert status == 200
    assert result["paypal_integration_status"] == "NOT_CONFIGURED"
    assert result["paypal_merchant_id"] is None
    assert Ledger(db_bad).get("screen-tx-1")["skyfire_service_id"] == SERVICE_ID


def test_untrusted_screen_request_cannot_override_configured_paypal_merchant(tmp_path, monkeypatch):
    configure_test_mapping(monkeypatch)
    app, token, db_path = local_screening_app(tmp_path, amount="50.00")
    status, _, body = submit_local_screening(
        app, token, paypal_merchant_override="ATTACKER-MERCHANT-OVERRIDE",
    )
    assert status == 422
    assert b"ATTACKER-MERCHANT-OVERRIDE" not in body
    assert Ledger(db_path).get("screen-tx-1") is None
    schema = app.openapi()["components"]["schemas"]["TransactionScreenRequest"]["properties"]
    assert "paypal_merchant_id" not in schema


def test_review_disabled_when_configuration_missing_and_rejects_wrong_credential(tmp_path, monkeypatch):
    clear_test_reviewer(monkeypatch)
    app, token, _ = local_screening_app(tmp_path, amount="50.00", risk_scorer_marker=None)
    submit_local_screening(app, token, transaction_id="review-auth", idempotency_key="review-auth-key", amount="50.00")
    status, _, _ = submit_review(app, "review-auth")
    assert status == 503

    configure_test_reviewer(monkeypatch)
    app, token, _ = local_screening_app(tmp_path / "configured", amount="50.00", risk_scorer_marker=None)
    submit_local_screening(app, token, transaction_id="review-auth2", idempotency_key="review-auth-key2", amount="50.00")
    status, _, body = submit_review(app, "review-auth2", credential="wrong-local-test-credential")
    assert status == 401
    assert b"wrong-local-test-credential" not in body


def test_authenticated_hold_release_is_durable_idempotent_and_releases_reservation(tmp_path, monkeypatch):
    configure_test_reviewer(monkeypatch)
    app, token, db_path = local_screening_app(tmp_path, amount="50.00", risk_scorer_marker=None)
    screen_status, _, screen_body = submit_local_screening(
        app, token, transaction_id="review-release", idempotency_key="review-release-key", amount="50.00",
    )
    assert screen_status == 200 and json.loads(screen_body)["status"] == "HOLD"

    from trustguard import TrustGuard
    from paypal_rest import PayPalRestOrdersProvider
    def forbidden(*_args, **_kwargs):
        raise AssertionError("administrative review must never invoke provider dispatch")
    monkeypatch.setattr(TrustGuard, "authorize_and_dispatch", forbidden)
    monkeypatch.setattr(PayPalRestOrdersProvider, "create_order", forbidden)

    first_status, _, first_body = submit_review(app, "review-release")
    second_status, _, second_body = submit_review(app, "review-release")
    first, second = json.loads(first_body), json.loads(second_body)
    assert first_status == second_status == 200
    assert first == second
    assert first["decision"] == "RELEASE_RESERVATION"
    assert first["transaction_state"] == "REVIEW_RELEASED"
    assert first["reviewer_id"] == TEST_REVIEWER_ID
    assert first["reason"] == "LOCAL TEST ONLY synthetic HOLD review"
    assert TEST_REVIEWER_CREDENTIAL not in first_body.decode()
    record = Ledger(db_path).get("review-release")
    assert record["status"] == "REVIEW_RELEASED"
    assert record["reviewer_id"] == TEST_REVIEWER_ID
    assert record["review_decision"] == "RELEASE_RESERVATION"
    assert record["review_reason"] == first["reason"]
    assert record["reviewed_at"] == first["reviewed_at"]
    with Ledger(db_path)._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM transaction_reviews WHERE transaction_id='review-release'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM transactions WHERE grant_id=? AND status IN ('RESERVED','SCREENED_ALLOW','HOLD','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','UNKNOWN')", (record["grant_id"],)).fetchone()[0] == 0

    from trustguard import CanonicalTransaction
    released_capacity_tx = CanonicalTransaction.build(
        transaction_id="after-release", idempotency_key="after-release-key", amount="50.00",
        currency="USD", skyfire_service_id=SERVICE_ID,
    )
    assert Ledger(db_path).reserve(record["grant_id"], released_capacity_tx, 5000, "USD") == "RESERVED"


def _make_review_state(ledger, transaction_id, state, provider_order_id=None):
    from trustguard import CanonicalTransaction
    tx = CanonicalTransaction.build(
        transaction_id=transaction_id, idempotency_key=f"{transaction_id}-idem",
        amount="1.00", currency="USD", skyfire_service_id=SERVICE_ID,
    )
    ledger.reserve("review-state-grant", tx, 1000, "USD")
    if state in {"DISPATCH_STARTED", "UNKNOWN", "CREATED"}:
        ledger.transition(transaction_id, "DISPATCH_STARTED")
        if state == "UNKNOWN":
            ledger.transition(transaction_id, "UNKNOWN", provider_order_id)
        elif state == "CREATED":
            ledger.transition(transaction_id, "CREATED", provider_order_id or "ORDER-TEST")
    elif state == "HOLD_WITH_ORDER":
        with ledger._connect() as db:
            db.execute("UPDATE transactions SET status='HOLD',provider_order_id='ORDER-TEST' WHERE transaction_id=?", (transaction_id,))
    elif state == "HOLD":
        with ledger._connect() as db:
            db.execute("UPDATE transactions SET status='HOLD' WHERE transaction_id=?", (transaction_id,))


@pytest.mark.parametrize("state", ["DISPATCH_STARTED", "UNKNOWN", "CREATED", "HOLD_WITH_ORDER"])
def test_review_rejects_dispatched_unknown_or_provider_order_states(tmp_path, monkeypatch, state):
    configure_test_reviewer(monkeypatch)
    ledger = Ledger(tmp_path / f"review-{state}.sqlite")
    transaction_id = f"state-{state}"
    _make_review_state(ledger, transaction_id, state)
    app = create_app(settings=settings(tmp_path), ledger=ledger, verifier=FakeVerifier({}))
    status, _, _ = submit_review(app, transaction_id)
    assert status == 409
    assert ledger.get(transaction_id)["reviewer_id"] is None


def test_review_rejects_conflicting_duplicate_and_audits_keep_hold(tmp_path, monkeypatch):
    configure_test_reviewer(monkeypatch)
    ledger = Ledger(tmp_path / "keep-hold.sqlite")
    _make_review_state(ledger, "keep-hold", "HOLD")
    app = create_app(settings=settings(tmp_path), ledger=ledger, verifier=FakeVerifier({}))
    first = submit_review(app, "keep-hold", decision="KEEP_HOLD", reason="retain pending manual evidence")
    duplicate = submit_review(app, "keep-hold", decision="KEEP_HOLD", reason="retain pending manual evidence")
    conflict = submit_review(app, "keep-hold", decision="RELEASE_RESERVATION", reason="different choice")
    assert first[0] == duplicate[0] == 200
    assert json.loads(first[2]) == json.loads(duplicate[2])
    assert conflict[0] == 409
    record = ledger.get("keep-hold")
    assert record["status"] == "HOLD"
    assert record["review_decision"] == "KEEP_HOLD"
    with ledger._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM transaction_reviews WHERE transaction_id='keep-hold'").fetchone()[0] == 1
