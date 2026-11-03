import asyncio
import concurrent.futures
import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app import create_app
from skyfire_auth import (
    SKYFIRE_ISSUER,
    SkyfireSettings,
    SkyfireTokenError,
    SkyfireTokenVerifier,
)
from trustguard import Ledger


SELLER_ID = "seller-agent-test"
SERVICE_ID = "seller-service-test"


class FakeVerifier:
    def __init__(self, result):
        self.result = result
        self.values = []

    def verify(self, token):
        self.values.append(token)
        return self.result


def settings(tmp_path):
    return SkyfireSettings(SELLER_ID, SERVICE_ID, str(tmp_path / "skyfire.sqlite3"))


def signing_material():
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "skyfire-test-key", "alg": "ES256", "use": "sig"})
    return private, jwk


def make_token(private, *, typ="kya-pay+jwt", overrides=None, jti=None):
    now = int(time.time())
    claims = {
        "iss": SKYFIRE_ISSUER,
        "sub": "buyer-agent-account",
        "aud": SELLER_ID,
        "iat": now - 5,
        "exp": now + 600,
        "jti": jti or str(uuid.uuid4()),
        "env": "sandbox",
        "ssi": SERVICE_ID,
        "amt": "1.25",
        "cur": "USD",
        "val": "1250000",
        "stp": "card",
        "sti": {"verified": True, "payment_token": "SENSITIVE-SETTLEMENT-DATA"},
    }
    claims.update(overrides or {})
    return jwt.encode(claims, private, algorithm="ES256", headers={"kid": "skyfire-test-key", "typ": typ})


def verifier(settings_, jwk, *, ttl=300, fetcher=None):
    return SkyfireTokenVerifier(
        settings_,
        jwks_fetcher=fetcher or (lambda: {"keys": [jwk]}),
        cache_ttl_seconds=ttl,
    )


def asgi_request(app, method, path, *, headers=None):
    """Invoke the ASGI app directly; this harness performs no network I/O."""
    messages = []
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
        "headers": [(b"host", b"testserver"), *[(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]],
        "server": ("testserver", 80), "client": ("127.0.0.1", 12345),
    }
    sent_request = False

    async def receive():
        nonlocal sent_request
        if not sent_request:
            sent_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), body


def test_valid_es256_tokens_and_all_supported_types(tmp_path):
    private, jwk = signing_material()
    check = verifier(settings(tmp_path), jwk)
    for typ in ("kya+jwt", "pay+jwt", "kya-pay+jwt", "application/kya-pay+jwt"):
        claims = check.verify(make_token(private, typ=typ))
        assert claims["token_type"] == typ.removeprefix("application/")
        assert claims["aud"] == SELLER_ID
        assert claims["ssi"] == SERVICE_ID
    kya = check.verify(make_token(private, typ="kya+jwt", overrides={"amt": None, "cur": None, "val": None, "stp": None, "sti": None}))
    assert kya["amount"] is None and kya["currency"] is None


@pytest.mark.parametrize("overrides,typ", [
    ({"iss": "https://attacker.example"}, "kya-pay+jwt"),
    ({"aud": "another-seller"}, "kya-pay+jwt"),
    ({"env": "production"}, "kya-pay+jwt"),
    ({"ssi": "another-service"}, "kya-pay+jwt"),
    ({"exp": int(time.time()) - 10}, "kya-pay+jwt"),
    ({"iat": int(time.time()) + 360}, "kya-pay+jwt"),
    ({"jti": "not-a-uuid"}, "kya-pay+jwt"),
    ({"amt": "not-money"}, "pay+jwt"),
    ({"amt": "0"}, "pay+jwt"),
    ({"cur": "usd"}, "pay+jwt"),
    ({"cur": "USDD"}, "pay+jwt"),
    ({"val": "0"}, "pay+jwt"),
    ({"stp": "other"}, "pay+jwt"),
    ({"sti": {"verified": False, "payment_token": "secret"}}, "pay+jwt"),
])
def test_invalid_claims_rejected(tmp_path, overrides, typ):
    private, jwk = signing_material()
    with pytest.raises(SkyfireTokenError):
        verifier(settings(tmp_path), jwk).verify(make_token(private, typ=typ, overrides=overrides))


def test_invalid_signature_and_unknown_kid_rejected(tmp_path):
    private, jwk = signing_material()
    other = ec.generate_private_key(ec.SECP256R1())
    fetches = []
    check = verifier(settings(tmp_path), jwk, fetcher=lambda: (fetches.append(1) or {"keys": [jwk]}))
    with pytest.raises(SkyfireTokenError):
        check.verify(make_token(other))
    wrong_kid_token = jwt.encode(
        {"iss": SKYFIRE_ISSUER, "sub": "buyer", "aud": SELLER_ID, "iat": int(time.time()) - 1,
         "exp": int(time.time()) + 100, "jti": str(uuid.uuid4()), "env": "sandbox", "ssi": SERVICE_ID},
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
        {"iss": SKYFIRE_ISSUER}, "x" * 32, algorithm="HS256",
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
    for name in ("SKYFIRE_SELLER_AGENT_ACCOUNT_ID", "SKYFIRE_SELLER_SERVICE_ID", "TRUSTGUARD_DATABASE_PATH"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(SkyfireTokenError):
        SkyfireSettings.from_env()
    app = create_app()
    status, _, _ = asgi_request(app, "GET", "/healthz")
    assert status == 503
    status, _, _ = asgi_request(app, "POST", "/v1/agent/authorize", headers={"skyfire-pay-id": "not-stored"})
    assert status == 503


def test_api_openapi_health_and_header_documentation(tmp_path):
    fake = FakeVerifier({"jti": "unused", "exp": int(time.time()) + 300, "token_type": "kya+jwt", "sub": "buyer", "aud": SELLER_ID, "ssi": SERVICE_ID, "amount": None, "currency": None})
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "api.sqlite3"), verifier=fake)
    status, _, body = asgi_request(app, "GET", "/healthz")
    assert status == 200 and json.loads(body)["status"] == "ok"
    status, _, body = asgi_request(app, "GET", "/openapi.json")
    assert status == 200
    spec = json.loads(body)
    assert "/v1/agent/authorize" in spec["paths"]
    parameters = spec["paths"]["/v1/agent/authorize"]["post"]["parameters"]
    assert any(p["in"] == "header" and p["name"] == "skyfire-pay-id" and p["required"] is True for p in parameters)


def test_authorize_endpoint_persists_only_jti_and_does_not_expose_sti_or_token(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "false")
    private, jwk = signing_material()
    token_id = str(uuid.uuid4())
    token = make_token(private, jti=token_id)
    check = verifier(settings(tmp_path), jwk)
    database = tmp_path / "api-secure.sqlite3"
    app = create_app(settings=settings(tmp_path), ledger=Ledger(database), verifier=check)
    status, _, body = asgi_request(app, "POST", "/v1/agent/authorize", headers={"skyfire-pay-id": token})
    assert status == 200
    result = json.loads(body)
    assert result["valid"] is True
    assert result["skyfire_payment_authorization"] == {
        "status": "TOKEN_AUTHORIZATION_SIGNAL_ONLY", "amount": "1.25", "currency": "USD",
    }
    assert result["paypal_payment_status"] == "NOT_STARTED"
    assert result["paypal_payment_authorized"] is False
    assert "SENSITIVE-SETTLEMENT-DATA" not in body.decode()
    assert token not in body.decode()
    assert "SENSITIVE-SETTLEMENT-DATA" not in caplog.text
    assert token not in caplog.text
    raw_db = database.read_bytes()
    assert token.encode() not in raw_db
    assert b"SENSITIVE-SETTLEMENT-DATA" not in raw_db
    assert token_id.encode() in raw_db
    duplicate, _, duplicate_body = asgi_request(app, "POST", "/v1/agent/authorize", headers={"skyfire-pay-id": token})
    assert duplicate == 401
    assert "SENSITIVE-SETTLEMENT-DATA" not in duplicate_body.decode()


def test_missing_header_and_replay_database_failure_fail_closed(tmp_path):
    private, jwk = signing_material()
    fake = verifier(settings(tmp_path), jwk)
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "missing.sqlite3"), verifier=fake)
    status, _, _ = asgi_request(app, "POST", "/v1/agent/authorize")
    assert status == 422

    class FailingLedger:
        def claim_replay_id(self, *args, **kwargs):
            raise OSError("write failure")
    token = make_token(private)
    app_with_bad_store = create_app(settings=settings(tmp_path), ledger=FailingLedger(), verifier=fake)
    status, _, body = asgi_request(app_with_bad_store, "POST", "/v1/agent/authorize", headers={"skyfire-pay-id": token})
    assert status == 503
    assert token not in body.decode()


def test_concurrent_duplicate_jti_is_atomically_rejected(tmp_path):
    token_id = str(uuid.uuid4())
    fake = FakeVerifier({
        "jti": token_id, "exp": int(time.time()) + 300, "token_type": "kya+jwt",
        "sub": "buyer", "aud": SELLER_ID, "ssi": SERVICE_ID, "amount": None, "currency": None,
    })
    app = create_app(settings=settings(tmp_path), ledger=Ledger(tmp_path / "concurrent-api.sqlite3"), verifier=fake)
    def submit(_):
        status, _, _ = asgi_request(app, "POST", "/v1/agent/authorize", headers={"skyfire-pay-id": "opaque-local-test-token"})
        return status
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(submit, range(8)))
    assert statuses.count(200) == 1
    assert statuses.count(401) == 7
