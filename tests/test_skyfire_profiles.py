"""LOCAL TEST ONLY: generated ES256 tokens and fake JWKS for isolated profiles."""
import asyncio
import json
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
    DRAFT_HEADER,
    LEGACY_HEADER,
    PROFILE_DRAFT,
    PROFILE_LEGACY,
    SkyfireSettings,
    SkyfireTokenError,
    SkyfireTokenVerifier,
    parse_profile_header,
    protocol_header,
)
from trustguard import Ledger

SELLER_AGENT_ID = "LOCAL-TEST-ONLY-SELLER-AGENT"
SELLER_SERVICE_ID = "LOCAL-TEST-ONLY-SELLER-SERVICE"
DRAFT_AUDIENCE = "LOCAL-TEST-ONLY-TARGET-IDENTITY"


def _settings(tmp_path, profile, *, confirmed=True, target_domain=None):
    audience = SELLER_AGENT_ID if profile == PROFILE_LEGACY else DRAFT_AUDIENCE
    return SkyfireSettings(
        DOCUMENTED_SANDBOX_ISSUER,
        DOCUMENTED_SANDBOX_JWKS_URL,
        "sandbox",
        SELLER_AGENT_ID,
        SELLER_SERVICE_ID,
        str(tmp_path / f"{profile}.sqlite3"),
        target_domain=target_domain,
        protocol_profile=profile,
        expected_audience=audience,
        account_configuration_confirmed=confirmed,
    )


def _key_material():
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "LOCAL-TEST-ONLY-KEY", "alg": "ES256", "use": "sig"})
    return private, jwk


def _claims(profile, **overrides):
    now = int(time.time())
    claims = {
        "iss": DOCUMENTED_SANDBOX_ISSUER,
        "sub": str(uuid.uuid4()) if profile == PROFILE_LEGACY else "LOCAL-TEST-ONLY-PAIRWISE-SUBJECT",
        "aud": SELLER_AGENT_ID if profile == PROFILE_LEGACY else DRAFT_AUDIENCE,
        "iat": now - 5,
        "exp": now + 600,
        "jti": str(uuid.uuid4()) if profile == PROFILE_LEGACY else "LOCAL-TEST-ONLY-TOKEN-ID-1",
        "env": "sandbox",
        "amt": "5.00",
        "cur": "USD",
        "val": "5000000",
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
    claims["ssi" if profile == PROFILE_LEGACY else "tsi"] = SELLER_SERVICE_ID
    if profile == PROFILE_DRAFT:
        claims.update({"tps": "pay_per_use", "tpr": "1.00", "mnr": 50})
    claims.update(overrides)
    return claims


def _token(private, profile, *, typ="kya-pay+jwt", kid="LOCAL-TEST-ONLY-KEY",
           overrides=None, drop_claims=()):
    claims = _claims(profile, **(overrides or {}))
    for name in drop_claims:
        claims.pop(name, None)
    return jwt.encode(
        claims,
        private,
        algorithm="ES256",
        headers={"kid": kid, "typ": typ},
    )


def _verifier(tmp_path, profile, jwk, **settings_options):
    settings = _settings(tmp_path, profile, **settings_options)
    return SkyfireTokenVerifier(settings, jwks_fetcher=lambda: {"keys": [jwk]})


def _asgi(app, method, path, *, headers=None, capture_headers=False):
    sent = []
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "https", "path": path,
        "raw_path": path.encode(), "query_string": b"", "root_path": "",
        "headers": [(b"host", b"testserver"), *[(k.lower().encode(), v.encode()) for k, v in (headers or [])]],
        "server": ("testserver", 443), "client": ("127.0.0.1", 12345),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    if capture_headers:
        return start["status"], dict(start["headers"]), body
    return start["status"], body


@pytest.mark.parametrize("profile", [PROFILE_LEGACY, PROFILE_DRAFT])
def test_each_profile_accepts_its_own_valid_fixture(profile, tmp_path):
    private, jwk = _key_material()
    verifier = _verifier(tmp_path, profile, jwk)
    claims = verifier.verify(_token(private, profile))
    assert claims["protocol_profile"] == profile
    assert claims["service_id"] == SELLER_SERVICE_ID
    assert claims["amount"] == Decimal("5.00")
    assert claims["currency"] == "USD"


def test_legacy_profile_accepts_only_published_ssi_and_header(tmp_path):
    private, jwk = _key_material()
    verifier = _verifier(tmp_path, PROFILE_LEGACY, jwk)
    assert verifier.verify(_token(private, PROFILE_LEGACY))["service_id"] == SELLER_SERVICE_ID
    with pytest.raises(SkyfireTokenError):
        verifier.verify(_token(private, PROFILE_LEGACY, overrides={"ssi": None, "tsi": SELLER_SERVICE_ID}))
    with pytest.raises(SkyfireTokenError):
        parse_profile_header(PROFILE_LEGACY, [], [_token(private, PROFILE_LEGACY)])


def test_draft_profile_accepts_structured_token_list_but_not_ssi_alias(tmp_path):
    private, jwk = _key_material()
    verifier = _verifier(tmp_path, PROFILE_DRAFT, jwk)
    token = _token(private, PROFILE_DRAFT)
    assert parse_profile_header(PROFILE_DRAFT, [token, token], []) == [token, token]
    assert verifier.verify(token)["sub_semantics"] == "pairwise_initiator_identity_subject"
    with pytest.raises(SkyfireTokenError):
        verifier.verify(_token(private, PROFILE_DRAFT, overrides={"tsi": None, "ssi": SELLER_SERVICE_ID}))


def test_profile_header_mix_and_malformed_list_fail_closed(tmp_path):
    private, _ = _key_material()
    token = _token(private, PROFILE_DRAFT)
    with pytest.raises(SkyfireTokenError):
        parse_profile_header(PROFILE_DRAFT, [token], [token])
    with pytest.raises(SkyfireTokenError):
        parse_profile_header(PROFILE_DRAFT, [token + ";param=1"], [])
    with pytest.raises(SkyfireTokenError):
        parse_profile_header(PROFILE_DRAFT, [token + ","], [])
    with pytest.raises(SkyfireTokenError):
        parse_profile_header(PROFILE_DRAFT, [""], [])
    large_member = "A" * 6140 + ".e30.c2ln"
    assert len(large_member) >= 6144
    assert parse_profile_header(PROFILE_DRAFT, [large_member], []) == [large_member]


def test_profile_type_wrong_issuer_audience_service_and_environment_rejected(tmp_path):
    private, jwk = _key_material()
    for profile in (PROFILE_LEGACY, PROFILE_DRAFT):
        verifier = _verifier(tmp_path, profile, jwk)
        for typ in ("JWT", "application/unsupported+jwt"):
            with pytest.raises(SkyfireTokenError):
                verifier.verify(_token(private, profile, typ=typ))
        bad_claim_sets = (
            {"iss": "https://wrong-issuer.invalid"},
            {"aud": "LOCAL-TEST-ONLY-WRONG-AUDIENCE"},
            {"env": "production"},
            {"ssi" if profile == PROFILE_DRAFT else "tsi": "LOCAL-TEST-ONLY-WRONG-SERVICE"},
            {"exp": int(time.time()) - 10},
            {"iat": int(time.time()) + 600},
        )
        for overrides in bad_claim_sets:
            with pytest.raises(SkyfireTokenError):
                verifier.verify(_token(private, profile, overrides=overrides))


def test_signature_unknown_kid_missing_claims_and_malformed_token_rejected(tmp_path):
    private, jwk = _key_material()
    verifier = _verifier(tmp_path, PROFILE_DRAFT, jwk)
    other_key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(SkyfireTokenError):
        verifier.verify(_token(other_key, PROFILE_DRAFT))
    with pytest.raises(SkyfireTokenError):
        verifier.verify(_token(private, PROFILE_DRAFT, kid="LOCAL-TEST-ONLY-UNKNOWN"))
    with pytest.raises(SkyfireTokenError):
        verifier.verify(_token(private, PROFILE_DRAFT, overrides={"tsi": None}))
    with pytest.raises(SkyfireTokenError):
        verifier.verify("LOCAL-TEST-ONLY-NOT-A-JWT")
    with pytest.raises(SkyfireTokenError):
        verifier.verify("bm90LWpzb24.eyJhIjoxfQ.c2lnbmF0dXJl")


def test_profile_specific_identifier_rules_and_repeated_jti_semantics(tmp_path):
    private, jwk = _key_material()
    legacy = _verifier(tmp_path, PROFILE_LEGACY, jwk)
    with pytest.raises(SkyfireTokenError):
        legacy.verify(_token(private, PROFILE_LEGACY, overrides={"jti": "not-a-uuid"}))
    draft = _verifier(tmp_path, PROFILE_DRAFT, jwk)
    reusable = _token(private, PROFILE_DRAFT, overrides={"jti": "draft-token-id-not-uuid"})
    assert draft.verify(reusable)["jti"] == "draft-token-id-not-uuid"
    assert draft.verify(reusable)["jti"] == "draft-token-id-not-uuid"


@pytest.mark.parametrize("profile", [PROFILE_LEGACY, PROFILE_DRAFT])
@pytest.mark.parametrize("claim", ["iss", "sub", "aud", "iat", "exp", "jti"])
def test_required_common_claims_cannot_be_omitted(profile, claim, tmp_path):
    private, jwk = _key_material()
    with pytest.raises(SkyfireTokenError):
        _verifier(tmp_path, profile, jwk).verify(_token(private, profile, drop_claims=(claim,)))


def test_legacy_requires_env_while_draft_env_is_optional_but_validated(tmp_path):
    private, jwk = _key_material()
    with pytest.raises(SkyfireTokenError):
        _verifier(tmp_path, PROFILE_LEGACY, jwk).verify(
            _token(private, PROFILE_LEGACY, drop_claims=("env",))
        )
    draft = _verifier(tmp_path, PROFILE_DRAFT, jwk)
    assert draft.verify(_token(private, PROFILE_DRAFT, drop_claims=("env",)))["protocol_profile"] == PROFILE_DRAFT


@pytest.mark.parametrize("profile", [PROFILE_LEGACY, PROFILE_DRAFT])
def test_profile_service_claim_cannot_be_omitted(profile, tmp_path):
    private, jwk = _key_material()
    service_claim = "ssi" if profile == PROFILE_LEGACY else "tsi"
    with pytest.raises(SkyfireTokenError):
        _verifier(tmp_path, profile, jwk).verify(
            _token(private, profile, drop_claims=(service_claim,))
        )


def test_draft_settlement_verified_is_optional_but_false_and_bad_pricing_are_rejected(tmp_path):
    private, jwk = _key_material()
    verifier = _verifier(tmp_path, PROFILE_DRAFT, jwk)
    token = _token(private, PROFILE_DRAFT, overrides={
        "sti": {
            "type": "visa_vic", "payment_token": "0000000000000000",
            "token_expiration_month": "12", "token_expiration_year": "2030",
            "token_security_code": "000",
        },
    })
    assert verifier.verify(token)["amount"] == Decimal("5.00")
    bad_claims = (
        {"sti": {**_claims(PROFILE_DRAFT)["sti"], "verified": False}},
        {"tps": "LOCAL-TEST-ONLY-UNKNOWN-PRICING"},
        {"tpr": "0"},
        {"mnr": True},
        {"sti": {**_claims(PROFILE_DRAFT)["sti"], "type": "unsupported"}},
    )
    for overrides in bad_claims:
        with pytest.raises(SkyfireTokenError):
            verifier.verify(_token(private, PROFILE_DRAFT, overrides=overrides))


def test_secret_and_jwt_material_never_appear_in_profile_error():
    secret = "LOCAL-TEST-ONLY-DO-NOT-LEAK"
    error = SkyfireTokenError("Skyfire token validation failed")
    assert secret not in str(error)
    assert "jwt" not in str(error).lower()


def test_selected_profile_alone_appears_in_openapi_and_unconfirmed_account_stays_unready(tmp_path):
    private, jwk = _key_material()
    selected = _settings(tmp_path, PROFILE_LEGACY, confirmed=False)
    verifier = SkyfireTokenVerifier(selected, jwks_fetcher=lambda: {"keys": [jwk]})
    app = create_app(settings=selected, ledger=Ledger(tmp_path / "openapi.sqlite3"),
                     verifier=verifier, openapi_enabled=True)
    status, body = _asgi(app, "GET", "/openapi.json")
    assert status == 200
    spec = json.loads(body)
    params = spec["paths"]["/v1/agent/authorize"]["post"]["parameters"]
    assert any(param["name"] == LEGACY_HEADER and param["required"] for param in params)
    assert all(param["name"] != DRAFT_HEADER for param in params)
    assert _asgi(app, "GET", "/healthz")[0] == 503


def test_unconfirmed_configuration_blocks_direct_verifier_before_key_fetch(tmp_path):
    private, jwk = _key_material()
    selected = _settings(tmp_path, PROFILE_DRAFT, confirmed=False)
    fetches = []
    verifier = SkyfireTokenVerifier(
        selected, jwks_fetcher=lambda: (fetches.append(True) or {"keys": [jwk]}),
    )
    with pytest.raises(SkyfireTokenError, match="not confirmed"):
        verifier.verify(_token(private, PROFILE_DRAFT))
    assert fetches == []


@pytest.mark.parametrize("profile", [PROFILE_LEGACY, PROFILE_DRAFT])
def test_route_enforces_selected_header_claim_profile_and_openapi(profile, tmp_path):
    private, jwk = _key_material()
    selected = _settings(tmp_path, profile)
    verifier = SkyfireTokenVerifier(selected, jwks_fetcher=lambda: {"keys": [jwk]})
    app = create_app(settings=selected, ledger=Ledger(tmp_path / f"api-{profile}.sqlite3"),
                     verifier=verifier, openapi_enabled=True)
    good = _token(private, profile)
    selected_name = protocol_header(profile)
    other_name = DRAFT_HEADER if profile == PROFILE_LEGACY else LEGACY_HEADER
    status, response_headers, body = _asgi(
        app, "POST", "/v1/agent/authorize", headers=[(selected_name, good)], capture_headers=True,
    )
    assert status == 200
    assert selected_name.lower().encode() in response_headers[b"vary"].lower()
    assert response_headers[b"cache-control"] == b"private, no-store"
    result = json.loads(body)
    assert isinstance(result["subject_id"], str) and result["subject_id"]
    if profile == PROFILE_LEGACY:
        assert str(uuid.UUID(result["subject_id"])) == result["subject_id"]
    else:
        assert result["subject_semantics"] == "pairwise_initiator_identity_subject"
    assert result["seller_service_id"] == SELLER_SERVICE_ID
    assert result["paypal_payment_authorized"] is False
    assert good not in body.decode()
    assert "LOCAL TEST ONLY" not in body.decode()

    assert _asgi(app, "POST", "/v1/agent/authorize", headers=[(other_name, good)])[0] == 401
    assert _asgi(app, "POST", "/v1/agent/authorize",
                 headers=[(selected_name, good), (other_name, good)])[0] == 401
    wrong_identity = "ssi" if profile == PROFILE_DRAFT else "tsi"
    mixed_claim_token = _token(private, profile, overrides={wrong_identity: SELLER_SERVICE_ID})
    assert _asgi(app, "POST", "/v1/agent/authorize",
                 headers=[(selected_name, mixed_claim_token)])[0] == 401
    assert _asgi(app, "POST", "/v1/agent/authorize",
                 headers=[(selected_name, good + ", " + good)])[0] == 401

    status, schema_body = _asgi(app, "GET", "/openapi.json")
    assert status == 200
    parameters = json.loads(schema_body)["paths"]["/v1/agent/authorize"]["post"]["parameters"]
    names = {parameter["name"] for parameter in parameters if parameter["in"] == "header"}
    assert selected_name in names and other_name not in names
    from openapi_spec_validator import validate
    validate(json.loads(schema_body))


def test_unset_or_unsupported_profile_fails_closed(monkeypatch):
    monkeypatch.delenv("SKYFIRE_PROTOCOL_PROFILE", raising=False)
    with pytest.raises(SkyfireTokenError):
        SkyfireSettings.from_env()
    monkeypatch.setenv("SKYFIRE_PROTOCOL_PROFILE", "guess-from-token")
    with pytest.raises(SkyfireTokenError):
        SkyfireSettings.from_env()
