import base64
import hashlib
import time

import pytest
import requests
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from paypal_rest import (
    ORDERS_PATH,
    SANDBOX_BASE_URL,
    TOKEN_PATH,
    PayPalRestOrdersProvider,
)
from trustguard import (
    CanonicalTransaction,
    ConfigurationError,
    ProviderAmbiguousError,
    ProviderDefinitiveError,
    Ledger,
    TrustGuard,
    TrustConfig,
    jwk_thumbprint,
)


@pytest.fixture(autouse=True)
def explicit_test_merchant_mapping(monkeypatch):
    monkeypatch.setenv("TRUSTGUARD_PAYPAL_MERCHANT_ID", "merchant-1")


class FakeResponse:
    def __init__(self, status_code, payload=None, *, json_error=False):
        self.status_code = status_code
        self.payload = payload
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise ValueError("not JSON")
        return self.payload


class FakeSession:
    def __init__(self, *, post=None, get=None):
        self.post_responses = list(post or [])
        self.get_responses = list(get or [])
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        response = self.post_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        response = self.get_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def config():
    return TrustConfig.from_values(
        issuer="https://trusted.example", audience="trustguard", trusted_keys={"k": "public-key"},
        grant_id_field="id", grant_limit_field="limit", grant_currency_field="currency",
        grant_payees_field="payees", jwt_algorithms=("ES256",),
    )


def tx(amount="50.00", currency="USD", payee="merchant-1", txn="local-txn-1", idem="paypal-req-1"):
    return CanonicalTransaction.build(transaction_id=txn, idempotency_key=idem, amount=amount, currency=currency, payee=payee)


def unit_for(transaction, *, amount=None, currency=None, payee=None, captures=None):
    unit = {
        "reference_id": transaction.transaction_id,
        "payee": {"merchant_id": payee or transaction.payee},
        "amount": {"currency_code": currency or transaction.currency, "value": amount or f"{transaction.amount_decimal:.2f}"},
    }
    if captures is not None:
        unit["payments"] = {"captures": captures}
    return unit


def order(transaction, status="CREATED", *, order_id="PAYPAL-ORDER-1", unit=None):
    return {"id": order_id, "status": status, "purchase_units": [unit or unit_for(transaction)]}


def provider(monkeypatch, session, **kwargs):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "test-client-secret")
    return PayPalRestOrdersProvider(config(), session=session, **kwargs)


def test_sandbox_provider_fails_closed_without_flag_or_credentials(monkeypatch):
    monkeypatch.delenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", raising=False)
    with pytest.raises(ConfigurationError):
        PayPalRestOrdersProvider.from_env(config(), session=FakeSession())
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.delenv("PAYPAL_CLIENT_ID", raising=False)
    monkeypatch.delenv("PAYPAL_CLIENT_SECRET", raising=False)
    with pytest.raises(ConfigurationError):
        PayPalRestOrdersProvider.from_env(config(), session=FakeSession())


def test_from_env_loads_credentials_but_runtime_flag_still_blocks_requests(monkeypatch):
    session = FakeSession()
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "test-client-secret")
    api = PayPalRestOrdersProvider.from_env(config(), session=session)
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "false")
    with pytest.raises(ConfigurationError):
        api.create_order(tx())
    assert session.calls == []


def test_incomplete_trust_config_blocks_provider_initialization(monkeypatch):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "test-client-secret")
    incomplete = TrustConfig("", "", {}, (), "", "", "", "")
    with pytest.raises(ConfigurationError):
        PayPalRestOrdersProvider(incomplete, session=FakeSession())


def test_oauth_failure_stops_before_order_request(monkeypatch):
    session = FakeSession(post=[FakeResponse(401, {"error": "invalid_client"})])
    api = provider(monkeypatch, session)
    with pytest.raises(ProviderDefinitiveError):
        api.create_order(tx())
    assert len(session.calls) == 1
    assert session.calls[0][1] == SANDBOX_BASE_URL + TOKEN_PATH
    assert session.calls[0][2]["timeout"] == (3.05, 15.0)
    assert session.calls[0][2]["allow_redirects"] is False


def test_oauth_uses_client_credentials_and_creates_bound_order_with_idempotency(monkeypatch):
    transaction = tx()
    session = FakeSession(post=[
        FakeResponse(200, {"access_token": "opaque-test-token", "expires_in": 3600}),
        FakeResponse(201, order(transaction, "CREATED")),
    ])
    api = provider(monkeypatch, session)
    result = api.create_order(transaction)
    assert result == {"id": "PAYPAL-ORDER-1", "status": "CREATED"}
    oauth = session.calls[0]
    assert oauth[1] == SANDBOX_BASE_URL + TOKEN_PATH
    assert oauth[2]["data"] == {"grant_type": "client_credentials"}
    assert oauth[2]["auth"] == ("test-client-id", "test-client-secret")
    create = session.calls[1]
    assert create[1] == SANDBOX_BASE_URL + ORDERS_PATH
    assert create[2]["headers"]["PayPal-Request-Id"] == transaction.idempotency_key
    assert create[2]["json"] == {
        "intent": "CAPTURE",
        "purchase_units": [{"reference_id": transaction.transaction_id, "payee": {"merchant_id": transaction.payee}, "amount": {"currency_code": transaction.currency, "value": "50.00"}}],
    }
    assert result["status"] != "COMPLETED"


def test_repeated_create_uses_same_paypal_request_id_and_oauth_cache(monkeypatch):
    transaction = tx()
    session = FakeSession(post=[
        FakeResponse(200, {"access_token": "opaque-test-token", "expires_in": 3600}),
        FakeResponse(201, order(transaction, "CREATED")),
        FakeResponse(201, order(transaction, "CREATED")),
    ])
    api = provider(monkeypatch, session)
    api.create_order(transaction)
    api.create_order(transaction)
    create_calls = [c for c in session.calls if c[1] == SANDBOX_BASE_URL + ORDERS_PATH]
    assert len(create_calls) == 2
    assert [c[2]["headers"]["PayPal-Request-Id"] for c in create_calls] == [transaction.idempotency_key] * 2
    assert sum(c[1] == SANDBOX_BASE_URL + TOKEN_PATH for c in session.calls) == 1


def test_order_timeout_is_ambiguous_and_not_retried(monkeypatch):
    session = FakeSession(post=[FakeResponse(200, {"access_token": "token", "expires_in": 3600}), requests.Timeout("timed out")])
    api = provider(monkeypatch, session)
    with pytest.raises(ProviderAmbiguousError):
        api.create_order(tx())
    assert len(session.calls) == 2
    assert session.calls[1][1] == SANDBOX_BASE_URL + ORDERS_PATH


def test_order_idempotency_conflict_is_ambiguous(monkeypatch):
    session = FakeSession(post=[
        FakeResponse(200, {"access_token": "token", "expires_in": 3600}),
        FakeResponse(409, {"name": "ORDER_ALREADY_EXISTS"}),
    ])
    api = provider(monkeypatch, session)
    with pytest.raises(ProviderAmbiguousError):
        api.create_order(tx())
    assert len(session.calls) == 2


@pytest.mark.parametrize("bad_response", [
    FakeResponse(201, None, json_error=True),
    FakeResponse(201, {"status": "CREATED", "purchase_units": []}),
])
def test_malformed_order_response_is_ambiguous(monkeypatch, bad_response):
    session = FakeSession(post=[FakeResponse(200, {"access_token": "token", "expires_in": 3600}), bad_response])
    api = provider(monkeypatch, session)
    with pytest.raises(ProviderAmbiguousError):
        api.create_order(tx())


@pytest.mark.parametrize("unit", [
    lambda t: unit_for(t, amount="51.00"),
    lambda t: unit_for(t, payee="attacker-merchant"),
    lambda t: unit_for(t, currency="EUR"),
])
def test_order_response_amount_currency_and_payee_mismatch_is_ambiguous(monkeypatch, unit):
    transaction = tx()
    session = FakeSession(post=[
        FakeResponse(200, {"access_token": "token", "expires_in": 3600}),
        FakeResponse(201, order(transaction, unit=unit(transaction))),
    ])
    api = provider(monkeypatch, session)
    with pytest.raises(ProviderAmbiguousError) as err:
        api.create_order(transaction)
    assert err.value.provider_order_id == "PAYPAL-ORDER-1"


def test_get_reconciliation_maps_created_and_approved(monkeypatch):
    transaction = tx()
    responses = [FakeResponse(200, order(transaction, s)) for s in ("CREATED", "APPROVED")]
    session = FakeSession(post=[FakeResponse(200, {"access_token": "token", "expires_in": 3600})], get=responses)
    api = provider(monkeypatch, session)
    assert api.get_order_details(transaction, "PAYPAL-ORDER-1")["status"] == "CREATED"
    assert api.get_order_details(transaction, "PAYPAL-ORDER-1")["status"] == "APPROVED"
    assert all(call[1].startswith(SANDBOX_BASE_URL + ORDERS_PATH + "/") for call in session.calls if call[0] == "GET")


def test_get_reconciliation_requires_exact_completed_capture_evidence(monkeypatch):
    transaction = tx()
    captures = [{"id": "CAPTURE-1", "status": "COMPLETED", "amount": {"currency_code": "USD", "value": "50.00"}}]
    session = FakeSession(
        post=[FakeResponse(200, {"access_token": "token", "expires_in": 3600})],
        get=[
            FakeResponse(200, order(transaction, "COMPLETED", unit=unit_for(transaction, captures=captures))),
            FakeResponse(200, order(transaction, "COMPLETED", unit=unit_for(transaction, captures=[{**captures[0], "amount": {"currency_code": "USD", "value": "49.00"}}]))),
            FakeResponse(200, order(transaction, "COMPLETED", unit=unit_for(transaction))),
        ],
    )
    api = provider(monkeypatch, session)
    confirmed = api.get_order_details(transaction, "PAYPAL-ORDER-1")
    assert confirmed == {"id": "PAYPAL-ORDER-1", "status": "COMPLETED", "verified_capture": True, "capture_ids": ["CAPTURE-1"]}
    assert api.get_order_details(transaction, "PAYPAL-ORDER-1")["status"] == "UNKNOWN"
    assert api.get_order_details(transaction, "PAYPAL-ORDER-1")["status"] == "UNKNOWN"


def test_get_reconciliation_wrong_payee_or_order_id_is_unknown(monkeypatch):
    transaction = tx()
    session = FakeSession(
        post=[FakeResponse(200, {"access_token": "token", "expires_in": 3600})],
        get=[
            FakeResponse(200, order(transaction, unit=unit_for(transaction, payee="evil"))),
            FakeResponse(200, order(transaction, order_id="OTHER-ORDER")),
        ],
    )
    api = provider(monkeypatch, session)
    assert api.get_order_details(transaction, "PAYPAL-ORDER-1")["status"] == "UNKNOWN"
    assert api.get_order_details(transaction, "PAYPAL-ORDER-1")["status"] == "UNKNOWN"


def test_voided_order_is_failed_only_when_binding_matches_and_no_completed_capture(monkeypatch):
    transaction = tx()
    session = FakeSession(
        post=[FakeResponse(200, {"access_token": "token", "expires_in": 3600})],
        get=[FakeResponse(200, order(transaction, "VOIDED"))],
    )
    api = provider(monkeypatch, session)
    assert api.get_order_details(transaction, "PAYPAL-ORDER-1")["status"] == "FAILED"


def auth_material():
    access_key = ec.generate_private_key(ec.SECP256R1())
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    trust = TrustConfig.from_values(
        issuer="https://issuer.example", audience="trustguard", trusted_keys={"signing-key": access_key.public_key()},
        grant_id_field="gid", grant_limit_field="limit", grant_currency_field="currency",
        grant_payees_field="payees", jwt_algorithms=("ES256",),
    )
    return access_key, proof_key, jwk, trust


def token_and_proof(access_key, proof_key, jwk, *, suffix="1"):
    now = int(time.time())
    token = jwt.encode({
        "iss": "https://issuer.example", "aud": "trustguard", "sub": "agent",
        "iat": now - 1, "exp": now + 600, "jti": f"access-{suffix}",
        "cnf": {"jkt": jwk_thumbprint(jwk)},
        "delegation_grant": {"gid": "trusted-grant", "limit": 10000, "currency": "USD", "payees": ["merchant-1"]},
    }, access_key, algorithm="ES256", headers={"kid": "signing-key"})
    ath = base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()
    proof = jwt.encode({
        "htm": "POST", "htu": "https://merchant.example/pay", "iat": now,
        "jti": f"proof-{suffix}", "ath": ath,
    }, proof_key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})
    return token, proof


def test_trustguard_sandbox_create_and_reconcile_full_flow(monkeypatch, tmp_path):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "test-client-secret")
    transaction = tx()
    completed = order(transaction, "COMPLETED", unit=unit_for(transaction, captures=[{
        "id": "CAPTURE-1", "status": "COMPLETED", "amount": {"currency_code": "USD", "value": "50.00"},
    }]))
    session = FakeSession(
        post=[FakeResponse(200, {"access_token": "opaque-token", "expires_in": 3600}), FakeResponse(201, order(transaction))],
        get=[FakeResponse(200, completed)],
    )
    access_key, proof_key, jwk, trust = auth_material()
    api = PayPalRestOrdersProvider(trust, session=session)
    ledger = Ledger(tmp_path / "provider-flow.sqlite")
    guard = TrustGuard(trust, ledger, api)
    token, proof = token_and_proof(access_key, proof_key, jwk)
    created = guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", transaction)
    assert created["status"] == "CREATED"
    assert created["payment_completed"] is False
    assert ledger.get(transaction.transaction_id)["status"] == "CREATED"
    result = guard.reconcile(transaction.transaction_id)
    assert result["status"] == "COMPLETED"
    assert result["payment_completed"] is True
    assert ledger.get(transaction.transaction_id)["status"] == "COMPLETED"
    assert [call[0] for call in session.calls] == ["POST", "POST", "GET"]


def test_trustguard_oauth_failure_is_failed_without_order_request(monkeypatch, tmp_path):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "test-client-secret")
    session = FakeSession(post=[FakeResponse(401, {"error": "invalid_client"})])
    access_key, proof_key, jwk, trust = auth_material()
    api = PayPalRestOrdersProvider(trust, session=session)
    ledger = Ledger(tmp_path / "oauth-failure.sqlite")
    guard = TrustGuard(trust, ledger, api)
    token, proof = token_and_proof(access_key, proof_key, jwk)
    result = guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    assert result["status"] == "FAILED"
    assert ledger.get("local-txn-1")["status"] == "FAILED"
    assert len(session.calls) == 1
    assert session.calls[0][1] == SANDBOX_BASE_URL + TOKEN_PATH


def test_trustguard_order_timeout_persists_unknown_and_never_retries(monkeypatch, tmp_path):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "test-client-secret")
    session = FakeSession(post=[FakeResponse(200, {"access_token": "opaque-token", "expires_in": 3600}), requests.Timeout("ambiguous")])
    access_key, proof_key, jwk, trust = auth_material()
    api = PayPalRestOrdersProvider(trust, session=session)
    ledger = Ledger(tmp_path / "timeout.sqlite")
    guard = TrustGuard(trust, ledger, api)
    token, proof = token_and_proof(access_key, proof_key, jwk, suffix="1")
    first = guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    token2, proof2 = token_and_proof(access_key, proof_key, jwk, suffix="2")
    second = guard.authorize_and_dispatch(token2, proof2, "POST", "https://merchant.example/pay", tx())
    assert first["status"] == second["status"] == "UNKNOWN"
    assert ledger.get("local-txn-1")["status"] == "UNKNOWN"
    assert len(session.calls) == 2
    assert all(call[1] != SANDBOX_BASE_URL + ORDERS_PATH for call in session.calls[2:])
    with pytest.raises(Exception, match="no PayPal order ID"):
        guard.reconcile("local-txn-1")
