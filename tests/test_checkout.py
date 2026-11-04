import base64
import hashlib
import sqlite3
import time

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ec

from paypal_rest import ORDERS_PATH, SANDBOX_BASE_URL, TOKEN_PATH, PayPalRestOrdersProvider
from trustguard import (
    CanonicalTransaction,
    ConfigurationError,
    Ledger,
    LedgerError,
    ProviderAmbiguousError,
    RiskScreeningPipeline,
    SecurityError,
    TrustConfig,
    TrustGuard,
    jwk_thumbprint,
)
from risk_scoring import RiskAssessment


ISSUER = "https://issuer.example"
AUDIENCE = "trustguard-checkout"
MERCHANT = "merchant-1"
SERVICE = "service-1"
ORDER_ID = "PAYPAL-ORDER-1"
CAPTURE_ID = "PAYPAL-CAPTURE-1"
CHECKOUT_URL = "https://merchant.example/pay"


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
    """Deterministic HTTP double; an exhausted queue is a test failure, not network."""

    def __init__(self, *, post=(), get=()):
        self.post_responses = list(post)
        self.get_responses = list(get)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if not self.post_responses:
            raise AssertionError(f"unexpected POST: {url}")
        response = self.post_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if not self.get_responses:
            raise AssertionError(f"unexpected GET: {url}")
        response = self.get_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FixedRiskScorer:
    model_version = "checkout-test-model"
    training_dataset_id = "checkout-test-data"

    def __init__(self, decision="ALLOW", score=0.01):
        self.decision = decision
        self.score_value = score

    def score(self, features):
        assert set(features) == {
            "amount_to_grant_ratio",
            "cumulative_spending_ratio",
            "recent_velocity_ratio",
            "new_payee",
        }
        return RiskAssessment(self.model_version, self.training_dataset_id, self.score_value, self.decision)


def trust_config(signing_key):
    return TrustConfig.from_values(
        issuer=ISSUER,
        audience=AUDIENCE,
        trusted_keys={"access-key": signing_key.public_key()},
        grant_id_field="gid",
        grant_limit_field="limit",
        grant_currency_field="currency",
        grant_payees_field="payees",
        jwt_algorithms=("ES256",),
    )


def set_paypal_env(monkeypatch, *, mapped_service=SERVICE):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "synthetic-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "synthetic-client-secret")
    monkeypatch.setenv("TRUSTGUARD_PAYPAL_MERCHANT_ID", MERCHANT)
    monkeypatch.setenv("SKYFIRE_SELLER_SERVICE_ID", SERVICE)
    monkeypatch.setenv("TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID", mapped_service)


def transaction(*, transaction_id="tx-low5", idempotency_key="create-request-1", amount="5.00"):
    return CanonicalTransaction.build(
        transaction_id=transaction_id,
        idempotency_key=idempotency_key,
        amount=amount,
        currency="USD",
        payee=MERCHANT,
        skyfire_service_id=SERVICE,
        paypal_merchant_id=MERCHANT,
    )


def order_unit(tx, *, amount=None, currency=None, merchant=None, captures=None):
    unit = {
        "reference_id": tx.transaction_id,
        "payee": {"merchant_id": merchant or MERCHANT},
        "amount": {
            "currency_code": currency or tx.currency,
            "value": amount or f"{tx.amount_decimal:.2f}",
        },
    }
    if captures is not None:
        unit["payments"] = {"captures": captures}
    return unit


def paypal_order(tx, status="CREATED", *, order_id=ORDER_ID, unit=None, links=None):
    body = {
        "id": order_id,
        "status": status,
        "purchase_units": [unit or order_unit(tx)],
    }
    if links is not None:
        body["links"] = links
    return body


def completed_order(tx, *, amount=None, currency=None, merchant=None, capture_ids=(CAPTURE_ID,)):
    captures = [
        {
            "id": capture_id,
            "status": "COMPLETED",
            "amount": {
                "currency_code": currency or tx.currency,
                "value": amount or f"{tx.amount_decimal:.2f}",
            },
        }
        for capture_id in capture_ids
    ]
    return paypal_order(
        tx,
        "COMPLETED",
        unit=order_unit(tx, amount=amount, currency=currency, merchant=merchant, captures=captures),
    )


def auth_material(*, suffix="1", grant_limit=10000, access_key=None):
    access_key = access_key or ec.generate_private_key(ec.SECP256R1())
    dpop_key = ec.generate_private_key(ec.SECP256R1())
    dpop_jwk = jwt.algorithms.ECAlgorithm.to_jwk(dpop_key.public_key(), as_dict=True)
    config = trust_config(access_key)
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "synthetic-agent",
            "iat": now - 1,
            "exp": now + 600,
            "jti": f"access-{suffix}",
            "cnf": {"jkt": jwk_thumbprint(dpop_jwk)},
            "delegation_grant": {
                "gid": "grant-low5",
                "limit": grant_limit,
                "currency": "USD",
                "payees": [MERCHANT],
            },
        },
        access_key,
        algorithm="ES256",
        headers={"kid": "access-key"},
    )
    ath = base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()
    proof = jwt.encode(
        {
            "htm": "POST",
            "htu": CHECKOUT_URL,
            "iat": now,
            "jti": f"proof-{suffix}",
            "ath": ath,
        },
        dpop_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": dpop_jwk},
    )
    return config, token, proof


def make_provider(monkeypatch, session, config):
    set_paypal_env(monkeypatch)
    return PayPalRestOrdersProvider(config, session=session)


def make_flow(monkeypatch, tmp_path, *, session, scorer=None):
    config, token, proof = auth_material()
    provider = make_provider(monkeypatch, session, config)
    ledger = Ledger(tmp_path / "checkout.sqlite")
    guard = TrustGuard(config, ledger, provider, risk_scorer=scorer or FixedRiskScorer())
    tx = transaction()
    created = guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)
    return guard, ledger, provider, tx, created


def paypal_posts(session, suffix):
    return [call for call in session.calls if call[0] == "POST" and call[1].endswith(suffix)]


def test_sandbox_contract_uses_distinct_canonical_merchant_and_skyfire_mapping(monkeypatch):
    config, _, _ = auth_material()
    tx = transaction()
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, paypal_order(tx)),
        ]
    )
    provider = make_provider(monkeypatch, session, config)
    result = provider.create_order(tx)
    assert result == {"id": ORDER_ID, "status": "CREATED"}
    create = paypal_posts(session, ORDERS_PATH)[0]
    assert create[2]["json"] == {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "reference_id": tx.transaction_id,
                "payee": {"merchant_id": MERCHANT},
                "amount": {"currency_code": "USD", "value": "5.00"},
            }
        ],
    }
    assert SERVICE not in repr(create[2]["json"])
    assert tx.skyfire_service_id == SERVICE
    assert tx.paypal_merchant_id == MERCHANT


def test_skyfire_mapping_is_explicit_and_missing_or_inconsistent_mapping_blocks_calls(monkeypatch):
    config, _, _ = auth_material()
    tx = transaction()
    for mapped_service, seller_service in ((None, SERVICE), ("wrong-service", SERVICE), (SERVICE, "other-service")):
        monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
        monkeypatch.setenv("PAYPAL_CLIENT_ID", "synthetic-client-id")
        monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "synthetic-client-secret")
        monkeypatch.setenv("TRUSTGUARD_PAYPAL_MERCHANT_ID", MERCHANT)
        if mapped_service is None:
            monkeypatch.delenv("TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID", raising=False)
        else:
            monkeypatch.setenv("TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID", mapped_service)
        monkeypatch.setenv("SKYFIRE_SELLER_SERVICE_ID", seller_service)
        session = FakeSession()
        provider = PayPalRestOrdersProvider(config, session=session)
        with pytest.raises(ConfigurationError):
            provider.create_order(tx)
        assert session.calls == []


def test_authorize_low5_grant100_then_explicit_capture_verifies_get_and_is_idempotent(monkeypatch, tmp_path):
    signing_key = ec.generate_private_key(ec.SECP256R1())
    config, token, proof = auth_material(suffix="first", grant_limit=10000, access_key=signing_key)
    tx = transaction()
    capture_body = {"id": ORDER_ID, "status": "COMPLETED"}
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, paypal_order(tx, "CREATED")),
            FakeResponse(201, capture_body),
        ],
        get=[
            FakeResponse(200, paypal_order(tx, "APPROVED")),
            FakeResponse(200, completed_order(tx)),
        ],
    )
    provider = make_provider(monkeypatch, session, config)
    ledger = Ledger(tmp_path / "checkout.sqlite")
    guard = TrustGuard(config, ledger, provider, risk_scorer=FixedRiskScorer())

    created = guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)
    assert created["status"] == "CREATED"
    assert created["payment_completed"] is False
    assert ledger.get(tx.transaction_id)["status"] == "CREATED"

    completed = guard.capture_approved_order(tx.transaction_id, buyer_approved=True)
    assert completed["status"] == "COMPLETED"
    assert completed["payment_completed"] is True
    assert completed["capture_ids"] == [CAPTURE_ID]
    assert ledger.get(tx.transaction_id)["status"] == "COMPLETED"

    # Replaying the authenticated checkout or capture cannot create a second provider request.
    token2_config, token2, proof2 = auth_material(suffix="second", grant_limit=10000, access_key=signing_key)
    assert token2_config.issuer == config.issuer
    assert guard.authorize_and_dispatch(token2, proof2, "POST", CHECKOUT_URL, tx)["status"] == "COMPLETED"
    assert guard.capture_approved_order(tx.transaction_id, buyer_approved=True)["status"] == "COMPLETED"

    create_posts = paypal_posts(session, ORDERS_PATH)
    capture_posts = paypal_posts(session, ORDERS_PATH + "/" + ORDER_ID + "/capture")
    assert len(create_posts) == 1
    assert len(capture_posts) == 1
    assert create_posts[0][2]["headers"]["PayPal-Request-Id"] == tx.idempotency_key
    assert capture_posts[0][2]["headers"]["PayPal-Request-Id"] == ledger.get(tx.transaction_id)["capture_request_id"]
    assert create_posts[0][2]["headers"]["PayPal-Request-Id"] != capture_posts[0][2]["headers"]["PayPal-Request-Id"]
    assert capture_posts[0][2]["json"] == {}
    assert all(call[1].startswith(SANDBOX_BASE_URL) for call in session.calls)
    assert sum(call[1] == SANDBOX_BASE_URL + TOKEN_PATH for call in session.calls) == 1


def test_capture_status_marker_is_persisted_before_capture_post(monkeypatch, tmp_path):
    config, token, proof = auth_material(suffix="marker")
    tx = transaction()
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, paypal_order(tx)),
            FakeResponse(201, {"id": ORDER_ID, "status": "COMPLETED"}),
        ],
        get=[FakeResponse(200, paypal_order(tx, "APPROVED")), FakeResponse(200, completed_order(tx))],
    )
    provider = make_provider(monkeypatch, session, config)
    ledger = Ledger(tmp_path / "marker.sqlite")
    guard = TrustGuard(config, ledger, provider, risk_scorer=FixedRiskScorer())
    assert guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)["status"] == "CREATED"

    observed = {}
    original_capture = provider.capture_order

    def capture_after_marker(canonical_tx, order_id, request_id):
        observed["record"] = ledger.get(canonical_tx.transaction_id)
        return original_capture(canonical_tx, order_id, request_id)

    provider.capture_order = capture_after_marker
    assert guard.capture_approved_order(tx.transaction_id, buyer_approved=True)["status"] == "COMPLETED"
    assert observed["record"]["status"] == "DISPATCH_STARTED"
    assert observed["record"]["capture_request_id"].startswith("cap-")


@pytest.mark.parametrize(
    "bad_unit",
    [
        {"amount": "4.99"},
        {"currency": "EUR"},
        {"merchant": "attacker-merchant"},
    ],
)
def test_capture_get_binding_mismatch_is_unknown(monkeypatch, tmp_path, bad_unit):
    config, token, proof = auth_material(suffix="mismatch-" + str(len(bad_unit)))
    tx = transaction(transaction_id="tx-" + str(len(bad_unit)), idempotency_key="idem-" + str(len(bad_unit)))
    mismatch = completed_order(tx, **bad_unit)
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, paypal_order(tx)),
            FakeResponse(201, {"id": ORDER_ID, "status": "COMPLETED"}),
        ],
        get=[FakeResponse(200, paypal_order(tx, "APPROVED")), FakeResponse(200, mismatch)],
    )
    provider = make_provider(monkeypatch, session, config)
    ledger = Ledger(tmp_path / f"mismatch-{len(bad_unit)}.sqlite")
    guard = TrustGuard(config, ledger, provider, risk_scorer=FixedRiskScorer())
    assert guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)["status"] == "CREATED"
    result = guard.capture_approved_order(tx.transaction_id, buyer_approved=True)
    assert result == {"status": "UNKNOWN", "transaction_id": tx.transaction_id, "payment_completed": False}
    assert ledger.get(tx.transaction_id)["status"] == "UNKNOWN"
    assert len(paypal_posts(session, ORDERS_PATH + "/" + ORDER_ID + "/capture")) == 1


@pytest.mark.parametrize(
    "approval_link",
    [
        "https://www.paypal.com/checkoutnow?token=" + ORDER_ID,
        "https://www.sandbox.paypal.com/checkoutnow?token=ATTACKER-ORDER",
    ],
)
def test_malicious_or_unbound_approval_link_is_ambiguous(monkeypatch, approval_link):
    config, _, _ = auth_material()
    tx = transaction()
    response = paypal_order(tx, links=[{"rel": "approve", "href": approval_link}])
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, response),
        ]
    )
    provider = make_provider(monkeypatch, session, config)
    with pytest.raises(ProviderAmbiguousError) as error:
        provider.create_order(tx)
    assert error.value.provider_order_id == ORDER_ID
    assert all(call[1].startswith(SANDBOX_BASE_URL) for call in session.calls)


def test_hold_and_review_released_never_checkout_or_capture(monkeypatch, tmp_path):
    for index, expected_status in enumerate(("HOLD", "REVIEW_RELEASED")):
        config, token, proof = auth_material(suffix=f"hold-{index}")
        session = FakeSession()
        provider = make_provider(monkeypatch, session, config)
        ledger = Ledger(tmp_path / f"hold-{index}.sqlite")
        guard = TrustGuard(config, ledger, provider, risk_scorer=FixedRiskScorer("HOLD", 0.99))
        tx = transaction(transaction_id=f"hold-tx-{index}", idempotency_key=f"hold-idem-{index}")
        result = guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)
        assert result["status"] == "HOLD"
        if expected_status == "REVIEW_RELEASED":
            review = ledger.review_hold(
                tx.transaction_id,
                reviewer_id="reviewer-1",
                decision="RELEASE_RESERVATION",
                reason="manual release test",
            )
            assert review["transaction_state"] == "REVIEW_RELEASED"
        assert ledger.get(tx.transaction_id)["status"] == expected_status
        with pytest.raises(SecurityError):
            guard.capture_approved_order(tx.transaction_id, buyer_approved=True)
        assert session.calls == []


def test_capture_timeout_becomes_unknown_and_reconcile_approved_never_retries(monkeypatch, tmp_path):
    config, token, proof = auth_material(suffix="timeout")
    tx = transaction()
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, paypal_order(tx)),
            requests.Timeout("capture timed out after dispatch"),
        ],
        get=[
            FakeResponse(200, paypal_order(tx, "APPROVED")),
            FakeResponse(200, paypal_order(tx, "APPROVED")),
        ],
    )
    provider = make_provider(monkeypatch, session, config)
    ledger = Ledger(tmp_path / "timeout.sqlite")
    guard = TrustGuard(config, ledger, provider, risk_scorer=FixedRiskScorer())
    assert guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)["status"] == "CREATED"

    first = guard.capture_approved_order(tx.transaction_id, buyer_approved=True)
    assert first["status"] == "UNKNOWN"
    record = ledger.get(tx.transaction_id)
    assert record["status"] == "UNKNOWN"
    request_id = record["capture_request_id"]
    assert request_id

    reconciled = guard.reconcile(tx.transaction_id)
    assert reconciled["status"] == "APPROVED"
    assert ledger.get(tx.transaction_id)["capture_request_id"] == request_id
    with pytest.raises(LedgerError, match="capture already started"):
        guard.capture_approved_order(tx.transaction_id, buyer_approved=True)
    assert len(paypal_posts(session, ORDERS_PATH + "/" + ORDER_ID + "/capture")) == 1


def test_missing_explicit_buyer_approval_makes_no_provider_calls(monkeypatch, tmp_path):
    config, token, proof = auth_material(suffix="no-buyer")
    tx = transaction()
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, paypal_order(tx)),
        ]
    )
    provider = make_provider(monkeypatch, session, config)
    ledger = Ledger(tmp_path / "no-buyer.sqlite")
    guard = TrustGuard(config, ledger, provider, risk_scorer=FixedRiskScorer())
    assert guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)["status"] == "CREATED"
    calls_after_create = list(session.calls)
    with pytest.raises(SecurityError, match="explicit buyer approval"):
        guard.capture_approved_order(tx.transaction_id)
    assert session.calls == calls_after_create


def test_capture_persistence_trigger_failure_blocks_capture_post(monkeypatch, tmp_path):
    config, token, proof = auth_material(suffix="trigger")
    tx = transaction()
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, paypal_order(tx)),
        ],
        get=[FakeResponse(200, paypal_order(tx, "APPROVED"))],
    )
    provider = make_provider(monkeypatch, session, config)
    db_path = tmp_path / "trigger.sqlite"
    ledger = Ledger(db_path)
    guard = TrustGuard(config, ledger, provider, risk_scorer=FixedRiskScorer())
    assert guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)["status"] == "CREATED"
    db = sqlite3.connect(db_path)
    db.execute(
        """
        CREATE TRIGGER reject_capture_marker
        BEFORE UPDATE OF status ON transactions
        WHEN NEW.status='DISPATCH_STARTED'
        BEGIN SELECT RAISE(ABORT, 'capture marker persistence failed'); END
        """
    )
    db.commit()
    db.close()

    with pytest.raises(sqlite3.IntegrityError, match="capture marker persistence failed"):
        guard.capture_approved_order(tx.transaction_id, buyer_approved=True)
    assert ledger.get(tx.transaction_id)["status"] == "APPROVED"
    assert ledger.get(tx.transaction_id)["capture_request_id"] is None
    assert paypal_posts(session, ORDERS_PATH + "/" + ORDER_ID + "/capture") == []


def test_completed_capture_evidence_and_marker_survive_ledger_reopen(monkeypatch, tmp_path):
    config, token, proof = auth_material(suffix="reopen")
    tx = transaction()
    session = FakeSession(
        post=[
            FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
            FakeResponse(201, paypal_order(tx)),
            FakeResponse(201, {"id": ORDER_ID, "status": "COMPLETED"}),
        ],
        get=[FakeResponse(200, paypal_order(tx, "APPROVED")), FakeResponse(200, completed_order(tx))],
    )
    provider = make_provider(monkeypatch, session, config)
    db_path = tmp_path / "reopen.sqlite"
    ledger = Ledger(db_path)
    guard = TrustGuard(config, ledger, provider, risk_scorer=FixedRiskScorer())
    assert guard.authorize_and_dispatch(token, proof, "POST", CHECKOUT_URL, tx)["status"] == "CREATED"
    assert guard.capture_approved_order(tx.transaction_id, buyer_approved=True)["status"] == "COMPLETED"
    before = ledger.get(tx.transaction_id)
    assert before["capture_request_id"]
    assert any(e["operation"] == "capture" and e["result"]["verified_capture"] for e in before["provider_evidence"])

    reopened = Ledger(db_path)
    after = reopened.get(tx.transaction_id)
    assert after["status"] == "COMPLETED"
    assert after["capture_request_id"] == before["capture_request_id"]
    assert after["provider_evidence"] == before["provider_evidence"]
    reopened_guard = TrustGuard(config, reopened, provider, risk_scorer=FixedRiskScorer())
    assert reopened_guard.capture_approved_order(tx.transaction_id, buyer_approved=True) == {
        "status": "COMPLETED",
        "transaction_id": tx.transaction_id,
        "payment_completed": True,
        "provider_order_id": ORDER_ID,
        "capture_ids": [CAPTURE_ID],
    }
    assert len(paypal_posts(session, ORDERS_PATH + "/" + ORDER_ID + "/capture")) == 1


def test_duplicate_completed_capture_ids_are_not_verified(monkeypatch):
    config, _, _ = auth_material(suffix="duplicate-capture")
    tx = transaction()
    duplicate_captures = (CAPTURE_ID, CAPTURE_ID)
    session = FakeSession(
        post=[FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600})],
        get=[FakeResponse(200, completed_order(tx, capture_ids=duplicate_captures))],
    )
    provider = make_provider(monkeypatch, session, config)
    assert provider.get_order_details(tx, ORDER_ID) == {"id": ORDER_ID, "status": "UNKNOWN"}
    assert len([call for call in session.calls if call[0] == "GET"]) == 1
    assert all(call[1].startswith(SANDBOX_BASE_URL) for call in session.calls)


def test_payer_action_required_returns_bound_sandbox_approval_not_completion(monkeypatch):
    config, _, _ = auth_material(suffix="payer-action")
    tx = transaction()
    approval_url = f"https://www.sandbox.paypal.com/checkoutnow?token={ORDER_ID}"
    session = FakeSession(post=[
        FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 3600}),
        FakeResponse(201, paypal_order(tx, "PAYER_ACTION_REQUIRED", links=[{"rel": "payer-action", "href": approval_url}])),
    ])
    result = make_provider(monkeypatch, session, config).create_order(tx)
    assert result == {"id": ORDER_ID, "status": "CREATED", "approval_url": approval_url}


def test_ledger_cannot_mark_completed_from_a_status_label_without_capture_evidence(tmp_path):
    ledger = Ledger(tmp_path / "no-capture-evidence.sqlite")
    tx = transaction()
    ledger.reserve("evidence-grant", tx, 10000, "USD")
    ledger.transition(tx.transaction_id, "DISPATCH_STARTED")
    ledger.transition(tx.transaction_id, "APPROVED", ORDER_ID)
    with pytest.raises(LedgerError, match="verified provider capture evidence"):
        ledger.transition(tx.transaction_id, "COMPLETED", ORDER_ID)
    assert ledger.get(tx.transaction_id)["status"] == "APPROVED"
