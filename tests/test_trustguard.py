import concurrent.futures
import inspect
import json
import sqlite3
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from trustguard import (
    Authenticator, CanonicalTransaction, ConfigurationError, Ledger, MockProvider,
    SecurityError, TrustConfig, TrustGuard, build_paypal_order_payload,
    jwk_thumbprint,
)
from risk_scoring import (
    ANOMALY_THRESHOLD, MODEL_VERSION, TRAINING_DATASET_ID,
    RiskAssessment, SyntheticIsolationForestScorer,
)


ISSUER = "https://issuer.example"
AUDIENCE = "trustguard-test"
GRANT = {"gid": "grant-canonical-42", "limit": 10000, "currency": "USD", "payees": ["merchant-1"]}


@pytest.fixture
def signing_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def config(signing_key):
    return TrustConfig.from_values(
        issuer=ISSUER, audience=AUDIENCE, trusted_keys={"access-key": signing_key.public_key()},
        grant_id_field="gid", grant_limit_field="limit", grant_currency_field="currency",
        grant_payees_field="payees", jwt_algorithms=("ES256",),
    )


def access_token(key, *, grant=None, issuer=ISSUER, audience=AUDIENCE, exp=None, jti="token-1", cnf=None):
    now = int(time.time())
    claims = {"iss": issuer, "sub": "agent-1", "aud": audience, "iat": now - 1,
              "exp": exp or now + 600, "jti": jti, "delegation_grant": dict(grant or GRANT),
              "cnf": cnf or {"jkt": "placeholder"}}
    return jwt.encode(claims, key, algorithm="ES256", headers={"kid": "access-key"})


def proof_token(private_key, public_jwk, token, *, method="POST", url="https://merchant.example/pay", jti="proof-1", iat=None, bad_ath=False):
    ath = "bad" if bad_ath else __import__("base64").urlsafe_b64encode(__import__("hashlib").sha256(token.encode()).digest()).rstrip(b"=").decode()
    return jwt.encode({"htm": method, "htu": url, "iat": int(time.time()) if iat is None else iat, "jti": jti, "ath": ath}, private_key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk})


def tx(name="tx-1", idem="idem-1", amount="50.00", currency="USD", payee="merchant-1", supported_currencies=("USD",)):
    return CanonicalTransaction.build(transaction_id=name, idempotency_key=idem, amount=amount, currency=currency, payee=payee, supported_currencies=supported_currencies)


def test_config_fails_closed_without_explicit_grant_contract():
    with pytest.raises(ConfigurationError):
        TrustConfig.from_values(issuer=ISSUER, audience=AUDIENCE, trusted_keys={"x": "key"}, grant_id_field="", grant_limit_field="limit", grant_currency_field="currency", grant_payees_field="payees")


def test_invalid_jwt_signature_rejected(config, signing_key, tmp_path):
    other = ec.generate_private_key(ec.SECP256R1())
    token = access_token(other)
    with pytest.raises(SecurityError):
        Authenticator(config).verify_access_token(token)


@pytest.mark.parametrize("kwargs", [{"issuer": "https://attacker"}, {"audience": "wrong"}, {"exp": int(time.time()) - 10}])
def test_issuer_audience_expiration_rejected(config, signing_key, kwargs):
    with pytest.raises(SecurityError):
        Authenticator(config).verify_access_token(access_token(signing_key, **kwargs))


def test_signed_token_verified_and_grant_id_taken_from_configured_authenticated_claim(config, signing_key):
    claims = Authenticator(config).verify_access_token(access_token(signing_key))
    assert claims["delegation_grant"]["_canonical_grant_id"] == "grant-canonical-42"


def test_dpop_signature_and_request_binding_rejected(config, signing_key):
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    claims = Authenticator(config).verify_access_token(token)
    verifier = Authenticator(config)
    good = proof_token(proof_key, jwk, token)
    verifier.verify_dpop(good, claims, "POST", "https://merchant.example/pay", token)
    with pytest.raises(SecurityError):
        verifier.verify_dpop(good, claims, "GET", "https://merchant.example/pay", token)
    with pytest.raises(SecurityError):
        verifier.verify_dpop(proof_token(ec.generate_private_key(ec.SECP256R1()), jwk, token), claims, "POST", "https://merchant.example/pay", token)


def test_dpop_wrong_access_token_hash_rejected(config, signing_key):
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    claims = Authenticator(config).verify_access_token(token)
    proof = proof_token(proof_key, jwk, token, bad_ath=True)
    with pytest.raises(SecurityError):
        Authenticator(config).verify_dpop(proof, claims, "POST", "https://merchant.example/pay", token)


def test_dpop_persistent_replay_rejected(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    ledger.claim_replay_id("dpop", "same-jti", time.time() + 300)
    with pytest.raises(SecurityError):
        ledger.claim_replay_id("dpop", "same-jti", time.time() + 300)
    assert Ledger(tmp_path / "ledger.sqlite").get("missing") is None


def test_dpop_replay_concurrent_insert_allows_only_one(tmp_path):
    db = tmp_path / "concurrent.sqlite"
    Ledger(db)
    def attempt(_):
        try:
            Ledger(db).claim_replay_id("dpop", "one", time.time() + 300)
            return True
        except SecurityError:
            return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert sum(results) == 1


def test_caller_grant_id_cannot_change_canonical_ledger_identity(tmp_path, config, signing_key):
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    proof = proof_token(proof_key, jwk, token)
    ledger = Ledger(tmp_path / "ledger.sqlite")
    guard = TrustGuard(config, ledger, MockProvider())
    assert "grant_id" not in inspect.signature(TrustGuard.authorize_and_dispatch).parameters
    guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    assert ledger.get("tx-1")["grant_id"] == "grant-canonical-42"


def test_cumulative_spending_and_unknown_reservations(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    ledger.reserve("g", tx("1", "i1", "60.00"), 10000, "USD")
    ledger.transition("1", "DISPATCH_STARTED")
    ledger.transition("1", "UNKNOWN")
    with pytest.raises(SecurityError):
        ledger.reserve("g", tx("2", "i2", "50.00"), 10000, "USD")


def test_concurrent_reservations_cannot_exceed_limit(tmp_path):
    db = tmp_path / "concurrent.sqlite"
    Ledger(db)
    def reserve(i):
        try:
            Ledger(db).reserve("g", tx(f"tx-{i}", f"idem-{i}", "60.00"), 10000, "USD")
            return True
        except SecurityError:
            return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, (1, 2)))
    assert sum(results) == 1


def test_database_transition_failure_blocks_provider_call(tmp_path, config, signing_key):
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    proof = proof_token(proof_key, jwk, token)
    provider = MockProvider()
    ledger = Ledger(tmp_path / "ledger.sqlite")
    def fail(*args, **kwargs):
        raise OSError("simulated durable write failure")
    ledger.transition = fail
    with pytest.raises(OSError):
        TrustGuard(config, ledger, provider).authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    assert provider.calls == []


def test_sqlite_dispatch_state_write_failure_blocks_provider(tmp_path, config, signing_key):
    db_path = tmp_path / "write-failure.sqlite"
    provider = MockProvider()
    ledger = Ledger(db_path)
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    proof = proof_token(proof_key, jwk, token)
    db = sqlite3.connect(db_path)
    db.execute("CREATE TRIGGER reject_dispatch BEFORE UPDATE OF status ON transactions WHEN NEW.status='DISPATCH_STARTED' BEGIN SELECT RAISE(ABORT, 'simulated disk write failure'); END")
    db.commit()
    db.close()
    with pytest.raises(sqlite3.IntegrityError):
        TrustGuard(config, ledger, provider).authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    assert provider.calls == []
    assert Ledger(db_path).get("tx-1")["status"] == "SCREENED_ALLOW"


def test_unknown_is_terminal_and_never_redispatched(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    ledger.reserve("g", tx(), 10000, "USD")
    ledger.transition("tx-1", "DISPATCH_STARTED")
    ledger.transition("tx-1", "UNKNOWN")
    with pytest.raises(Exception):
        ledger.transition("tx-1", "DISPATCH_STARTED")


def test_ambiguous_provider_outcome_is_unknown_and_never_redispatched(tmp_path, config, signing_key):
    provider = MockProvider(TimeoutError("simulated timeout"))
    ledger = Ledger(tmp_path / "unknown.sqlite")
    guard = TrustGuard(config, ledger, provider)
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)}, jti="unknown-token-1")
    proof = proof_token(proof_key, jwk, token, jti="unknown-proof-1")
    result = guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    assert result["status"] == "UNKNOWN"
    assert ledger.get("tx-1")["status"] == "UNKNOWN"
    token2 = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)}, jti="unknown-token-2")
    proof2 = proof_token(proof_key, jwk, token2, jti="unknown-proof-2")
    result2 = guard.authorize_and_dispatch(token2, proof2, "POST", "https://merchant.example/pay", tx())
    assert result2["status"] == "UNKNOWN"
    assert len(provider.calls) == 1


def test_amount_currency_payee_mismatch_rejected(tmp_path, config, signing_key):
    for index, bad in enumerate([tx("a", "a-idem", "10.00", payee="evil"), tx("b", "b-idem", "10.00", currency="EUR", supported_currencies=("USD", "EUR"))]):
        ledger = Ledger(tmp_path / f"ledger-{index}.sqlite")
        guard = TrustGuard(config, ledger, MockProvider())
        proof_key = ec.generate_private_key(ec.SECP256R1())
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
        token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)}, jti=f"token-{index}")
        proof = proof_token(proof_key, jwk, token, jti=f"proof-{index}")
        with pytest.raises(SecurityError):
            guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", bad)


def test_amount_over_authenticated_grant_limit_is_rejected_before_dispatch(tmp_path, config, signing_key):
    provider = MockProvider()
    ledger = Ledger(tmp_path / "amount-limit.sqlite")
    guard = TrustGuard(config, ledger, provider)
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    limited_grant = {"gid": "grant-canonical-42", "limit": 4999, "currency": "USD", "payees": ["merchant-1"]}
    token = access_token(signing_key, grant=limited_grant, cnf={"jkt": jwk_thumbprint(jwk)})
    proof = proof_token(proof_key, jwk, token)
    with pytest.raises(SecurityError, match="spending limit"):
        guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx(amount="50.00"))
    assert provider.calls == []


def test_duplicate_dispatch_after_created_is_not_repeated(tmp_path, config, signing_key):
    provider = MockProvider({"status": "CREATED", "id": "MOCK-ORDER-1"})
    ledger = Ledger(tmp_path / "duplicate.sqlite")
    guard = TrustGuard(config, ledger, provider)
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    first_token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)}, jti="duplicate-token-1")
    first_proof = proof_token(proof_key, jwk, first_token, jti="duplicate-proof-1")
    first = guard.authorize_and_dispatch(first_token, first_proof, "POST", "https://merchant.example/pay", tx())
    second_token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)}, jti="duplicate-token-2")
    second_proof = proof_token(proof_key, jwk, second_token, jti="duplicate-proof-2")
    second = guard.authorize_and_dispatch(second_token, second_proof, "POST", "https://merchant.example/pay", tx())
    assert first["status"] == second["status"] == "CREATED"
    assert len(provider.calls) == 1
    assert Ledger(tmp_path / "duplicate.sqlite").get("tx-1")["provider_order_id"] == "MOCK-ORDER-1"


def test_payload_is_exact_canonical_amount_currency_and_payee():
    payload = build_paypal_order_payload(tx(amount="50.25"))
    unit = payload["purchase_units"][0]
    assert unit["amount"] == {"currency_code": "USD", "value": "50.25"}
    assert unit["payee"] == {"merchant_id": "merchant-1"}


def test_application_restart_persists_transaction_state(tmp_path):
    path = tmp_path / "restart.sqlite"
    first = Ledger(path)
    first.reserve("g", tx(), 10000, "USD")
    first.transition("tx-1", "DISPATCH_STARTED")
    second = Ledger(path)
    assert second.get("tx-1")["status"] == "DISPATCH_STARTED"
    assert path.stat().st_mode & 0o777 == 0o600


def test_existing_order_created_ledger_migrates_to_created(tmp_path):
    path = tmp_path / "legacy.sqlite"
    db = sqlite3.connect(path)
    db.executescript("""
      CREATE TABLE transactions (
        transaction_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
        amount_minor INTEGER NOT NULL, currency TEXT NOT NULL, payee TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('RESERVED','DISPATCH_STARTED','UNKNOWN','ORDER_CREATED','FAILED')),
        provider_order_id TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
      );
      CREATE INDEX tx_grant_status ON transactions(grant_id,status);
      CREATE TABLE replay_ids (kind TEXT NOT NULL,jti TEXT NOT NULL,expires_at REAL NOT NULL,PRIMARY KEY(kind,jti));
      INSERT INTO transactions VALUES('legacy-tx','grant','legacy-idem',5000,'USD','merchant-1','ORDER_CREATED','OLD-ORDER',1,1);
    """)
    db.close()
    ledger = Ledger(path)
    assert ledger.get("legacy-tx")["status"] == "CREATED"
    ledger.transition("legacy-tx", "APPROVED")
    assert ledger.get("legacy-tx")["status"] == "APPROVED"


def test_mock_flow_records_order_created_not_capture_and_has_idempotency(tmp_path, config, signing_key):
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    proof = proof_token(proof_key, jwk, token)
    provider = MockProvider({"status": "CREATED", "id": "MOCK-1"})
    ledger = Ledger(tmp_path / "ledger.sqlite")
    guard = TrustGuard(config, ledger, provider)
    result = guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    assert result["status"] == "CREATED"
    assert ledger.get("tx-1")["status"] == "CREATED"
    assert provider.calls[0][1] == "idem-1"
    assert provider.calls[0][0] == build_paypal_order_payload(tx())
    assert ledger.get("tx-1")["provider_order_id"] == "MOCK-1"


def test_create_response_claiming_completed_is_kept_unknown(tmp_path, config, signing_key):
    provider = MockProvider({"status": "COMPLETED", "id": "MOCK-1", "verified_capture": True})
    ledger = Ledger(tmp_path / "completed-create.sqlite")
    guard = TrustGuard(config, ledger, provider)
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    proof = proof_token(proof_key, jwk, token)
    result = guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    assert result["status"] == "UNKNOWN"
    assert result.get("payment_completed") is not True
    assert ledger.get("tx-1")["status"] == "UNKNOWN"


def test_reconciliation_requires_verified_capture_to_mark_completed(tmp_path, config, signing_key):
    provider = MockProvider(
        {"status": "CREATED", "id": "MOCK-1"},
        {"status": "COMPLETED", "id": "MOCK-1", "verified_capture": True},
    )
    ledger = Ledger(tmp_path / "reconcile.sqlite")
    guard = TrustGuard(config, ledger, provider)
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    proof = proof_token(proof_key, jwk, token)
    created = guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    assert created["status"] == "CREATED"
    assert created["payment_completed"] is False
    result = guard.reconcile("tx-1")
    assert result["status"] == "COMPLETED"
    assert result["payment_completed"] is True
    assert ledger.get("tx-1")["status"] == "COMPLETED"


def test_reconciliation_without_capture_evidence_stays_unknown(tmp_path, config, signing_key):
    provider = MockProvider(
        {"status": "CREATED", "id": "MOCK-1"},
        {"status": "COMPLETED", "id": "MOCK-1"},
    )
    ledger = Ledger(tmp_path / "no-capture.sqlite")
    guard = TrustGuard(config, ledger, provider)
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)})
    proof = proof_token(proof_key, jwk, token)
    guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx())
    result = guard.reconcile("tx-1")
    assert result["status"] == "UNKNOWN"
    assert result["payment_completed"] is False
    assert ledger.get("tx-1")["status"] == "UNKNOWN"


def test_real_provider_dispatch_disabled_by_default(tmp_path, config):
    class Realish:
        def create_order(self, *_):
            raise AssertionError("must not be called")
    with pytest.raises(ConfigurationError):
        TrustGuard(config, Ledger(tmp_path / "ledger.sqlite"), Realish())


def test_in_memory_ledger_is_rejected():
    with pytest.raises(ConfigurationError):
        Ledger(":memory:")


def test_dashboard_is_demo_labeled_and_safe_rendering():
    root = Path(__file__).parents[1]
    html = root.joinpath("dashboard_v2.html").read_text()
    assert "DEMO / SIMULATED" in html
    assert "innerHTML" not in html
    assert "textContent" in html
    assert "UNKNOWN" in html
    assert "trustguard-isolation-forest-synthetic-v1" in html
    assert "not production validated" in html
    data = json.loads(Path(__file__).parents[1].joinpath("hasil.json").read_text())
    assert data["transaksi_terakhir"] is None
    assert data["statistik"] is None

    legacy = root.joinpath("dashboard.html").read_text()
    assert "DEMO / SIMULATED" in legacy
    assert "AKTIF" not in legacy and "LULUS" not in legacy
    assert "7R3064957MB0759941" not in legacy
    assert "No PayPal order IDs or payment outcomes" in legacy


def test_entrypoint_has_no_provider_call():
    source = Path(__file__).parents[1].joinpath("main_public.py").read_text()
    assert "PAYPAL_CLIENT_SECRET" not in source
    assert "create_order" not in source


def dispatch_for_risk_test(guard, config, signing_key, transaction, suffix):
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, cnf={"jkt": jwk_thumbprint(jwk)}, jti=f"risk-token-{suffix}")
    proof = proof_token(proof_key, jwk, token, jti=f"risk-proof-{suffix}")
    return guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", transaction)


class FixedRiskScorer:
    model_version = "test-fixed-risk-v1"
    training_dataset_id = "synthetic-test-fixture-v1"

    def __init__(self, score=0.1, decision="ALLOW", failure=None):
        self.value, self.decision, self.failure = score, decision, failure
        self.calls = []

    def score(self, features):
        self.calls.append(dict(features))
        if self.failure:
            raise self.failure
        return RiskAssessment(self.model_version, self.training_dataset_id, self.value, self.decision)


def test_real_low_anomaly_inference_allows_valid_transaction(config, signing_key, tmp_path):
    provider = MockProvider()
    ledger = Ledger(tmp_path / "low-risk.sqlite")
    guard = TrustGuard(config, ledger, provider)
    result = dispatch_for_risk_test(guard, config, signing_key, tx("low-tx", "low-idem", "10.00"), "low")
    assert result["status"] == "CREATED"
    risk = result["risk_assessment"]
    assert risk["model_version"] == MODEL_VERSION
    assert risk["training_dataset_id"] == TRAINING_DATASET_ID
    assert 0.0 <= risk["anomaly_score"] < ANOMALY_THRESHOLD
    assert risk["decision"] == "ALLOW"
    assert len(provider.calls) == 1


def test_high_anomaly_is_durably_held_without_provider_call(config, signing_key, tmp_path):
    provider = MockProvider()
    path = tmp_path / "high-risk.sqlite"
    ledger = Ledger(path)
    guard = TrustGuard(config, ledger, provider)
    result = dispatch_for_risk_test(guard, config, signing_key, tx("high-tx", "high-idem", "95.00"), "high")
    assert result["status"] == "HOLD"
    assert result["risk_assessment"]["decision"] == "HOLD"
    assert result["risk_assessment"]["anomaly_score"] >= ANOMALY_THRESHOLD
    assert ledger.get("high-tx")["status"] == "HOLD"
    assert provider.calls == []
    restarted = Ledger(path).get("high-tx")
    assert restarted["risk_decision"] == "HOLD"
    assert restarted["risk_model_version"] == MODEL_VERSION
    assert restarted["anomaly_score"] == result["risk_assessment"]["anomaly_score"]
    assert restarted["risk_scored_at"] is not None


def test_inconsistent_high_score_allow_decision_fails_closed(config, signing_key, tmp_path):
    provider = MockProvider()
    scorer = FixedRiskScorer(score=0.99, decision="ALLOW")
    ledger = Ledger(tmp_path / "inconsistent-risk.sqlite")
    guard = TrustGuard(config, ledger, provider, risk_scorer=scorer)
    result = dispatch_for_risk_test(guard, config, signing_key, tx("inconsistent-tx", "inconsistent-idem", "10.00"), "inconsistent")
    assert result["status"] == "HOLD"
    assert ledger.get("inconsistent-tx")["status"] == "HOLD"
    assert provider.calls == []


@pytest.mark.parametrize("risk_scorer", [
    FixedRiskScorer(failure=RuntimeError("synthetic model failure")),
    None,
])
def test_model_failure_or_unavailable_fails_closed_to_hold(config, signing_key, tmp_path, risk_scorer):
    provider = MockProvider()
    ledger = Ledger(tmp_path / f"fail-closed-{id(risk_scorer)}.sqlite")
    guard = TrustGuard(config, ledger, provider, risk_scorer=risk_scorer)
    result = dispatch_for_risk_test(guard, config, signing_key, tx("held-tx", "held-idem", "10.00"), f"held-{id(risk_scorer)}")
    assert result["status"] == "HOLD"
    assert result["risk_assessment"]["decision"] == "HOLD"
    assert result["risk_assessment"]["anomaly_score"] is None
    assert ledger.get("held-tx")["status"] == "HOLD"
    assert provider.calls == []


def test_risk_features_are_ledger_derived_and_cannot_override_authorization(config, signing_key, tmp_path):
    scorer = FixedRiskScorer()
    provider = MockProvider()
    guard = TrustGuard(config, Ledger(tmp_path / "risk-boundary.sqlite"), provider, risk_scorer=scorer)
    assert "risk_features" not in inspect.signature(TrustGuard.authorize_and_dispatch).parameters

    with pytest.raises(SecurityError):
        dispatch_for_risk_test(guard, config, signing_key, tx("bad-payee", "bad-payee-idem", "10.00", payee="merchant-evil"), "bad-payee")
    limited = {"gid": "grant-canonical-42", "limit": 4999, "currency": "USD", "payees": ["merchant-1"]}
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=True)
    token = access_token(signing_key, grant=limited, cnf={"jkt": jwk_thumbprint(jwk)}, jti="risk-limit-token")
    proof = proof_token(proof_key, jwk, token, jti="risk-limit-proof")
    with pytest.raises(SecurityError, match="spending limit"):
        guard.authorize_and_dispatch(token, proof, "POST", "https://merchant.example/pay", tx("over-limit", "over-limit-idem", "50.00"))
    assert scorer.calls == []

    first = tx("idem-first", "shared-risk-idem", "10.00")
    dispatch_for_risk_test(guard, config, signing_key, first, "idem-first")
    second = tx("idem-second", "shared-risk-idem", "11.00")
    with pytest.raises(SecurityError, match="idempotency key"):
        dispatch_for_risk_test(guard, config, signing_key, second, "idem-second")
    assert len(scorer.calls) == 1
    assert scorer.calls[0] == {
        "amount_to_grant_ratio": 0.1,
        "cumulative_spending_ratio": 0.1,
        "recent_velocity_ratio": 0.0,
        "new_payee": 1.0,
    }
    assert len(provider.calls) == 1


def test_risk_decision_and_model_version_survive_ledger_restart(config, signing_key, tmp_path):
    path = tmp_path / "risk-restart.sqlite"
    provider = MockProvider()
    first = Ledger(path)
    result = dispatch_for_risk_test(TrustGuard(config, first, provider), config, signing_key, tx("restart-risk", "restart-risk-idem", "10.00"), "restart")
    restarted = Ledger(path).get("restart-risk")
    assert restarted["risk_model_version"] == result["risk_assessment"]["model_version"]
    assert restarted["risk_training_dataset_id"] == TRAINING_DATASET_ID
    assert restarted["risk_decision"] == "ALLOW"
    assert restarted["risk_scored_at"] is not None
    assert restarted["risk_features"]["amount_to_grant_ratio"] == 0.1


def test_synthetic_model_is_reproducible_for_same_version_and_features():
    features = {
        "amount_to_grant_ratio": 0.1,
        "cumulative_spending_ratio": 0.1,
        "recent_velocity_ratio": 0.0,
        "new_payee": 1.0,
    }
    first = SyntheticIsolationForestScorer().score(features)
    second = SyntheticIsolationForestScorer().score(features)
    assert first.model_version == second.model_version == MODEL_VERSION
    assert first.training_dataset_id == second.training_dataset_id == TRAINING_DATASET_ID
    assert first.anomaly_score == second.anomaly_score
    assert first.decision == second.decision
