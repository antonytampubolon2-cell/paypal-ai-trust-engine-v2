import json
import sqlite3

import pytest

from risk_scoring import EXPLANATION_VERSION, explain_assessment
from trustguard import CanonicalTransaction, Ledger, RiskScreeningPipeline

# These helpers generate an ES256 token and a fake JWKS in-process; they do not
# contact the Skyfire network.
from test_skyfire_api import local_screening_app, submit_local_screening


FEATURES_REVERSED = {
    "new_payee": 1.0,
    "recent_velocity_ratio": 0.60,
    "cumulative_spending_ratio": 0.82,
    "amount_to_grant_ratio": 0.70,
}


@pytest.mark.parametrize(
    ("decision", "score", "summary", "first_reason"),
    [
        (
            "ALLOW",
            0.20,
            "Anomaly ranking is below the screening threshold; ALLOW does not prove absence of fraud or authorize payment.",
            "ANOMALY_BELOW_THRESHOLD",
        ),
        (
            "HOLD",
            0.90,
            "Anomaly ranking reached the screening threshold; HOLD requires review. Listed signals describe observed feature context, not proven causes of fraud.",
            "ANOMALY_THRESHOLD_EXCEEDED",
        ),
    ],
)
def test_explanation_is_exact_deterministic_and_ordered(decision, score, summary, first_reason):
    explanation = explain_assessment(FEATURES_REVERSED, decision, score)

    assert explanation == {
        "version": EXPLANATION_VERSION,
        "reason_codes": [
            first_reason,
            "HIGH_AMOUNT_TO_GRANT_RATIO",
            "HIGH_CUMULATIVE_GRANT_UTILIZATION",
            "ELEVATED_RECENT_TRANSACTION_VELOCITY",
            "NEW_PAYEE_FOR_GRANT",
        ],
        "summary": summary,
        "feature_signals": [
            {
                "feature": "amount_to_grant_ratio",
                "value": 0.70,
                "reason_code": "HIGH_AMOUNT_TO_GRANT_RATIO",
                "description": "Transaction amount uses at least 70% of the authenticated grant limit.",
            },
            {
                "feature": "cumulative_spending_ratio",
                "value": 0.82,
                "reason_code": "HIGH_CUMULATIVE_GRANT_UTILIZATION",
                "description": "Reserved and spent amounts use at least 82% of the authenticated grant limit.",
            },
            {
                "feature": "recent_velocity_ratio",
                "value": 0.60,
                "reason_code": "ELEVATED_RECENT_TRANSACTION_VELOCITY",
                "description": "The ledger records at least three other active transactions within ten minutes.",
            },
            {
                "feature": "new_payee",
                "value": 1.0,
                "reason_code": "NEW_PAYEE_FOR_GRANT",
                "description": "No other active transaction for this grant and currency uses this payee.",
            },
        ],
        "method": "Deterministic trusted-feature rule annotations; not causal IsolationForest attribution. Synthetic-model anomaly ranking is not a calibrated fraud probability.",
    }
    assert set(explanation) == {"version", "reason_codes", "summary", "feature_signals", "method"}
    assert all(not key.startswith("_") for key in explanation)


def test_missing_ledger_features_fail_closed_to_durable_hold_and_survive_reopen(monkeypatch, tmp_path):
    path = tmp_path / "missing-features.sqlite3"
    ledger = Ledger(path)
    tx = CanonicalTransaction.build(
        transaction_id="missing-features-tx",
        idempotency_key="missing-features-idem",
        amount="10.00",
        currency="USD",
        skyfire_service_id="service-test",
    )
    monkeypatch.setattr(ledger, "risk_features", lambda *_args, **_kwargs: {})

    result = RiskScreeningPipeline(ledger).screen_authorized_transaction(
        tx,
        grant_id="grant-test",
        max_spend_minor=1000,
        grant_currency="USD",
        authorized_service_id="service-test",
    )
    record = ledger.get(tx.transaction_id)

    assert result["status"] == result["risk_assessment"]["decision"] == "HOLD"
    assert result["risk_assessment"]["anomaly_score"] is None
    assert record["status"] == "HOLD"
    assert record["risk_decision"] == "HOLD"
    assert record["risk_explanation"] == result["risk_assessment"]["explanation"]
    assert record["risk_explanation"]["version"] == EXPLANATION_VERSION
    assert record["risk_explanation"]["reason_codes"] == [
        "MODEL_UNAVAILABLE",
        "TRUSTED_FEATURES_MISSING_OR_INVALID",
    ]
    assert "fail-closed HOLD" in record["risk_explanation"]["summary"]

    reopened = Ledger(path).get(tx.transaction_id)
    assert reopened["risk_explanation"] == record["risk_explanation"]
    assert reopened["risk_decision"] == "HOLD"
    assert reopened["status"] == "HOLD"


def test_legacy_risk_row_gets_explanation_backfilled_without_changing_metadata(tmp_path):
    path = tmp_path / "legacy-risk.sqlite3"
    created_at = 101.25
    updated_at = 202.5
    scored_at = 303.75
    features = {
        "amount_to_grant_ratio": 0.15,
        "cumulative_spending_ratio": 0.25,
        "recent_velocity_ratio": 0.10,
        "new_payee": 0.0,
    }
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE transactions (
            transaction_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE, amount_minor INTEGER NOT NULL,
            currency TEXT NOT NULL, payee TEXT, skyfire_service_id TEXT,
            paypal_merchant_id TEXT,
            status TEXT NOT NULL CHECK(status IN ('RESERVED','SCREENED_ALLOW','HOLD','REVIEW_RELEASED','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','FAILED','UNKNOWN')),
            provider_order_id TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
        );
        CREATE INDEX tx_grant_status ON transactions(grant_id,status);
        CREATE TABLE replay_ids (kind TEXT NOT NULL, jti TEXT NOT NULL, expires_at REAL NOT NULL, PRIMARY KEY(kind,jti));
        CREATE TABLE risk_assessments (
            transaction_id TEXT PRIMARY KEY,
            anomaly_score REAL,
            model_version TEXT NOT NULL,
            training_dataset_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            scored_at REAL NOT NULL,
            features_json TEXT NOT NULL
        );
        """
    )
    db.execute(
        "INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "legacy-risk-tx", "legacy-grant", "legacy-risk-idem", 1500, "USD",
            "merchant-test", "service-test", "merchant-test", "SCREENED_ALLOW",
            None, created_at, updated_at,
        ),
    )
    db.execute(
        "INSERT INTO risk_assessments VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "legacy-risk-tx", 0.12, "legacy-model-v7", "legacy-dataset-v4",
            "ALLOW", scored_at, json.dumps(features, sort_keys=True),
        ),
    )
    db.commit()
    db.close()

    ledger = Ledger(path)
    record = ledger.get("legacy-risk-tx")
    expected = explain_assessment(features, "ALLOW", 0.12)

    assert record["risk_explanation"] == expected
    assert record["risk_model_version"] == "legacy-model-v7"
    assert record["risk_training_dataset_id"] == "legacy-dataset-v4"
    assert record["risk_decision"] == "ALLOW"
    assert record["anomaly_score"] == 0.12
    assert record["risk_scored_at"] == scored_at
    assert record["created_at"] == created_at
    assert record["updated_at"] == updated_at


def test_signed_http_screening_returns_persisted_explanation_and_reuses_decision(tmp_path):
    app, token, db_path = local_screening_app(tmp_path, amount="50.00")

    first_status, _, first_body = submit_local_screening(
        app, token, transaction_id="http-risk-tx", idempotency_key="http-risk-idem", amount="5.00"
    )
    second_status, _, second_body = submit_local_screening(
        app, token, transaction_id="http-risk-tx", idempotency_key="http-risk-idem", amount="5.00"
    )
    first = json.loads(first_body)
    second = json.loads(second_body)
    record = Ledger(db_path).get("http-risk-tx")

    assert first_status == second_status == 200
    assert first == second
    assert first["status"] == first["risk_assessment"]["decision"] == record["risk_decision"]
    assert first["risk_assessment"]["explanation"] == record["risk_explanation"]
    assert first["risk_assessment"]["explanation"]["version"] == EXPLANATION_VERSION

    with Ledger(db_path)._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM transactions WHERE transaction_id=?", ("http-risk-tx",)).fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM risk_assessments WHERE transaction_id=?", ("http-risk-tx",)).fetchone()[0] == 1


class _UnexpectedRiskScorer:
    model_version = "must-not-run"
    training_dataset_id = "must-not-run"

    def __init__(self):
        self.calls = 0

    def score(self, _features):
        self.calls += 1
        raise AssertionError("risk model must not run for an invalid JWT")


def test_invalid_signed_jwt_is_rejected_before_model_explanation_or_provider_dispatch(monkeypatch, tmp_path):
    from paypal_rest import PayPalRestOrdersProvider
    from trustguard import TrustGuard

    def forbidden_dispatch(*_args, **_kwargs):
        raise AssertionError("provider dispatch must not run for an invalid JWT")

    monkeypatch.setattr(TrustGuard, "authorize_and_dispatch", forbidden_dispatch)
    monkeypatch.setattr(PayPalRestOrdersProvider, "create_order", forbidden_dispatch)
    scorer = _UnexpectedRiskScorer()
    app, _, db_path = local_screening_app(tmp_path, risk_scorer_marker=scorer)

    status, _, body = submit_local_screening(app, "not-a-signed-token")

    assert status == 401
    assert b"not-a-signed-token" not in body
    assert scorer.calls == 0
    assert Ledger(db_path).get("screen-tx-1") is None
    with Ledger(db_path)._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0] == 0
