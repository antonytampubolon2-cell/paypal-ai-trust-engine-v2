import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from scripts.run_local_demo import DISCLAIMER, run_demo
from skyfire_auth import (
    DOCUMENTED_SANDBOX_ISSUER,
    DOCUMENTED_SANDBOX_JWKS_URL,
    SkyfireSettings,
    SkyfireTokenError,
    SkyfireTokenVerifier,
)


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "scripts" / "run_local_demo.py"


def test_run_demo_exercises_real_http_routes_and_security_scenarios():
    report = run_demo()
    scenarios = {item["scenario"]: item for item in report["scenarios"]}

    assert scenarios["A — LOW RISK"]["risk_decision"] == "ALLOW"
    assert scenarios["A — LOW RISK"]["durable_ledger_state"] == "SCREENED_ALLOW"
    assert scenarios["A — LOW RISK"]["training_dataset_id"]
    assert scenarios["A — LOW RISK"]["scored_at"] > 0
    assert scenarios["A — LOW RISK"]["explanation"]["method"]
    assert scenarios["B — HIGH RISK"]["risk_decision"] == "HOLD"
    assert scenarios["B — HIGH RISK"]["durable_ledger_state"] == "HOLD"

    authorization = scenarios["F — TOKEN AUTHORIZATION ONLY"]
    assert authorization["token_valid"] is True
    assert authorization["paypal_payment_status"] == "NOT_STARTED"
    assert authorization["paypal_payment_authorized"] is False
    assert authorization["payment_status"] == "NOT_DISPATCHED"

    invalid_auth = scenarios["G — INVALID AUTHENTICATION"]
    assert invalid_auth["http_status"] == 401
    assert invalid_auth["decision"] == "DENY"
    assert invalid_auth["risk_inference_run"] is False
    assert invalid_auth["ledger_record_created"] is False
    assert invalid_auth["payment_status"] == "NOT_DISPATCHED"

    screening_replay = scenarios["H — IDENTICAL SCREENING REQUEST REPLAY"]
    assert screening_replay["http_status"] == 200
    assert screening_replay["same_response_returned"] is True
    assert screening_replay["no_second_inference"] is True
    assert screening_replay["semantics"] == "IDEMPOTENT_REPLAY_NOT_AUTH_FAILURE"

    dpop_replay = scenarios["I — DPOP PROOF REPLAY"]
    assert dpop_replay["decision"] == "DENY"
    assert dpop_replay["reused_proof_rejected"] is True
    assert dpop_replay["control"] == "DURABLE_REPLAY_ID_GUARD_IN_LEGACY_TRUSTGUARD_AUTH_FLOW"

    amount_cap = scenarios["J — AMOUNT ABOVE SIGNED AUTHORIZATION"]
    assert amount_cap["http_status"] == 403
    assert amount_cap["decision"] == "DENY"
    assert amount_cap["ledger_record_created"] is False
    assert amount_cap["risk_inference_run"] is False
    assert amount_cap["payment_status"] == "NOT_DISPATCHED"

    cumulative_cap = scenarios["K — CUMULATIVE GRANT LIMIT"]
    assert cumulative_cap["http_status"] == 409
    assert cumulative_cap["decision"] == "DENY"
    assert cumulative_cap["ledger_record_created"] is False
    assert cumulative_cap["risk_inference_run"] is False
    assert cumulative_cap["payment_status"] == "NOT_DISPATCHED"

    for item in report["scenarios"]:
        assert item.get("execution_label") == "SIMULATED"
        assert item.get("payment_status") == "NOT_DISPATCHED"

    review = scenarios["C — ADMIN REVIEW"]
    assert review["risk_decision"] == "HOLD"
    assert review["durable_ledger_state"] == "REVIEW_RELEASED"
    assert review["reviewer_decision"] == "RELEASE_RESERVATION"
    assert review["reserved_minor_before"] == 5000
    assert review["reserved_minor_after"] == 0
    assert review["audit_persisted"] is True
    assert review["payment_authorized"] is False

    durability = scenarios["D — DURABILITY"]
    assert durability["risk_decision"] == "HOLD"
    assert durability["durable_ledger_state"] == "REVIEW_RELEASED"
    assert durability["restart_idempotency_verified"] is True
    assert durability["transaction_count"] == 2
    assert durability["audit_count"] == 1

    provider_safety = scenarios["E — PROVIDER SAFETY"]
    assert provider_safety["provider_invocation_count"] == 0
    assert provider_safety["external_network_attempt_count"] == 0
    assert provider_safety["paypal_dispatch"] == "DISABLED_NOT_CALLED"
    assert report["provider_invocation_count"] == 0
    assert report["paypal_dispatch"] == "DISABLED_NOT_CALLED"
    assert report["model_inference_count"] == 2
    assert report["disclaimer"] == DISCLAIMER

    assert report["http_routes_exercised"] == [
        ("POST", "/v1/agent/authorize"),
        ("POST", "/v1/agent/screen-transaction"),
        ("POST", "/v1/agent/screen-transaction"),
        ("POST", "/v1/agent/screen-transaction"),
        ("POST", "/v1/agent/screen-transaction"),
        ("POST", "/v1/agent/screen-transaction"),
        ("POST", "/v1/agent/screen-transaction"),
        ("POST", "/v1/admin/transactions/LOCAL-TEST-ONLY-HIGH/review"),
        ("POST", "/v1/agent/screen-transaction"),
        ("POST", "/v1/admin/transactions/LOCAL-TEST-ONLY-HIGH/review"),
        ("POST", "/v1/agent/screen-transaction"),
    ]


def test_run_demo_ignores_hostile_ambient_paypal_environment_and_restores_it(monkeypatch):
    hostile = {
        "TRUSTGUARD_ENABLE_PAYPAL_SANDBOX": "true",
        "PAYPAL_CLIENT_ID": "LOCAL-TEST-ONLY-FAKE-CLIENT-ID",
        "PAYPAL_CLIENT_SECRET": "LOCAL-TEST-ONLY-FAKE-CLIENT-SECRET",
        "TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID": "LOCAL-TEST-ONLY-FAKE-SERVICE",
        "TRUSTGUARD_PAYPAL_MERCHANT_ID": "LOCAL-TEST-ONLY-FAKE-MERCHANT",
    }
    for name, value in hostile.items():
        monkeypatch.setenv(name, value)
    before = os.environ.copy()

    report = run_demo()

    assert os.environ == before
    assert report["provider_invocation_count"] == 0
    assert report["paypal_dispatch"] == "DISABLED_NOT_CALLED"
    provider_safety = next(item for item in report["scenarios"] if item["scenario"] == "E — PROVIDER SAFETY")
    assert provider_safety["provider_invocation_count"] == 0
    assert provider_safety["external_network_attempt_count"] == 0
    report_text = json.dumps(report)
    assert hostile["PAYPAL_CLIENT_ID"] not in report_text
    assert hostile["PAYPAL_CLIENT_SECRET"] not in report_text
    assert hostile["TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID"] not in report_text
    assert hostile["TRUSTGUARD_PAYPAL_MERCHANT_ID"] not in report_text


def test_production_skyfire_verifier_rejects_independently_signed_token_and_is_not_replaced(tmp_path):
    trusted_private = ec.generate_private_key(ec.SECP256R1())
    independent_private = ec.generate_private_key(ec.SECP256R1())
    trusted_jwk = jwt.algorithms.ECAlgorithm.to_jwk(trusted_private.public_key(), as_dict=True)
    trusted_jwk.update({"kid": "LOCAL-TEST-ONLY-TRUSTED", "alg": "ES256", "use": "sig"})
    settings = SkyfireSettings(
        DOCUMENTED_SANDBOX_ISSUER,
        DOCUMENTED_SANDBOX_JWKS_URL,
        "sandbox",
        "LOCAL-TEST-ONLY-SELLER",
        "LOCAL-TEST-ONLY-SERVICE",
        str(tmp_path / "verifier.sqlite3"),
    )
    verifier_method = SkyfireTokenVerifier.verify
    verifier = SkyfireTokenVerifier(settings, jwks_fetcher=lambda: {"keys": [trusted_jwk]})
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": settings.issuer,
            "sub": "LOCAL-TEST-ONLY-BUYER",
            "aud": settings.seller_agent_account_id,
            "iat": now - 5,
            "exp": now + 600,
            "jti": str(uuid.uuid4()),
            "env": "sandbox",
            "tsi": settings.seller_service_id,
        },
        independent_private,
        algorithm="ES256",
        headers={"kid": trusted_jwk["kid"], "typ": "kya+jwt"},
    )

    with pytest.raises(SkyfireTokenError):
        verifier.verify(token)
    assert SkyfireTokenVerifier.verify is verifier_method
    assert verifier_method.__module__ == "skyfire_auth"
    assert Path(verifier_method.__code__.co_filename).resolve() == ROOT / "skyfire_auth.py"


def test_demo_subprocess_emits_json_disclaimer_without_jwt_or_private_material():
    completed = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=os.environ.copy(),
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    report = json.loads(completed.stdout)
    assert report["disclaimer"] == DISCLAIMER
    assert "LOCAL TEST ONLY" in report["disclaimer"]
    assert "eyJ" not in completed.stdout
    assert "-----BEGIN" not in completed.stdout
    assert "PRIVATE KEY" not in completed.stdout
    assert "payment_token" not in completed.stdout
    assert report["provider_invocation_count"] == 0
    assert report["model_inference_count"] == 2
