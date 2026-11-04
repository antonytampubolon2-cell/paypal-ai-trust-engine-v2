import json
import os
from pathlib import Path

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ec

from paypal_rest import PayPalRestOrdersProvider
from scripts import run_paypal_sandbox_demo as demo
from skyfire_auth import (
    DOCUMENTED_SANDBOX_ISSUER,
    DOCUMENTED_SANDBOX_JWKS_URL,
    SkyfireSettings,
    SkyfireTokenError,
    SkyfireTokenVerifier,
)
from trustguard import CanonicalTransaction, ConfigurationError, TrustConfig


ROOT = Path(__file__).resolve().parents[1]
PAYPAL_SYNTHETIC_SERVICE_ID = "LOCAL-TEST-ONLY-PAYPAL-SERVICE-DEMO"
LOCAL_DEMO_SERVICE_ID = PAYPAL_SYNTHETIC_SERVICE_ID
PAYPAL_MERCHANT_ID = "distinct-paypal-merchant"


def valid_environment(tmp_path):
    return {
        "TRUSTGUARD_LOCAL_SANDBOX_DEMO": "true",
        "TRUSTGUARD_ENABLE_PAYPAL_SANDBOX": "true",
        "PAYPAL_CLIENT_ID": "fake-client-id-for-local-test",
        "PAYPAL_CLIENT_SECRET": "fake-secret-for-local-test",
        "TRUSTGUARD_LOCAL_TEST_SERVICE_ID": LOCAL_DEMO_SERVICE_ID,
        "TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID": LOCAL_DEMO_SERVICE_ID,
        "TRUSTGUARD_PAYPAL_MERCHANT_ID": PAYPAL_MERCHANT_ID,
        "TRUSTGUARD_DATABASE_PATH": str(tmp_path / "persistent.sqlite3"),
    }


def test_validate_config_requires_every_gate(tmp_path):
    values = valid_environment(tmp_path)
    for name in demo.REQUIRED_ENV:
        missing = dict(values)
        missing.pop(name)
        with pytest.raises(ValueError, match=name):
            demo.validate_config(missing)


def test_validate_config_rejects_disabled_demo_and_nonpersistent_database(tmp_path):
    values = valid_environment(tmp_path)
    values["TRUSTGUARD_LOCAL_SANDBOX_DEMO"] = "false"
    with pytest.raises(ValueError, match="TRUSTGUARD_LOCAL_SANDBOX_DEMO"):
        demo.validate_config(values)

    values = valid_environment(tmp_path)
    values["TRUSTGUARD_DATABASE_PATH"] = ":memory:"
    with pytest.raises(ValueError, match="persistent"):
        demo.validate_config(values)


@pytest.mark.parametrize("local_flag", [None, "false"])
def test_validate_config_rejects_synthetic_service_without_explicit_local_flag(tmp_path, local_flag):
    values = valid_environment(tmp_path)
    if local_flag is None:
        values.pop("TRUSTGUARD_LOCAL_SANDBOX_DEMO")
    else:
        values["TRUSTGUARD_LOCAL_SANDBOX_DEMO"] = local_flag

    with pytest.raises(ValueError, match="TRUSTGUARD_LOCAL_SANDBOX_DEMO"):
        demo.validate_config(values)


def test_validate_config_rejects_malformed_local_service_prefix(tmp_path):
    values = valid_environment(tmp_path)
    values["TRUSTGUARD_LOCAL_TEST_SERVICE_ID"] = "LOCAL-TEST-SERVICE-DEMO"
    values["TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID"] = values["TRUSTGUARD_LOCAL_TEST_SERVICE_ID"]

    with pytest.raises(ValueError, match="LOCAL-TEST-ONLY-PAYPAL-prefixed"):
        demo.validate_config(values)


def test_validate_config_requires_operator_mapping_and_distinct_namespaces(tmp_path):
    values = valid_environment(tmp_path)
    values["TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID"] = "invented-different-source"
    with pytest.raises(ValueError, match="exactly equal"):
        demo.validate_config(values)

    values = valid_environment(tmp_path)
    values["TRUSTGUARD_PAYPAL_MERCHANT_ID"] = values["TRUSTGUARD_LOCAL_TEST_SERVICE_ID"]
    with pytest.raises(ValueError, match="differ"):
        demo.validate_config(values)


def test_local_credentials_are_es256_and_use_loopback_issuer(tmp_path):
    values = valid_environment(tmp_path)
    config = demo.validate_config(values)
    credentials = demo.generate_local_credentials(
        callback_port=43127,
        merchant_id=config.merchant_id,
        seller_service_id=config.seller_service_id,
    )

    assert config.seller_service_id == LOCAL_DEMO_SERVICE_ID
    assert credentials.trust_config.issuer == "http://127.0.0.1:43127"
    assert credentials.trust_config.jwt_algorithms == ("ES256",)
    assert credentials.dispatch_url == "http://127.0.0.1:43127/local/paypal/authorize"
    header = jwt.get_unverified_header(credentials.access_token)
    assert header["alg"] == "ES256"
    dpop_header = jwt.get_unverified_header(credentials.dpop_proof)
    assert dpop_header["alg"] == "ES256"
    assert "d" not in dpop_header["jwk"]
    claims = jwt.decode(credentials.access_token, options={"verify_signature": False})
    assert claims["iss"] == credentials.trust_config.issuer
    assert claims["delegation_grant"]["limit"] == 10000
    assert claims["delegation_grant"]["payees"] == [config.merchant_id]
    assert "SKYFIRE" not in credentials.access_token


def test_callback_requires_nonce_and_matching_provider_order_token():
    state = demo.CallbackState("random-nonce")
    state.set_expected_order("verified-order-id")

    assert not state.accept("/paypal/callback/random-nonce", {"token": ["other-order"]})
    assert not state.signal.is_set()
    assert not state.accept("/paypal/callback/wrong-nonce", {"token": ["verified-order-id"]})
    assert not state.signal.is_set()

    assert state.accept(
        "/paypal/callback/random-nonce",
        {"token": ["verified-order-id"], "PayerID": ["payer"]},
    )
    assert state.signal.is_set()
    assert state.received_token == "verified-order-id"
    assert state.received_payer_id == "payer"


def test_missing_gate_blocks_fake_credentials_before_provider_or_http(monkeypatch, tmp_path, capsys):
    values = valid_environment(tmp_path)
    values.pop("TRUSTGUARD_LOCAL_SANDBOX_DEMO")
    monkeypatch.setattr(demo.os, "environ", values)

    def forbidden_provider(*_args, **_kwargs):
        raise AssertionError("provider must not be initialized")

    monkeypatch.setattr("paypal_rest.PayPalRestOrdersProvider", forbidden_provider)
    monkeypatch.setattr(
        "requests.sessions.Session.request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("HTTP must not run")),
    )

    assert demo.main() == 2
    output = capsys.readouterr()
    assert "No provider or network was initialized" in output.out + output.err
    assert values["PAYPAL_CLIENT_ID"] not in output.out + output.err
    assert values["PAYPAL_CLIENT_SECRET"] not in output.out + output.err


def test_cli_source_does_not_print_private_material_or_provider_body():
    source = (ROOT / "scripts" / "run_paypal_sandbox_demo.py").read_text()
    assert "traceback" not in source.lower()
    assert "response.text" not in source
    assert "print(config.client_secret" not in source
    assert "print(credentials.access_token" not in source
    # The only JSON serialization is allowlisted result data, never a provider body.
    assert "json.dumps(result" not in source


class DemoFakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class DemoFakeSession:
    """Deterministic PayPal HTTP double; no request can reach the network."""

    def __init__(self, merchant_id, outcome):
        self.merchant_id = merchant_id
        self.outcome = outcome
        self.calls = []
        self.create_payload = None
        self.order_id = None
        self.get_statuses = {
            "success": ["APPROVED", "COMPLETED", "COMPLETED"],
            "mismatch": ["APPROVED", "COMPLETED"],
            "UNKNOWN": ["APPROVED"],
            "capture_timeout": ["APPROVED"],
            "manual_mismatch": [],
        }[outcome].copy()

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if url == "https://api-m.sandbox.paypal.com/v1/oauth2/token":
            return DemoFakeResponse(200, {"access_token": "fake-oauth-token", "expires_in": 3600})
        if url == "https://api-m.sandbox.paypal.com/v2/checkout/orders":
            self.create_payload = kwargs["json"]
            unit = self.create_payload["purchase_units"][0]
            assert unit["reference_id"]
            assert unit["amount"] == {"currency_code": "USD", "value": "5.00"}
            assert unit["payee"] == {"merchant_id": self.merchant_id}
            self.order_id = "SANDBOX-ORDER-1"
            return DemoFakeResponse(
                201,
                {
                    "id": self.order_id,
                    "status": "CREATED",
                    "purchase_units": [unit],
                    "links": [
                        {
                            "rel": "approve",
                            "href": f"https://www.sandbox.paypal.com/checkoutnow?token={self.order_id}",
                        }
                    ],
                },
            )
        if url == f"https://api-m.sandbox.paypal.com/v2/checkout/orders/{self.order_id}/capture":
            assert kwargs["json"] == {}
            if self.outcome == "capture_timeout":
                raise requests.Timeout("capture timed out after dispatch")
            status = "COMPLETED" if self.outcome in {"success", "mismatch"} else "PENDING"
            return DemoFakeResponse(201, {"id": self.order_id, "status": status})
        raise AssertionError(f"unexpected POST: {url}")

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        assert self.order_id is not None
        assert url == f"https://api-m.sandbox.paypal.com/v2/checkout/orders/{self.order_id}"
        assert self.get_statuses, "unexpected extra PayPal GET"
        status = self.get_statuses.pop(0)
        unit = dict(self.create_payload["purchase_units"][0])
        if status == "COMPLETED":
            assert unit["payee"] == {"merchant_id": self.merchant_id}
            amount = "4.99" if self.outcome == "mismatch" else "5.00"
            unit["payments"] = {
                "captures": [
                    {
                        "id": "SANDBOX-CAPTURE-1",
                        "status": "COMPLETED",
                        "amount": {"currency_code": "USD", "value": amount},
                    }
                ]
            }
        return DemoFakeResponse(
            200,
            {"id": self.order_id, "status": status, "purchase_units": [unit]},
        )


class FakeSocketServer:
    """Unsignalled local server double; the runner only needs its port and cleanup hooks."""

    server_port = 43127

    def serve_forever(self):
        return None

    def shutdown(self):
        return None

    def server_close(self):
        return None


def run_fake_demo(monkeypatch, tmp_path, *, outcome, inputs):
    values = valid_environment(tmp_path)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SKYFIRE_SELLER_SERVICE_ID", raising=False)

    session = DemoFakeSession(values["TRUSTGUARD_PAYPAL_MERCHANT_ID"], outcome)
    monkeypatch.setattr(demo, "_callback_server", lambda _state: FakeSocketServer())
    monkeypatch.setattr("paypal_rest.requests.Session", lambda: session)

    supplied = iter(inputs)
    prompts = []

    def input_fn(prompt):
        prompts.append(prompt)
        return next(supplied)

    output = []
    errors = []
    return_code = demo.run_demo(
        input_fn=input_fn,
        output_fn=output.append,
        error_fn=errors.append,
    )
    return return_code, output, errors, session, prompts


@pytest.mark.parametrize("outcome", ["success", "mismatch", "UNKNOWN", "capture_timeout"])
def test_run_demo_parameterized_outcomes_use_order_id_then_approve_and_no_callback_signal(
    monkeypatch, tmp_path, outcome,
):
    return_code, output, errors, session, prompts = run_fake_demo(
        monkeypatch,
        tmp_path,
        outcome=outcome,
        inputs=["SANDBOX-ORDER-1", "APPROVE"],
    )

    assert errors == []
    json_outputs = [json.loads(line) for line in output if line.startswith("{")]
    assert json_outputs[0]["status"] == "CREATED"
    assert json_outputs[0]["provider_order_id"] == "SANDBOX-ORDER-1"
    assert json_outputs[0]["approval_url"] == (
        "https://www.sandbox.paypal.com/checkoutnow?token=SANDBOX-ORDER-1"
    )
    assert any("returned order ID" in line for line in output)
    assert [prompt.split(":", 1)[0] for prompt in prompts] == [
        "Returned PayPal order ID (not a URL or JWT)",
        "Type APPROVE to capture",
    ]

    capture_posts = [call for call in session.calls if call[0] == "POST" and call[1].endswith("/SANDBOX-ORDER-1/capture")]
    create_posts = [call for call in session.calls if call[0] == "POST" and call[1].endswith("/v2/checkout/orders")]
    assert len(create_posts) == 1
    assert len(capture_posts) == 1
    assert capture_posts[0][2]["json"] == {}
    assert not session.get_statuses

    if outcome == "success":
        assert return_code == 0
        assert [item["status"] for item in json_outputs] == ["CREATED", "COMPLETED", "COMPLETED"]
        assert all(item["payment_completed"] is True for item in json_outputs[1:])
        assert all(item["capture_ids"] == ["SANDBOX-CAPTURE-1"] for item in json_outputs[1:])
        assert sum(call[0] == "GET" for call in session.calls) == 3
        assert sum(call[0] == "POST" for call in session.calls) == 3
    else:
        assert return_code == 3
        assert json_outputs[-1]["status"] == "UNKNOWN"
        assert json_outputs[-1]["payment_completed"] is False
        assert sum(call[0] == "POST" for call in session.calls) == 3
        if outcome in {"UNKNOWN", "capture_timeout"}:
            assert sum(call[0] == "GET" for call in session.calls) == 1
        else:
            assert sum(call[0] == "GET" for call in session.calls) == 2
        assert any("No retry was attempted" in line for line in output)


def test_manual_order_mismatch_stops_before_get_or_capture(monkeypatch, tmp_path):
    return_code, output, errors, session, prompts = run_fake_demo(
        monkeypatch,
        tmp_path,
        outcome="manual_mismatch",
        inputs=["WRONG-ORDER-ID", "APPROVE"],
    )

    assert return_code == 3
    assert errors == []
    assert [prompt.split(":", 1)[0] for prompt in prompts] == [
        "Returned PayPal order ID (not a URL or JWT)",
    ]
    assert any("manual order identity does not match" in line for line in output)
    assert [call[0] for call in session.calls] == ["POST", "POST"]
    assert not any(call[0] == "GET" for call in session.calls)
    assert not any(call[1].endswith("/capture") for call in session.calls)


def test_production_paypal_mapping_rejects_synthetic_official_service_without_local_env(monkeypatch):
    monkeypatch.setenv("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "true")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "fake-client-id")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "fake-client-secret")
    monkeypatch.setenv("TRUSTGUARD_PAYPAL_MERCHANT_ID", PAYPAL_MERCHANT_ID)
    monkeypatch.setenv("SKYFIRE_SELLER_SERVICE_ID", PAYPAL_SYNTHETIC_SERVICE_ID)
    monkeypatch.setenv("TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID", PAYPAL_SYNTHETIC_SERVICE_ID)
    monkeypatch.delenv("TRUSTGUARD_LOCAL_TEST_SERVICE_ID", raising=False)
    monkeypatch.delenv("TRUSTGUARD_LOCAL_SANDBOX_DEMO", raising=False)

    signing_key = ec.generate_private_key(ec.SECP256R1())
    trust_config = TrustConfig.from_values(
        issuer="https://issuer.example",
        audience="trustguard-test",
        trusted_keys={"test-key": signing_key.public_key()},
        grant_id_field="gid",
        grant_limit_field="limit",
        grant_currency_field="currency",
        grant_payees_field="payees",
        jwt_algorithms=("ES256",),
    )
    transaction = CanonicalTransaction.build(
        transaction_id="synthetic-paypal-tx",
        idempotency_key="synthetic-paypal-idem",
        amount="5.00",
        currency="USD",
        skyfire_service_id=PAYPAL_SYNTHETIC_SERVICE_ID,
        paypal_merchant_id=PAYPAL_MERCHANT_ID,
    )
    session = DemoFakeSession(PAYPAL_MERCHANT_ID, "manual_mismatch")
    provider = PayPalRestOrdersProvider(trust_config, session=session)

    with pytest.raises(ConfigurationError, match="synthetic service identity"):
        provider.create_order(transaction)
    assert session.calls == []


@pytest.mark.parametrize("local_flag", [None, "false", "true"])
def test_skyfire_settings_reject_reserved_paypal_synthetic_id_regardless_of_local_flag(
    monkeypatch, tmp_path, local_flag,
):
    if local_flag is None:
        monkeypatch.delenv("TRUSTGUARD_LOCAL_SANDBOX_DEMO", raising=False)
    else:
        monkeypatch.setenv("TRUSTGUARD_LOCAL_SANDBOX_DEMO", local_flag)

    with pytest.raises(SkyfireTokenError, match="synthetic service identities"):
        SkyfireSettings(
            DOCUMENTED_SANDBOX_ISSUER,
            DOCUMENTED_SANDBOX_JWKS_URL,
            "sandbox",
            "operator-seller-account",
            PAYPAL_SYNTHETIC_SERVICE_ID,
            str(tmp_path / "official.sqlite3"),
        )


def test_official_verifier_rejects_localhost_generated_token_with_fake_jwks_no_network(monkeypatch, tmp_path):
    monkeypatch.setenv("TRUSTGUARD_LOCAL_SANDBOX_DEMO", "true")
    local_credentials = demo.generate_local_credentials(
        callback_port=43127,
        merchant_id=PAYPAL_MERCHANT_ID,
        seller_service_id=LOCAL_DEMO_SERVICE_ID,
    )
    local_public_key = local_credentials.trust_config.trusted_keys[demo.LOCAL_ACCESS_KID]
    local_jwk = jwt.algorithms.ECAlgorithm.to_jwk(local_public_key, as_dict=True)
    local_jwk.update({"kid": demo.LOCAL_ACCESS_KID, "alg": "ES256", "use": "sig"})
    fetches = []
    verifier = SkyfireTokenVerifier(
        SkyfireSettings(
            DOCUMENTED_SANDBOX_ISSUER,
            DOCUMENTED_SANDBOX_JWKS_URL,
            "sandbox",
            "operator-seller-account",
            "operator-supplied-skyfire-service",
            str(tmp_path / "official.sqlite3"),
        ),
        jwks_fetcher=lambda: (fetches.append(1) or {"keys": [local_jwk]}),
    )

    with pytest.raises(SkyfireTokenError):
        verifier.verify(local_credentials.access_token)
    assert fetches == [1]


@pytest.mark.parametrize(
    "approval_url",
    [
        "https://www.paypal.com/checkoutnow?token=SANDBOX-ORDER-1",
        "https://api-m.sandbox.paypal.com/v2/checkout/orders/SANDBOX-ORDER-1",
        "https://www.sandbox.paypal.com.evil.example/checkoutnow?token=SANDBOX-ORDER-1",
    ],
)
def test_public_result_rejects_production_and_arbitrary_paypal_urls(approval_url):
    assert demo._public_result(
        {"status": "CREATED", "provider_order_id": "SANDBOX-ORDER-1", "approval_url": approval_url}
    ) == {"status": "CREATED", "provider_order_id": "SANDBOX-ORDER-1"}
