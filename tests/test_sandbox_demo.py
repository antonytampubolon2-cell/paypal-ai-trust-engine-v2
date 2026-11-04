import json
import os
from pathlib import Path

import jwt
import pytest

from scripts import run_paypal_sandbox_demo as demo


ROOT = Path(__file__).resolve().parents[1]


def valid_environment(tmp_path):
    return {
        "TRUSTGUARD_LOCAL_SANDBOX_DEMO": "true",
        "TRUSTGUARD_ENABLE_PAYPAL_SANDBOX": "true",
        "PAYPAL_CLIENT_ID": "fake-client-id-for-local-test",
        "PAYPAL_CLIENT_SECRET": "fake-secret-for-local-test",
        "SKYFIRE_SELLER_SERVICE_ID": "operator-supplied-skyfire-service",
        "TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID": "operator-supplied-skyfire-service",
        "TRUSTGUARD_PAYPAL_MERCHANT_ID": "distinct-paypal-merchant",
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


def test_validate_config_requires_operator_mapping_and_distinct_namespaces(tmp_path):
    values = valid_environment(tmp_path)
    values["TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID"] = "invented-different-source"
    with pytest.raises(ValueError, match="exactly equal"):
        demo.validate_config(values)

    values = valid_environment(tmp_path)
    values["TRUSTGUARD_PAYPAL_MERCHANT_ID"] = values["SKYFIRE_SELLER_SERVICE_ID"]
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
    monkeypatch.setattr("requests.sessions.Session.request", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("HTTP must not run")))

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


def test_run_demo_completes_with_real_guard_and_paypal_provider_fake_session(monkeypatch, tmp_path):
    values = valid_environment(tmp_path)
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    class FakeResponse:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload

        def json(self):
            return self._payload

    class FakeSession:
        """Deterministic PayPal HTTP double; no request can reach the network."""

        def __init__(self):
            self.calls = []
            self.create_payload = None
            self.order_id = None
            self.get_statuses = ["APPROVED", "COMPLETED", "COMPLETED"]

        def post(self, url, **kwargs):
            self.calls.append(("POST", url, kwargs))
            if url == "https://api-m.sandbox.paypal.com/v1/oauth2/token":
                return FakeResponse(200, {"access_token": "fake-oauth-token", "expires_in": 3600})
            if url == "https://api-m.sandbox.paypal.com/v2/checkout/orders":
                self.create_payload = kwargs["json"]
                unit = self.create_payload["purchase_units"][0]
                assert unit["reference_id"]
                assert unit["amount"] == {"currency_code": "USD", "value": "5.00"}
                assert unit["payee"] == {"merchant_id": values["TRUSTGUARD_PAYPAL_MERCHANT_ID"]}
                self.order_id = "SANDBOX-ORDER-1"
                return FakeResponse(
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
                return FakeResponse(201, {"id": self.order_id, "status": "COMPLETED"})
            raise AssertionError(f"unexpected POST: {url}")

        def get(self, url, **kwargs):
            self.calls.append(("GET", url, kwargs))
            assert self.order_id is not None
            assert url == f"https://api-m.sandbox.paypal.com/v2/checkout/orders/{self.order_id}"
            assert self.get_statuses, "unexpected extra PayPal GET"
            status = self.get_statuses.pop(0)
            unit = dict(self.create_payload["purchase_units"][0])
            if status == "COMPLETED":
                assert unit["payee"] == {"merchant_id": values["TRUSTGUARD_PAYPAL_MERCHANT_ID"]}
                unit["payments"] = {
                    "captures": [
                        {
                            "id": "SANDBOX-CAPTURE-1",
                            "status": "COMPLETED",
                            "amount": {"currency_code": "USD", "value": "5.00"},
                        }
                    ]
                }
            return FakeResponse(
                200,
                {"id": self.order_id, "status": status, "purchase_units": [unit]},
            )

    class FakeCallbackServer:
        """Callback server double with a port but no socket or listener."""

        server_port = 43127

        def serve_forever(self):
            return None

        def shutdown(self):
            return None

        def server_close(self):
            return None

    class SignallingCallbackState(demo.CallbackState):
        def set_expected_order(self, order_id):
            super().set_expected_order(order_id)
            assert self.accept(self.path, {"token": [order_id], "PayerID": ["fake-payer"]})

    session = FakeSession()
    monkeypatch.setattr(demo, "CallbackState", SignallingCallbackState)
    monkeypatch.setattr(demo, "_callback_server", lambda state: FakeCallbackServer())
    monkeypatch.setattr("paypal_rest.requests.Session", lambda: session)

    output = []
    errors = []
    assert demo.run_demo(input_fn=lambda _prompt: "APPROVE", output_fn=output.append, error_fn=errors.append) == 0
    assert errors == []
    assert not session.get_statuses

    json_outputs = [json.loads(line) for line in output if line.startswith("{")]
    assert [item["status"] for item in json_outputs] == ["CREATED", "COMPLETED", "COMPLETED"]
    assert json_outputs[0]["approval_url"] == (
        "https://www.sandbox.paypal.com/checkoutnow?token=SANDBOX-ORDER-1"
    )
    assert all(item["payment_completed"] is True for item in json_outputs[1:])
    assert all(item["capture_ids"] == ["SANDBOX-CAPTURE-1"] for item in json_outputs[1:])
    assert any("COMPLETED" in line and "SANDBOX-CAPTURE-1" in line for line in output)

    create_posts = [
        call for call in session.calls
        if call[0] == "POST" and call[1] == "https://api-m.sandbox.paypal.com/v2/checkout/orders"
    ]
    capture_posts = [
        call for call in session.calls
        if call[0] == "POST" and call[1].endswith("/SANDBOX-ORDER-1/capture")
    ]
    assert len(create_posts) == 1
    assert len(capture_posts) == 1
    assert sum(call[0] == "GET" for call in session.calls) == 3
    assert sum(call[0] == "POST" for call in session.calls) == 3
    assert create_posts[0][2]["json"]["purchase_units"][0]["reference_id"]
    assert capture_posts[0][2]["json"] == {}


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
