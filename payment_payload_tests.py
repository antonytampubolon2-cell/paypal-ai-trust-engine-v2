"""Regression tests for the PayPal Orders v2 request built by execute_safe_payment.

All provider behavior is mocked. These tests never call PayPal or create an order.
"""
import unittest
from decimal import Decimal

from main import execute_safe_payment, normalize_toolkit_items
import main_public


class MockPayPalAPI:
    def __init__(self, response=None, error=None):
        self.calls = []
        self.response = response if response is not None else {"id": "SYNTHETIC-MOCK-ORDER"}
        self.error = error

    def run(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


class MockToolkit:
    def __init__(self, api):
        self.api = api
        self.calls = 0

    def get_paypal_api(self):
        self.calls += 1
        return self.api


class MockAgent:
    def __init__(self, api, allowed=True):
        self.toolkit = MockToolkit(api)
        self.allowed = allowed
        self.policy_calls = []

    def process_payment_request(self, *args):
        self.policy_calls.append(args)
        return self.allowed


class PayPalOrdersV2PayloadTests(unittest.TestCase):
    def setUp(self):
        self.items = [
            {"name": " Item A ", "quantity": 2, "item_cost": "5.00", "item_total": "10.00"},
            {"name": "Item B", "quantity": 1, "unit_price": "2.34"},
        ]

    def test_normalizer_emits_orders_v2_item_schema_with_decimal_strings(self):
        items = normalize_toolkit_items(self.items, "USD")
        self.assertEqual(items, [
            {"name": "Item A", "quantity": "2",
             "unit_amount": {"currency_code": "USD", "value": "5.00"}},
            {"name": "Item B", "quantity": "1",
             "unit_amount": {"currency_code": "USD", "value": "2.34"}},
        ])
        self.assertEqual(
            sum(Decimal(item["unit_amount"]["value"]) * int(item["quantity"]) for item in items),
            Decimal("12.34"),
        )

    def test_execute_safe_payment_builds_complete_orders_v2_amount_and_breakdown(self):
        api = MockPayPalAPI()
        agent = MockAgent(api)
        result = execute_safe_payment(agent, "synthetic-token", "synthetic-proof", "POST",
                                      "https://example.test/pay", "USD", self.items)
        self.assertEqual(result["status"], "ORDER_CREATED")
        self.assertEqual(len(api.calls), 1)
        call = api.calls[0]
        self.assertEqual(call["method"], "create_order")
        params = call["params"]
        self.assertEqual(params["intent"], "AUTHORIZE")
        self.assertEqual(len(params["purchase_units"]), 1)
        unit = params["purchase_units"][0]
        self.assertEqual(unit["amount"], {
            "currency_code": "USD",
            "value": "12.34",
            "breakdown": {"item_total": {"currency_code": "USD", "value": "12.34"}},
        })
        self.assertEqual(unit["items"], normalize_toolkit_items(self.items, "USD"))
        self.assertEqual(
            sum(Decimal(item["unit_amount"]["value"]) * int(item["quantity"]) for item in unit["items"]),
            Decimal(unit["amount"]["value"]),
        )
        self.assertNotIn("item_cost", str(params))
        self.assertNotIn("item_total", unit["items"][0])
        self.assertNotIn("capture", call["method"].lower())

    def test_invalid_item_total_blocks_before_adapter_access(self):
        api = MockPayPalAPI()
        agent = MockAgent(api)
        invalid = [{"name": "Item", "quantity": 2, "item_cost": "5.00", "item_total": "9.99"}]
        result = execute_safe_payment(agent, "synthetic-token", "synthetic-proof", "POST",
                                      "https://example.test/pay", "USD", invalid)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(agent.toolkit.calls, 0)
        self.assertEqual(api.calls, [])

    def test_policy_denial_never_calls_paypal(self):
        api = MockPayPalAPI()
        agent = MockAgent(api, allowed=False)
        result = execute_safe_payment(agent, "synthetic-token", "synthetic-proof", "POST",
                                      "https://example.test/pay", "USD", self.items)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(agent.toolkit.calls, 0)
        self.assertEqual(api.calls, [])

    def test_ambiguous_provider_exception_returns_unknown_not_error(self):
        api = MockPayPalAPI(error=TimeoutError("synthetic ambiguous timeout"))
        agent = MockAgent(api)
        result = execute_safe_payment(agent, "synthetic-token", "synthetic-proof", "POST",
                                      "https://example.test/pay", "USD", self.items)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertNotIn("order_id", result)
        self.assertEqual(len(api.calls), 1)

    def test_response_without_order_id_returns_unknown(self):
        api = MockPayPalAPI(response={"status": "CREATED"})
        agent = MockAgent(api)
        result = execute_safe_payment(agent, "synthetic-token", "synthetic-proof", "POST",
                                      "https://example.test/pay", "USD", self.items)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertNotIn("order_id", result)
        self.assertEqual(len(api.calls), 1)

    def test_legacy_public_dispatch_is_disabled_even_for_synthetic_success(self):
        class NeverCallToolkit:
            def get_paypal_api(self):
                raise AssertionError("legacy branch must not call PayPal")
        class Agent:
            toolkit = NeverCallToolkit()
            def process_payment_request(self, *args):
                return True
        result = main_public.execute_safe_payment(
            Agent(), {"valid": True}, {"valid": True}, "POST",
            "https://example.test/pay", "USD", self.items
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("Legacy mock verification disabled", result["reason"])

    def test_legacy_public_entrypoint_has_no_credential_override_or_capture_enablement(self):
        from pathlib import Path
        source = (Path(__file__).resolve().parent / "main_public.py").read_text(encoding="utf-8")
        self.assertNotIn('os.environ["PAYPAL_CLIENT_ID"] =', source)
        self.assertNotIn('os.environ["PAYPAL_CLIENT_SECRET"] =', source)
        self.assertNotIn('"capture": True', source)
        self.assertNotIn("PayPalToolkit(", source)

    def test_main_toolkit_initialization_is_lazy_and_confirmation_gated(self):
        from pathlib import Path
        source = (Path(__file__).resolve().parent / "main.py").read_text(encoding="utf-8")
        self.assertIn("def initialize_paypal_toolkit()", source)
        self.assertIn('"capture": False', source)
        self.assertLess(source.index("TRUSTGUARD_CONFIRM_SANDBOX_ORDER"),
                        source.index("toolkit = initialize_paypal_toolkit()"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
