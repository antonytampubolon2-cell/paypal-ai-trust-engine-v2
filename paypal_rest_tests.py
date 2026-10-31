"""Pure unit tests for the PayPal Orders v2 rest_items schema.

No network calls, issuer values, merchant IDs, tokens, or credentials are used.
"""
import unittest
from decimal import Decimal

from paypal_rest import RestItemValidationError, normalize_rest_items


class PayPalRestItemsTests(unittest.TestCase):
    def setUp(self):
        self.items = [{
            "name": "Test item",
            "quantity": "2",
            "unit_amount": {"currency_code": "USD", "value": "5.00"},
        }]

    def test_items_total_must_equal_approved_amount(self):
        normalized, total = normalize_rest_items(
            self.items, currency="USD", approved_amount=Decimal("10.00")
        )
        self.assertEqual(total, Decimal("10.00"))
        self.assertEqual(normalized[0]["unit_amount"]["value"], "5.00")
        self.assertEqual(normalized[0]["quantity"], "2")

    def test_mismatch_rejected(self):
        with self.assertRaises(RestItemValidationError):
            normalize_rest_items(
                self.items, currency="USD", approved_amount=Decimal("10.01")
            )

    def test_legacy_rest_items_fields_rejected(self):
        item = dict(self.items[0], item_cost="5.00", item_total="10.00")
        with self.assertRaises(RestItemValidationError):
            normalize_rest_items([item], currency="USD", approved_amount=Decimal("10.00"))

    def test_wrong_currency_rejected(self):
        item = {
            "name": "Test item", "quantity": "1",
            "unit_amount": {"currency_code": "EUR", "value": "5.00"},
        }
        with self.assertRaises(RestItemValidationError):
            normalize_rest_items([item], currency="USD", approved_amount=Decimal("5.00"))

    def test_invalid_precision_and_float_money_rejected(self):
        for value in ("1.239", 1.239):
            with self.subTest(value=value):
                item = {
                    "name": "Test item", "quantity": "1",
                    "unit_amount": {"currency_code": "USD", "value": value},
                }
                with self.assertRaises(RestItemValidationError):
                    normalize_rest_items([item], currency="USD", approved_amount=Decimal("1.23"))

    def test_zero_negative_and_non_integer_quantity_rejected(self):
        for quantity in ("0", "-1", "1.5", True):
            with self.subTest(quantity=quantity):
                item = {
                    "name": "Test item", "quantity": quantity,
                    "unit_amount": {"currency_code": "USD", "value": "5.00"},
                }
                with self.assertRaises(RestItemValidationError):
                    normalize_rest_items([item], currency="USD", approved_amount=Decimal("5.00"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
