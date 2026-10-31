"""Strict PayPal Orders v2 line-item validation using Decimal.

This module builds only request data. It performs no network I/O, does not
create orders, and does not infer or synthesize merchant identity.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from trustguard_security import SUPPORTED_CURRENCY_MINOR_UNITS


class RestItemValidationError(ValueError):
    """Raised when line items cannot be bound exactly to the approved amount."""


def normalize_rest_items(
    rest_items: list[Mapping[str, Any]],
    *,
    currency: str,
    approved_amount: Decimal,
) -> tuple[list[dict[str, Any]], Decimal]:
    """Validate PayPal Orders v2 items and require their total to equal approval.

    Accepted input keys: name, quantity, unit_amount, plus optional description,
    sku, and category. Legacy fields such as item_cost/item_total are rejected.
    No floats are accepted for money.
    """
    if not isinstance(rest_items, list) or not rest_items:
        raise RestItemValidationError("rest_items must be a non-empty list.")
    if currency not in SUPPORTED_CURRENCY_MINOR_UNITS:
        raise RestItemValidationError("Unsupported currency.")
    if not isinstance(approved_amount, Decimal) or not approved_amount.is_finite() or approved_amount <= 0:
        raise RestItemValidationError("Approved amount must be a positive finite Decimal.")

    minor_units = SUPPORTED_CURRENCY_MINOR_UNITS[currency]
    normalized: list[dict[str, Any]] = []
    total = Decimal("0")
    allowed_keys = {"name", "quantity", "unit_amount", "description", "sku", "category"}
    allowed_categories = {"DIGITAL_GOODS", "PHYSICAL_GOODS", "DONATION"}

    for index, item in enumerate(rest_items):
        if not isinstance(item, Mapping):
            raise RestItemValidationError(f"rest_items[{index}] must be an object.")
        if set(item) - allowed_keys:
            raise RestItemValidationError(f"rest_items[{index}] contains unsupported fields.")
        name = item.get("name")
        quantity = item.get("quantity")
        unit = item.get("unit_amount")
        if not isinstance(name, str) or not name.strip() or len(name) > 127:
            raise RestItemValidationError(f"rest_items[{index}].name is invalid.")
        if isinstance(quantity, bool) or not (
            isinstance(quantity, int) and quantity > 0
            or isinstance(quantity, str) and re.fullmatch(r"[1-9][0-9]*", quantity)
        ):
            raise RestItemValidationError(f"rest_items[{index}].quantity must be a positive integer.")
        quantity_int = int(quantity)
        if not isinstance(unit, Mapping) or set(unit) != {"currency_code", "value"}:
            raise RestItemValidationError(f"rest_items[{index}].unit_amount has an invalid schema.")
        if unit.get("currency_code") != currency:
            raise RestItemValidationError(f"rest_items[{index}] currency does not match the approved currency.")
        raw_value = unit.get("value")
        if not isinstance(raw_value, (str, int)) or isinstance(raw_value, bool):
            raise RestItemValidationError(f"rest_items[{index}].unit_amount.value must be a decimal string or integer.")
        try:
            unit_amount = Decimal(str(raw_value))
        except (InvalidOperation, ValueError):
            raise RestItemValidationError(f"rest_items[{index}].unit_amount.value is malformed.") from None
        if not unit_amount.is_finite() or unit_amount <= 0 or unit_amount.as_tuple().exponent < -minor_units:
            raise RestItemValidationError(f"rest_items[{index}].unit_amount.value is invalid for {currency}.")
        unit_amount = unit_amount.quantize(Decimal(1).scaleb(-minor_units))
        total += unit_amount * quantity_int

        entry: dict[str, Any] = {
            "name": name.strip(),
            "quantity": str(quantity_int),
            "unit_amount": {
                "currency_code": currency,
                "value": format(unit_amount, f".{minor_units}f"),
            },
        }
        description = item.get("description")
        if description is not None:
            if not isinstance(description, str) or len(description) > 2048:
                raise RestItemValidationError(f"rest_items[{index}].description is invalid.")
            entry["description"] = description
        sku = item.get("sku")
        if sku is not None:
            if not isinstance(sku, str) or not sku or len(sku) > 127:
                raise RestItemValidationError(f"rest_items[{index}].sku is invalid.")
            entry["sku"] = sku
        category = item.get("category")
        if category is not None:
            if not isinstance(category, str) or category not in allowed_categories:
                raise RestItemValidationError(f"rest_items[{index}].category is invalid.")
            entry["category"] = category
        normalized.append(entry)

    if total != approved_amount:
        raise RestItemValidationError("Line-item total does not equal the approved amount.")
    return normalized, total
