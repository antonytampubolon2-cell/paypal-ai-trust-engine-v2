import json
import sqlite3
from collections import Counter, defaultdict
from decimal import Decimal

import pytest

from benchmark_v3_data import (
    ACTIVE_STATES,
    FEATURE_NAMES,
    FEATURE_VERSION,
    HOLDOUT_ONLY_SCENARIOS,
    SCENARIOS,
    features_from_history,
    generate_split,
    metadata,
    validate_features,
)
from trustguard import CanonicalTransaction, Ledger


EXPECTED_ROW_KEYS = {
    "id",
    "scenario",
    "description",
    "hidden_label",
    "features",
    "history",
    "latent_context",
}


def _money(minor: int) -> str:
    return f"{Decimal(minor) / Decimal(100):.2f}"


def _reserve_history(ledger: Ledger, history: dict) -> None:
    """Materialize only synthetic history rows, then set runtime state/time in SQLite."""
    for prior in history["prior_transactions"]:
        tx = CanonicalTransaction.build(
            transaction_id=prior["transaction_id"],
            idempotency_key=f"idem-{prior['transaction_id']}",
            amount=_money(prior["amount_minor"]),
            currency=prior["currency"],
            payee=prior["payee"] if prior["paypal_merchant_id"] is None and prior["skyfire_service_id"] is None else None,
            paypal_merchant_id=prior["paypal_merchant_id"],
            skyfire_service_id=prior["skyfire_service_id"],
            supported_currencies=("USD", "EUR"),
        )
        ledger.reserve(prior["grant_id"], tx, history["grantlimit_minor"], prior["currency"])
        with sqlite3.connect(ledger.path) as db:
            db.execute(
                "UPDATE transactions SET status=?, created_at=?, updated_at=? WHERE transaction_id=?",
                (prior["status"], prior["created_at"], prior["created_at"], prior["transaction_id"]),
            )


def _current_transaction(history: dict) -> CanonicalTransaction:
    return CanonicalTransaction.build(
        transaction_id=history["currenttxid"],
        idempotency_key=f"idem-{history['currenttxid']}",
        amount=_money(history["amount_minor"]),
        currency=history["currency"],
        payee=history["payee"],
    )


def test_constants_and_split_sizes_are_frozen():
    assert FEATURE_VERSION == "trustguard-canonical-ledger-v3-research"
    assert FEATURE_NAMES == (
        "amount_to_grant_ratio",
        "cumulative_spending_ratio",
        "recent_velocity_ratio",
        "new_payee",
    )
    assert set(SCENARIOS) == {
        "routine",
        "legitimate_high_utilization",
        "legitimate_high_velocity",
        "new_payee_benign",
        "abusive_high_utilization",
        "burst_abuse",
        "low_signal_anomaly",
        "interaction_mixed",
    }
    assert set(HOLDOUT_ONLY_SCENARIOS) == {
        "high_utilization_velocity_combo",
        "quiet_new_payee_combo",
    }
    assert len(generate_split("training")) == 8 * 64
    assert len(generate_split("validation")) == 8 * 48
    assert len(generate_split("holdout")) == 10 * 64


def test_generation_is_deterministic_and_has_exact_row_interface():
    first = generate_split("validation")
    second = generate_split("validation")
    assert first == second
    assert all(set(row) == EXPECTED_ROW_KEYS for row in first)
    assert all("label" not in row for row in first)
    assert Counter(row["scenario"] for row in first) == Counter({name: 48 for name in SCENARIOS})
    assert all(row["hidden_label"] in {0, 1} for row in first)
    assert all(row["features"] == features_from_history(row["history"]) for row in first)


def test_holdout_contains_only_two_unseen_scenario_names_in_addition_to_known_scenarios():
    validation_names = {row["scenario"] for row in generate_split("validation")}
    holdout_names = {row["scenario"] for row in generate_split("holdout")}
    assert validation_names == set(SCENARIOS)
    assert holdout_names == set(SCENARIOS) | set(HOLDOUT_ONLY_SCENARIOS)


def test_counterpart_scenarios_share_feature_histories_but_have_opposite_labels():
    rows = generate_split("validation")
    by_scenario = defaultdict(dict)
    for row in rows:
        by_scenario[row["scenario"]][json.dumps(row["features"], sort_keys=True)] = row

    for left, right in (
        ("legitimate_high_utilization", "abusive_high_utilization"),
        ("legitimate_high_velocity", "burst_abuse"),
    ):
        shared = set(by_scenario[left]) & set(by_scenario[right])
        assert shared, (left, right)
        paired = [
            (by_scenario[left][key], by_scenario[right][key])
            for key in shared
            if by_scenario[left][key]["hidden_label"] != by_scenario[right][key]["hidden_label"]
        ]
        assert paired
        a, b = paired[0]
        assert a["id"] != b["id"]
        assert a["history"]["currenttxid"] != b["history"]["currenttxid"]


def test_validate_features_rejects_unsupported_values_and_extra_schema():
    valid = {
        "amount_to_grant_ratio": 0.2,
        "cumulative_spending_ratio": 0.4,
        "recent_velocity_ratio": 0.6,
        "new_payee": 1.0,
    }
    assert validate_features(valid) is True
    bad_values = (
        {**valid, "recent_velocity_ratio": 0.1},
        {**valid, "new_payee": 0.5},
        {**valid, "amount_to_grant_ratio": -0.01},
        {**valid, "amount_to_grant_ratio": 0.8, "cumulative_spending_ratio": 0.7},
        {**valid, "cumulative_spending_ratio": float("nan")},
        {**valid, "new_payee": True},
    )
    for bad in bad_values:
        with pytest.raises(ValueError):
            validate_features(bad)
    with pytest.raises(ValueError):
        validate_features({**valid, "extra": 0.0})


def test_generated_histories_match_actual_ledger_risk_features(tmp_path):
    rows = generate_split("validation")
    sampled = [next(row for row in rows if row["scenario"] == scenario) for scenario in SCENARIOS]
    for index, row in enumerate(sampled):
        ledger = Ledger(tmp_path / f"parity-{index}.sqlite")
        history = row["history"]
        _reserve_history(ledger, history)
        actual = ledger.risk_features(
            history["grantid"],
            _current_transaction(history),
            history["grantlimit_minor"],
            now=history["now"],
        )
        assert actual == row["features"] == features_from_history(history)


def test_ledger_filter_edges_match_history_implementation(tmp_path):
    now = 10_000.0
    history = {
        "grantlimit_minor": 10_000,
        "amount_minor": 500,
        "now": now,
        "grantid": "synthetic-edge-grant",
        "currenttxid": "synthetic-edge-current",
        "currency": "USD",
        "payee": "synthetic-paypal-match",
        "prior_transactions": [],
    }

    def prior(txid, *, grant="synthetic-edge-grant", currency="USD", amount=100, created=now, status="RESERVED", paypal=None, skyfire=None, payee="synthetic-other"):
        history["prior_transactions"].append({
            "transaction_id": txid,
            "grant_id": grant,
            "currency": currency,
            "paypal_merchant_id": paypal,
            "skyfire_service_id": skyfire,
            "payee": payee,
            "amount_minor": amount,
            "created_at": created,
            "status": status,
        })

    # Exactly five active, matching rows exercise the velocity cap; one is exactly
    # on the 600-second lower boundary and one future timestamp proves no upper bound.
    for i in range(5):
        prior(f"synthetic-edge-active-{i}", amount=100, created=now - (600 if i == 0 else -i), payee=f"synthetic-other-{i}")
    prior("synthetic-edge-paypal", amount=200, created=now - 20, paypal="synthetic-paypal-match", payee="legacy-not-used")
    prior("synthetic-edge-current", amount=8_800, created=now, paypal="synthetic-paypal-match", payee="legacy-not-used")
    prior("synthetic-edge-old", amount=100, created=now - 601, paypal="synthetic-paypal-match", payee="legacy-not-used")
    prior("synthetic-edge-inactive", amount=100, created=now, status="FAILED", paypal="synthetic-paypal-match", payee="legacy-not-used")
    prior("synthetic-edge-other-grant", amount=8_000, created=now, grant="other-grant", paypal="synthetic-paypal-match", payee="legacy-not-used")
    prior("synthetic-edge-other-currency", amount=8_000, created=now, currency="EUR", paypal="synthetic-paypal-match", payee="legacy-not-used")
    # PayPal wins over a matching Skyfire identity in COALESCE precedence.
    prior("synthetic-edge-coalesce", amount=300, created=now, paypal="synthetic-paypal-other", skyfire="synthetic-paypal-match", payee="legacy-not-used")

    expected = features_from_history(history)
    ledger = Ledger(tmp_path / "edge.sqlite")
    _reserve_history(ledger, history)

    # Materialize the current-id exclusion after prior reservation, without needing
    # a provider or a real TrustGuard configuration.
    actual = ledger.risk_features(
        history["grantid"],
        _current_transaction(history),
        history["grantlimit_minor"],
        now=now,
    )
    assert actual == expected
    assert actual["recent_velocity_ratio"] == 1.0
    assert actual["new_payee"] == 0.0
    assert actual["cumulative_spending_ratio"] == 0.16


def test_metadata_records_seeds_ranges_and_hidden_label_contract():
    data = metadata()
    assert data["feature_version"] == FEATURE_VERSION
    assert data["seeds"] == {
        "training": 20261110,
        "validation": 20261111,
        "holdout": 20261112,
        "diagnostic": 20261113,
    }
    assert data["active_states"] == list(ACTIVE_STATES)
    assert data["label_noise"]["label_field"] == "hidden_label"
    assert data["label_noise"]["interaction_labels_use_bernoulli_draw"] is True
    assert data["generator_assumptions"]["model_inputs_are_features_only"] is True


def test_invalid_split_is_rejected():
    with pytest.raises(ValueError):
        generate_split("evaluation")


@pytest.mark.parametrize("paypal, expected_new", [("", 1.0), (None, 0.0)])
def test_coalesce_empty_identity_matches_sql_not_python_truthiness(tmp_path, paypal, expected_new):
    history = {"grantlimit_minor": 10_000, "amount_minor": 500, "now": 10_000.0,
               "grantid": "synthetic-null-grant", "currenttxid": "synthetic-null-current",
               "currency": "USD", "payee": "synthetic-service-match",
               "prior_transactions": [{"transaction_id": "synthetic-null-prior",
                   "grant_id": "synthetic-null-grant", "currency": "USD", "paypal_merchant_id": paypal,
                   "skyfire_service_id": "synthetic-service-match", "payee": "synthetic-other",
                   "amount_minor": 100, "created_at": 9_999.0, "status": "RESERVED"}]}
    ledger = Ledger(tmp_path / "coalesce.sqlite")
    _reserve_history(ledger, history)
    actual = ledger.risk_features(history["grantid"], _current_transaction(history),
                                  history["grantlimit_minor"], now=history["now"])
    assert actual == features_from_history(history)
    assert actual["new_payee"] == expected_new


def test_diagnostics_are_separately_seeded_runtime_valid_histories():
    from benchmark_v3_data import generate_diagnostic_split
    rows = generate_diagnostic_split()
    assert rows == generate_diagnostic_split()
    validation = {json.dumps(row["features"], sort_keys=True) for row in generate_split("validation")}
    diagnostic = {json.dumps(row["features"], sort_keys=True) for row in rows}
    assert not (validation & diagnostic)
    assert all(row["features"] == features_from_history(row["history"]) for row in rows)
    assert set(HOLDOUT_ONLY_SCENARIOS).issubset({row["scenario"] for row in rows})
