from __future__ import annotations

import copy
import json

import numpy as np
import pytest

import risk_candidate_v3 as candidate


def features(
    amount: float = 0.10,
    cumulative: float = 0.20,
    velocity: float = 0.0,
    new_payee: float = 0.0,
) -> dict[str, float]:
    return {
        "amount_to_grant_ratio": amount,
        "cumulative_spending_ratio": cumulative,
        "recent_velocity_ratio": velocity,
        "new_payee": new_payee,
    }


def training_rows() -> list[dict[str, float]]:
    rows = []
    velocities = (0.0, 0.2, 0.4, 0.6, 0.8, 1.0)
    for index in range(24):
        amount = 0.04 + (index % 6) * 0.025
        cumulative = amount + 0.06 + (index % 4) * 0.04
        rows.append(
            features(
                amount=amount,
                cumulative=min(cumulative, 0.98),
                velocity=velocities[index % len(velocities)],
                new_payee=float(index % 2),
            )
        )
    return rows


def test_constructor_does_not_fit_or_load_legacy_data():
    model = candidate.ResearchIsolationForestV3()
    assert model.fitted is False
    with pytest.raises(RuntimeError):
        model.score(features(), feature_version=candidate.FEATURE_VERSION)


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        {**features(), "hidden_label": 0},
        {key: value for key, value in features().items() if key != "new_payee"},
        {**features(), "amount_to_grant_ratio": True},
        {**features(), "amount_to_grant_ratio": np.nan},
        {**features(), "amount_to_grant_ratio": 0.0},
        {**features(), "amount_to_grant_ratio": 1.01},
        {**features(amount=0.30), "cumulative_spending_ratio": 0.20},
        {**features(), "recent_velocity_ratio": 0.1},
        {**features(), "new_payee": 0.5},
    ],
)
def test_canonical_feature_validation_is_strict(bad):
    with pytest.raises(ValueError):
        candidate.validate_features(bad)


def test_fit_requires_exact_feature_version_and_nonempty_explicit_data():
    model = candidate.ResearchIsolationForestV3()
    with pytest.raises(ValueError):
        model.fit(training_rows(), feature_version="trustguard-canonical-ledger-v2")
    with pytest.raises(ValueError):
        model.fit([], feature_version=candidate.FEATURE_VERSION)
    with pytest.raises(ValueError):
        model.fit(None, feature_version=candidate.FEATURE_VERSION)
    with pytest.raises(ValueError):
        model.fit([{**training_rows()[0], "scenario": "routine"}], feature_version=candidate.FEATURE_VERSION)


def test_fit_accepts_raw_matrix_but_rejects_bad_matrix_values():
    rows = training_rows()
    matrix = np.asarray(
        [[row[name] for name in candidate.FEATURE_NAMES] for row in rows], dtype=np.float64
    )
    model = candidate.ResearchIsolationForestV3()
    assert model.fit(matrix, feature_version=candidate.FEATURE_VERSION) is model
    bad = matrix.copy()
    bad[0, 2] = 0.1
    with pytest.raises(ValueError):
        candidate.ResearchIsolationForestV3().fit(bad, feature_version=candidate.FEATURE_VERSION)
    mixed_boolean = matrix.tolist()
    mixed_boolean[0][3] = True
    with pytest.raises(ValueError):
        candidate.ResearchIsolationForestV3().fit(
            mixed_boolean, feature_version=candidate.FEATURE_VERSION
        )


def test_fixed_estimator_argument_rejects_non_integer_or_non_128_values():
    with pytest.raises(ValueError):
        candidate.ResearchIsolationForestV3(n_estimators=128.0)
    with pytest.raises(ValueError):
        candidate.ResearchIsolationForestV3(n_estimators=64)


def test_fit_passes_only_x_and_fixed_forest_configuration(monkeypatch):
    calls = []
    original_fit = candidate.IsolationForest.fit

    def capture_fit(estimator, x, *args, **kwargs):
        calls.append((np.asarray(x).copy(), args, kwargs))
        return original_fit(estimator, x, *args, **kwargs)

    monkeypatch.setattr(candidate.IsolationForest, "fit", capture_fit)
    model = candidate.ResearchIsolationForestV3(representation="raw")
    model.fit(training_rows(), feature_version=candidate.FEATURE_VERSION)
    assert len(calls) == 1
    assert calls[0][0].shape == (24, 4)
    assert calls[0][1:] == ((), {})
    assert model.forest is not None
    assert model.forest.n_estimators == 128
    assert model.forest.max_samples == 24
    assert model.forest.contamination == 0.04
    assert model.forest.n_jobs == 1
    assert model.forest.random_state == 31001


def test_raw_and_interaction_models_are_deterministic_and_vectorized():
    rows = training_rows()
    first = candidate.ResearchIsolationForestV3("raw").fit(
        rows, feature_version=candidate.FEATURE_VERSION
    )
    second = candidate.ResearchIsolationForestV3("raw").fit(
        rows, feature_version=candidate.FEATURE_VERSION
    )
    probes = [features(), features(0.8, 0.9, 1.0, 1.0), features(0.01, 0.01, 0.2, 0.0)]
    assert first.metadata() == second.metadata()
    assert np.array_equal(first.score_many(probes, feature_version=candidate.FEATURE_VERSION), second.score_many(probes, feature_version=candidate.FEATURE_VERSION))
    assert all(0.0 <= first.score(row, feature_version=candidate.FEATURE_VERSION) <= 1.0 for row in probes)
    assert first.score_many(probes, feature_version=candidate.FEATURE_VERSION).shape == (3,)

    interactions = candidate.ResearchIsolationForestV3("interactions").fit(
        rows, feature_version=candidate.FEATURE_VERSION
    )
    assert interactions.forest is not None
    assert interactions.forest.random_state == 31002
    assert len(interactions.metadata()["feature_names"]) == 7


def test_metadata_is_json_safe_and_incompatible_versions_are_rejected():
    model = candidate.ResearchIsolationForestV3().fit(
        training_rows(), feature_version=candidate.FEATURE_VERSION
    )
    metadata = model.metadata()
    assert metadata["feature_version"] == candidate.FEATURE_VERSION
    assert metadata["model_version"] == candidate.MODEL_VERSION
    assert metadata["training_matrix_sha256"]
    assert metadata["forest_state_fingerprint"]
    assert candidate.validate_metadata(metadata) is True
    assert candidate.ResearchIsolationForestV3.validate_feature_metadata(metadata) is True
    json.dumps(metadata, allow_nan=False, sort_keys=True)

    for key, value in (
        ("feature_version", "trusted-risk-features-v1"),
        ("model_version", "trustguard-isolation-forest-synthetic-v2-candidate"),
        ("representation", "trusted-upper-tail-v2"),
    ):
        invalid = copy.deepcopy(metadata)
        invalid[key] = value
        with pytest.raises(ValueError):
            candidate.validate_metadata(invalid)


def test_ood_flags_legal_outside_training_range_but_rejects_malformed_values():
    model = candidate.ResearchIsolationForestV3().fit(
        training_rows(), feature_version=candidate.FEATURE_VERSION
    )
    flags = model.ood_features(
        features(amount=0.99, cumulative=0.99, velocity=1.0, new_payee=1.0),
        feature_version=candidate.FEATURE_VERSION,
    )
    assert set(flags) == set(candidate.FEATURE_NAMES)
    assert flags["amount_to_grant_ratio"] is True
    assert flags["cumulative_spending_ratio"] is True
    assert flags["recent_velocity_ratio"] is False or isinstance(flags["recent_velocity_ratio"], bool)
    with pytest.raises(ValueError):
        model.ood_features(features(velocity=0.1), feature_version=candidate.FEATURE_VERSION)


def test_refit_with_different_matrix_is_rejected_and_original_state_is_immutable():
    rows = training_rows()
    model = candidate.ResearchIsolationForestV3().fit(
        rows, feature_version=candidate.FEATURE_VERSION
    )
    before = model.metadata()
    rows[0]["amount_to_grant_ratio"] = 0.09
    assert model.metadata() == before
    with pytest.raises(RuntimeError):
        model.fit(rows, feature_version=candidate.FEATURE_VERSION)
