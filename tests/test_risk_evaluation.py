from __future__ import annotations

import copy
import hashlib
import json
import math
from collections.abc import Mapping

import pytest
from sklearn.metrics import average_precision_score, roc_auc_score

from risk_scoring import ANOMALY_THRESHOLD, FEATURE_NAMES, MODEL_VERSION, TRAINING_DATASET_ID

import risk_evaluation


SCENARIO_LABELS = {
    "routine_known_payee": 0,
    "routine_new_payee": 0,
    "high_grant_utilization": 1,
    "elevated_transaction_velocity": 1,
    "new_payee_high_utilization": 1,
    "combined_extreme": 1,
}
FIXED_TIMESTAMP = "2026-11-04T17:10:47+00:00"


def _feature_vector(value) -> tuple[float, ...]:
    """Return a stable tuple for either a row/vector representation."""
    if isinstance(value, Mapping):
        if "features" in value:
            value = value["features"]
        if isinstance(value, Mapping):
            return tuple(float(value[name]) for name in FEATURE_NAMES)
    if hasattr(value, "tolist"):
        value = value.tolist()
    return tuple(float(item) for item in value)


def _vector_hash(value) -> str:
    encoded = json.dumps(_feature_vector(value), separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _valid_row() -> dict:
    return {
        "id": "test-row",
        "scenario": "routine_known_payee",
        "label": 0,
        "features": {name: 0.1 for name in FEATURE_NAMES},
    }


def _scenario_counts(report: Mapping, split: str) -> Mapping:
    """Find the documented per-scenario count map without accepting totals."""
    sample_counts = report["sample_counts"]
    candidates = (
        sample_counts.get(split) if isinstance(sample_counts, Mapping) else None,
        sample_counts.get(f"{split}_by_scenario") if isinstance(sample_counts, Mapping) else None,
        report.get(f"{split}_sample_counts"),
        report.get(f"{split}_counts"),
    )
    for candidate in candidates:
        if isinstance(candidate, Mapping) and set(SCENARIO_LABELS).issubset(candidate):
            return candidate
    raise AssertionError(f"report has no per-scenario {split} counts: {report!r}")


def test_generated_splits_are_deterministic_well_shaped_and_cover_expected_scenarios():
    validation = risk_evaluation.generate_dataset(split="validation")
    evaluation = risk_evaluation.generate_dataset(split="evaluation")
    validation_again = risk_evaluation.generate_dataset(split="validation")
    evaluation_again = risk_evaluation.generate_dataset(split="evaluation")

    assert validation == validation_again
    assert evaluation == evaluation_again
    assert validation
    assert evaluation
    assert validation != evaluation

    for rows in (validation, evaluation):
        assert isinstance(rows, list)
        assert set(row["scenario"] for row in rows) == set(SCENARIO_LABELS)
        assert set(row["label"] for row in rows) == {0, 1}
        for row in rows:
            assert set(row) == {"id", "scenario", "label", "features"}
            assert isinstance(row["id"], str) and row["id"]
            assert row["label"] == SCENARIO_LABELS[row["scenario"]]
            assert set(row["features"]) == set(FEATURE_NAMES)
            assert all(
                isinstance(row["features"][name], float)
                and not isinstance(row["features"][name], bool)
                and math.isfinite(row["features"][name])
                and 0.0 <= row["features"][name] <= 1.0
                for name in FEATURE_NAMES
            )
        risk_evaluation.validate_data(rows)


def test_training_validation_and_evaluation_feature_vectors_are_disjoint():
    training = risk_evaluation.training_reference_vectors()
    validation = risk_evaluation.generate_dataset(split="validation")
    evaluation = risk_evaluation.generate_dataset(split="evaluation")

    training_hashes = {_vector_hash(vector) for vector in training}
    validation_hashes = {_vector_hash(row) for row in validation}
    evaluation_hashes = {_vector_hash(row) for row in evaluation}

    assert training_hashes
    assert validation_hashes
    assert evaluation_hashes
    assert training_hashes.isdisjoint(validation_hashes)
    assert training_hashes.isdisjoint(evaluation_hashes)
    assert validation_hashes.isdisjoint(evaluation_hashes)
    risk_evaluation.validate_dataset_separation(training, validation, evaluation)


def test_scorer_fit_uses_exact_training_reference_vectors(monkeypatch):
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from risk_scoring import SyntheticIsolationForestScorer

    reference = risk_evaluation.training_reference_vectors()
    expected = np.asarray([_feature_vector(vector) for vector in reference], dtype="float64")
    original_fit = IsolationForest.fit
    captured = {}

    def capture_fit(model, features, *args, **kwargs):
        captured["features"] = np.asarray(features).copy()
        return original_fit(model, features, *args, **kwargs)

    monkeypatch.setattr(IsolationForest, "fit", capture_fit)
    SyntheticIsolationForestScorer()._get_model()

    assert np.array_equal(captured["features"], expected)


def test_copied_training_vector_is_rejected_as_dataset_leak():
    training = risk_evaluation.training_reference_vectors()
    validation = risk_evaluation.generate_dataset(split="validation")
    evaluation = risk_evaluation.generate_dataset(split="evaluation")
    leaked = copy.deepcopy(validation[0])
    leaked["id"] = "deliberate-training-vector-leak"
    leaked["features"] = {
        name: value for name, value in zip(FEATURE_NAMES, _feature_vector(next(iter(training))))
    }

    with pytest.raises(ValueError):
        risk_evaluation.validate_dataset_separation(training, [*validation, leaked], evaluation)


def test_validate_data_rejects_empty_malformed_nonfinite_and_nonbinary_rows():
    with pytest.raises(ValueError):
        risk_evaluation.validate_data([])

    malformed_rows = []

    missing_label = _valid_row()
    del missing_label["label"]
    malformed_rows.append(missing_label)

    boolean_label = _valid_row()
    boolean_label["label"] = False
    malformed_rows.append(boolean_label)

    nonfinite_feature = _valid_row()
    nonfinite_feature["features"] = dict(nonfinite_feature["features"])
    nonfinite_feature["features"][FEATURE_NAMES[0]] = float("nan")
    malformed_rows.append(nonfinite_feature)

    missing_feature = _valid_row()
    missing_feature["features"] = dict(missing_feature["features"])
    del missing_feature["features"][FEATURE_NAMES[-1]]
    malformed_rows.append(missing_feature)

    unequal_feature_vector = _valid_row()
    unequal_feature_vector["features"] = [0.1, 0.2]
    malformed_rows.append(unequal_feature_vector)

    for row in malformed_rows:
        with pytest.raises(ValueError):
            risk_evaluation.validate_data([row])


def test_compute_metrics_matches_fixed_sklearn_oracle():
    labels = [0, 0, 1, 1]
    scores = [0.1, 0.8, 0.7, 0.2]
    metrics = risk_evaluation.compute_metrics(labels, scores, threshold=0.65)

    assert metrics["tn"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["tp"] == 1
    assert metrics["precision"] == pytest.approx(0.5)
    assert metrics["recall"] == pytest.approx(0.5)
    assert metrics["f1"] == pytest.approx(0.5)
    assert metrics["false_positive_rate"] == pytest.approx(0.5)
    assert metrics["roc_auc"] == pytest.approx(roc_auc_score(labels, scores))
    assert metrics["average_precision"] == pytest.approx(average_precision_score(labels, scores))


@pytest.mark.parametrize(
    ("labels", "scores"),
    [
        ([], []),
        ([0, 1], [0.2]),
        ([0, 1], [float("nan"), 0.8]),
        ([0, 2], [0.2, 0.8]),
        ([False, True], [0.2, 0.8]),
    ],
)
def test_compute_metrics_rejects_invalid_inputs(labels, scores):
    with pytest.raises(ValueError):
        risk_evaluation.compute_metrics(labels, scores)


def test_compute_metrics_marks_single_class_auc_and_no_positive_ap_undefined():
    no_positive = risk_evaluation.compute_metrics([0, 0], [0.1, 0.2])
    assert no_positive["roc_auc"] is None
    assert no_positive["average_precision"] is None

    all_positive = risk_evaluation.compute_metrics([1, 1], [0.1, 0.2])
    assert all_positive["roc_auc"] is None
    assert all_positive["average_precision"] == pytest.approx(1.0)


def test_actual_model_ranks_extreme_features_above_low_features_without_threshold_drift():
    from risk_scoring import SyntheticIsolationForestScorer

    low_features = {
        "amount_to_grant_ratio": 0.05,
        "cumulative_spending_ratio": 0.05,
        "recent_velocity_ratio": 0.0,
        "new_payee": 0.0,
    }
    extreme_features = {name: 1.0 for name in FEATURE_NAMES}
    scorer = SyntheticIsolationForestScorer()
    low = scorer.score(low_features)
    extreme = scorer.score(extreme_features)

    assert risk_evaluation.ANOMALY_THRESHOLD == ANOMALY_THRESHOLD
    assert extreme.anomaly_score > low.anomaly_score
    assert low.decision == ("HOLD" if low.anomaly_score >= ANOMALY_THRESHOLD else "ALLOW")
    assert extreme.decision == ("HOLD" if extreme.anomaly_score >= ANOMALY_THRESHOLD else "ALLOW")
    assert low.decision == "ALLOW"
    assert extreme.decision == "HOLD"


def test_evaluation_report_is_reproducible_and_contains_model_dataset_threshold_timestamp():
    first = risk_evaluation.build_evaluation_report(timestamp=FIXED_TIMESTAMP)
    second = risk_evaluation.build_evaluation_report(timestamp=FIXED_TIMESTAMP)

    assert first == second
    assert first["model_version"] == MODEL_VERSION
    assert first["dataset_id"] == risk_evaluation.DATASET_ID
    assert first["training_dataset_id"] == TRAINING_DATASET_ID
    assert first["threshold"] == ANOMALY_THRESHOLD
    assert first["timestamp"] == FIXED_TIMESTAMP
    assert set(first["metrics"]) >= {"validation", "evaluation"}

    validation_counts = _scenario_counts(first, "validation")
    evaluation_counts = _scenario_counts(first, "evaluation")
    assert set(validation_counts) == set(SCENARIO_LABELS)
    assert set(evaluation_counts) == set(SCENARIO_LABELS)
    assert all(isinstance(count, int) and count > 0 for count in validation_counts.values())
    assert all(isinstance(count, int) and count > 0 for count in evaluation_counts.values())
    assert sum(validation_counts.values()) == len(risk_evaluation.generate_dataset(split="validation"))
    assert sum(evaluation_counts.values()) == len(risk_evaluation.generate_dataset(split="evaluation"))

    # The same constraints used by the persistence script must permit strict JSON.
    json.dumps(first, sort_keys=True, allow_nan=False)


def test_evaluation_script_writes_actual_report_to_default_json_path(monkeypatch, tmp_path):
    from scripts import evaluate_risk_model

    # Redirect ROOT rather than passing --output: this exercises the CLI's
    # default evaluation/synthetic_report.json destination without changing
    # the checkout or depending on network/provider modules.
    monkeypatch.setattr(evaluate_risk_model, "ROOT", tmp_path)

    assert evaluate_risk_model.main(["--timestamp", FIXED_TIMESTAMP]) == 0
    output = tmp_path / "evaluation" / "synthetic_report.json"
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["dataset_id"] == risk_evaluation.DATASET_ID
    assert report["model_version"] == MODEL_VERSION
    assert report["threshold"] == ANOMALY_THRESHOLD
    assert report["timestamp"] == FIXED_TIMESTAMP
    assert set(report["metrics"]) >= {"validation", "evaluation"}
    assert output.read_text(encoding="utf-8").endswith("\n")


def test_seed_collision_rejected_before_inference(monkeypatch):
    monkeypatch.setattr(risk_evaluation, "VALIDATION_SEED", risk_evaluation.TRAINING_SEED)
    with pytest.raises(ValueError, match="seeds must be separate"):
        risk_evaluation.build_evaluation_report(timestamp=FIXED_TIMESTAMP)


def test_empty_training_reference_and_unhashable_scenario_are_rejected():
    import numpy as np
    validation = risk_evaluation.generate_dataset("validation")
    evaluation = risk_evaluation.generate_dataset("evaluation")
    with pytest.raises(ValueError, match="training vectors"):
        risk_evaluation.validate_dataset_separation(np.empty((0, len(FEATURE_NAMES))), validation, evaluation)
    invalid = copy.deepcopy(evaluation[:1])
    invalid[0]["scenario"] = []
    with pytest.raises(ValueError, match="invalid scenario"):
        risk_evaluation.validate_data(invalid)
