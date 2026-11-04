"""Deterministic synthetic evaluation harness for TrustGuard risk scoring.

This module intentionally does not fit or modify the production scorer.  The
training vectors are a byte-for-byte reproduction of the vector-generation
portion of :mod:`risk_scoring.SyntheticIsolationForestScorer._fit_model`, and
are used only for dataset fingerprints.  Validation and evaluation rows are
separate, seeded holdout scenarios with labels assigned by scenario rules,
not by model scores.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import math
import platform
import sys
from typing import Any

import numpy as np
import sklearn
from sklearn.metrics import average_precision_score, roc_auc_score

from risk_scoring import (
    ANOMALY_THRESHOLD,
    FEATURE_NAMES,
    MODEL_VERSION,
    TRAINING_DATASET_ID,
    TRAINING_SEED,
    SyntheticIsolationForestScorer,
)

VALIDATION_SEED = 20261105
EVALUATION_SEED = 20261106
DATASET_ID = "synthetic-risk-evaluation-evalv1"

SCENARIOS = (
    "routine_known_payee",
    "routine_new_payee",
    "high_grant_utilization",
    "elevated_transaction_velocity",
    "new_payee_high_utilization",
    "combined_extreme",
)
SCENARIO_LABELS = {
    "routine_known_payee": 0,
    "routine_new_payee": 0,
    "high_grant_utilization": 1,
    "elevated_transaction_velocity": 1,
    "new_payee_high_utilization": 1,
    "combined_extreme": 1,
}
_TRAINING_SCENARIO = "training_reference"
_NORMAL_VELOCITIES = (0.0, 0.2, 0.4)
_ANOMALOUS_VELOCITIES = (0.8, 1.0)
_ROW_KEYS = frozenset(("id", "scenario", "label", "features"))


def training_reference_vectors() -> np.ndarray:
    """Return the exact synthetic baseline matrix used by the production model.

    This copies only the unchanged RNG/distribution formula from the scorer;
    it does not instantiate or fit an IsolationForest.
    """
    rng = np.random.default_rng(TRAINING_SEED)
    count = 768
    baseline = np.column_stack((
        rng.beta(2.0, 4.0, count) * 0.70,
        rng.beta(1.5, 3.0, count) * 0.82,
        rng.beta(1.2, 8.0, count),
        rng.binomial(1, 0.25, count),
    )).astype("float64")
    return baseline


def _holdout_rows(split: str) -> list[dict[str, Any]]:
    if split == "validation":
        seed, per_scenario = VALIDATION_SEED, 40
    elif split == "evaluation":
        seed, per_scenario = EVALUATION_SEED, 80
    else:
        raise ValueError("split must be 'training', 'validation', or 'evaluation'")

    rng = np.random.default_rng(seed)
    rows: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        label = SCENARIO_LABELS[scenario]
        for index in range(per_scenario):
            if scenario == "routine_known_payee":
                amount = float(rng.uniform(0.05, 0.25))
                cumulative = float(rng.uniform(amount, 0.55))
                velocity = float(rng.choice(_NORMAL_VELOCITIES))
                new_payee = 0.0
            elif scenario == "routine_new_payee":
                amount = float(rng.uniform(0.05, 0.25))
                cumulative = float(rng.uniform(amount, 0.55))
                velocity = float(rng.choice(_NORMAL_VELOCITIES))
                new_payee = 1.0
            elif scenario == "high_grant_utilization":
                amount = float(rng.uniform(0.10, 0.45))
                cumulative = float(rng.uniform(0.82, 0.99))
                velocity = float(rng.choice(_NORMAL_VELOCITIES))
                new_payee = 0.0
            elif scenario == "elevated_transaction_velocity":
                amount = float(rng.uniform(0.05, 0.40))
                cumulative = float(rng.uniform(amount, 0.70))
                velocity = float(rng.choice(_ANOMALOUS_VELOCITIES))
                new_payee = 0.0
            elif scenario == "new_payee_high_utilization":
                amount = float(rng.uniform(0.20, 0.60))
                cumulative = float(rng.uniform(0.82, 0.99))
                velocity = float(rng.choice(_NORMAL_VELOCITIES))
                new_payee = 1.0
            else:  # combined_extreme
                amount = float(rng.uniform(0.65, 0.90))
                cumulative = float(rng.uniform(max(amount, 0.90), 1.0))
                velocity = float(rng.choice(_ANOMALOUS_VELOCITIES))
                new_payee = 1.0

            # The ranges above make this true by construction.  Keeping the
            # assignment explicit documents the synthetic ledger invariant.
            cumulative = max(cumulative, amount)
            features = {
                "amount_to_grant_ratio": amount,
                "cumulative_spending_ratio": cumulative,
                "recent_velocity_ratio": velocity,
                "new_payee": new_payee,
            }
            rows.append({
                "id": f"{split}-{scenario}-{index:03d}",
                "scenario": scenario,
                "label": label,
                "features": features,
            })
    return rows


def generate_dataset(split: str) -> list[dict[str, Any]]:
    """Generate a deterministic training, validation, or evaluation dataset.

    Validation contains 40 rows per holdout scenario and evaluation contains
    80 rows per scenario.  Training exposes the 768 exact baseline vectors as
    normal ``training_reference`` rows for fingerprinting only.
    """
    if split == "training":
        matrix = training_reference_vectors()
        return [
            {
                "id": f"training-reference-{index:04d}",
                "scenario": _TRAINING_SCENARIO,
                "label": 0,
                "features": {
                    name: (int(row[position]) if name == "new_payee" else float(row[position]))
                    for position, name in enumerate(FEATURE_NAMES)
                },
            }
            for index, row in enumerate(matrix)
        ]
    return _holdout_rows(split)


def _is_number(value: Any) -> bool:
    return not isinstance(value, (bool, np.bool_)) and isinstance(value, (int, float, np.integer, np.floating))


def validate_data(rows: Sequence[Mapping[str, Any]]) -> None:
    """Raise ``ValueError`` unless rows have the trusted evaluation schema."""
    if isinstance(rows, (str, bytes, bytearray)) or not isinstance(rows, Sequence):
        raise ValueError("data must be a non-empty sequence of row mappings")
    if not rows:
        raise ValueError("data must not be empty")

    seen: set[Any] = set()
    for position, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError(f"row {position} is not a mapping")
        if set(row) != _ROW_KEYS:
            raise ValueError(f"row {position} has missing or extra fields")
        row_id = row["id"]
        if not isinstance(row_id, str) or not row_id:
            raise ValueError(f"row {position} has an invalid id")
        if row_id in seen:
            raise ValueError(f"duplicate id: {row_id}")
        seen.add(row_id)

        scenario = row["scenario"]
        if not isinstance(scenario, str) or (scenario not in SCENARIO_LABELS and scenario != _TRAINING_SCENARIO):
            raise ValueError(f"row {position} has an invalid scenario")
        label = row["label"]
        if isinstance(label, (bool, np.bool_)) or not isinstance(label, (int, np.integer)) or int(label) not in (0, 1):
            raise ValueError(f"row {position} has an invalid label")
        expected_label = 0 if scenario == _TRAINING_SCENARIO else SCENARIO_LABELS[scenario]
        if int(label) != expected_label:
            raise ValueError(f"row {position} label does not match its scenario rule")

        features = row["features"]
        if not isinstance(features, Mapping) or set(features) != set(FEATURE_NAMES):
            raise ValueError(f"row {position} has missing or extra features")
        values = {name: features[name] for name in FEATURE_NAMES}
        for name, value in values.items():
            if not _is_number(value) or not math.isfinite(float(value)) or not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"row {position} feature {name} is NaN or out of range")
        new_payee = values["new_payee"]
        if float(new_payee) not in (0.0, 1.0):
            raise ValueError(f"row {position} new_payee must be 0 or 1")
        velocity = float(values["recent_velocity_ratio"])
        if scenario != _TRAINING_SCENARIO and velocity not in (*_NORMAL_VELOCITIES, *_ANOMALOUS_VELOCITIES):
            raise ValueError(f"row {position} recent_velocity_ratio is not a permitted discrete value")
        if scenario != _TRAINING_SCENARIO and float(values["cumulative_spending_ratio"]) < float(values["amount_to_grant_ratio"]):
            raise ValueError(f"row {position} cumulative spending is below amount")


def _row_vector(row: Mapping[str, Any]) -> np.ndarray:
    return np.asarray([float(row["features"][name]) for name in FEATURE_NAMES], dtype="float64")


def _feature_row_hash(vector: Sequence[float]) -> str:
    values = np.asarray(vector, dtype="float64")
    if values.shape != (len(FEATURE_NAMES),):
        raise ValueError("feature row has an invalid shape")
    return hashlib.sha256(values.tobytes(order="C")).hexdigest()


def _fingerprint_vectors(vectors: np.ndarray) -> dict[str, Any]:
    matrix = np.asarray(vectors, dtype="float64")
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES):
        raise ValueError("feature matrix has an invalid shape")
    row_hashes = [_feature_row_hash(row) for row in matrix]
    return {
        "count": int(matrix.shape[0]),
        "feature_row_hashes": row_hashes,
        "feature_matrix_sha256": hashlib.sha256(matrix.tobytes(order="C")).hexdigest(),
        "feature_row_hashes_sha256": hashlib.sha256("\n".join(row_hashes).encode("ascii")).hexdigest(),
    }


def validate_dataset_separation(
    training_vectors: Sequence[Sequence[float]],
    validation_rows: Sequence[Mapping[str, Any]],
    evaluation_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Fingerprint datasets and reject exact feature-row overlap between splits."""
    validate_data(validation_rows)
    validate_data(evaluation_rows)
    training_matrix = np.asarray(training_vectors, dtype="float64")
    if training_matrix.ndim != 2 or training_matrix.shape[1] != len(FEATURE_NAMES) or training_matrix.shape[0] == 0:
        raise ValueError("training vectors have an invalid shape")
    if not np.isfinite(training_matrix).all() or not ((training_matrix >= 0.0) & (training_matrix <= 1.0)).all():
        raise ValueError("training vectors contain an invalid feature value")

    fingerprints = {
        "training": _fingerprint_vectors(training_matrix),
        "validation": _fingerprint_vectors(np.asarray([_row_vector(row) for row in validation_rows])),
        "evaluation": _fingerprint_vectors(np.asarray([_row_vector(row) for row in evaluation_rows])),
    }
    sets = {name: set(value["feature_row_hashes"]) for name, value in fingerprints.items()}
    overlaps = {
        "training_validation": sorted(sets["training"] & sets["validation"]),
        "training_evaluation": sorted(sets["training"] & sets["evaluation"]),
        "validation_evaluation": sorted(sets["validation"] & sets["evaluation"]),
    }
    if any(overlaps.values()):
        raise ValueError("exact feature-row overlap detected between dataset splits")
    fingerprints["cross_split_overlap"] = {name: len(values) for name, values in overlaps.items()}
    return fingerprints


def _validate_metric_inputs(y_true: Sequence[Any], scores: Sequence[Any], threshold: Any) -> tuple[list[int], list[float], float]:
    if isinstance(y_true, (str, bytes, bytearray)) or isinstance(scores, (str, bytes, bytearray)):
        raise ValueError("labels and scores must be sequences")
    try:
        labels = list(y_true)
        values = list(scores)
    except TypeError as exc:
        raise ValueError("labels and scores must be sequences") from exc
    if not labels or not values:
        raise ValueError("labels and scores must not be empty")
    if len(labels) != len(values):
        raise ValueError("labels and scores must have equal lengths")
    if isinstance(threshold, (bool, np.bool_)) or not _is_number(threshold) or not math.isfinite(float(threshold)) or not 0.0 <= float(threshold) <= 1.0:
        raise ValueError("threshold must be finite and in the range 0..1")
    clean_labels: list[int] = []
    clean_scores: list[float] = []
    for label, score in zip(labels, values):
        if isinstance(label, (bool, np.bool_)) or not isinstance(label, (int, np.integer)) or int(label) not in (0, 1):
            raise ValueError("labels must contain only integer 0/1 values")
        if isinstance(score, (bool, np.bool_)) or not _is_number(score) or not math.isfinite(float(score)) or not 0.0 <= float(score) <= 1.0:
            raise ValueError("scores must be finite values in the range 0..1")
        clean_labels.append(int(label))
        clean_scores.append(float(score))
    return clean_labels, clean_scores, float(threshold)


def compute_metrics(y_true: Sequence[Any], scores: Sequence[Any], threshold: float = ANOMALY_THRESHOLD) -> dict[str, Any]:
    """Compute threshold metrics and ranking metrics with explicit undefined reasons."""
    labels, values, threshold_value = _validate_metric_inputs(y_true, scores, threshold)
    predictions = [int(score >= threshold_value) for score in values]
    tn = sum(label == 0 and prediction == 0 for label, prediction in zip(labels, predictions))
    fp = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions))
    fn = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions))
    tp = sum(label == 1 and prediction == 1 for label, prediction in zip(labels, predictions))

    undefined_reasons: dict[str, str | None] = {}
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    f1_denominator = 2 * tp + fp + fn
    fpr_denominator = fp + tn
    precision = (tp / precision_denominator) if precision_denominator else None
    recall = (tp / recall_denominator) if recall_denominator else None
    f1 = (2 * tp / f1_denominator) if f1_denominator else None
    false_positive_rate = (fp / fpr_denominator) if fpr_denominator else None
    undefined_reasons["precision"] = None if precision is not None else "no predicted positives"
    undefined_reasons["recall"] = None if recall is not None else "no actual positives"
    undefined_reasons["f1"] = None if f1 is not None else "no positive support or predicted positives"
    undefined_reasons["false_positive_rate"] = None if false_positive_rate is not None else "no actual negatives"

    distinct_labels = set(labels)
    if len(distinct_labels) < 2:
        roc_auc = None
        undefined_reasons["roc_auc"] = "single-class labels"
    else:
        roc_auc = float(roc_auc_score(labels, values))
        undefined_reasons["roc_auc"] = None
    if tp + fn == 0:
        average_precision = None
        undefined_reasons["average_precision"] = "zero actual positives"
    else:
        average_precision = float(average_precision_score(labels, values))
        undefined_reasons["average_precision"] = None

    return {
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        # Flat aliases keep the metric object convenient for callers while
        # confusion_matrix remains the canonical report representation.
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "roc_auc": roc_auc,
        "average_precision": average_precision,
        "undefined_reasons": undefined_reasons,
        "threshold": threshold_value,
    }


def _utc_timestamp(timestamp: Any) -> str:
    if timestamp is None:
        value = datetime.now(timezone.utc)
    elif isinstance(timestamp, datetime):
        value = timestamp
    elif isinstance(timestamp, str):
        text = timestamp.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            value = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
        # Preserve caller-supplied UTC spelling, including a +00:00 suffix,
        # so an injected timestamp remains byte-for-byte reproducible.
        if value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value):
            return timestamp.strip()
    else:
        raise ValueError("timestamp must be None, datetime, or ISO-8601 string")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _sample_counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    normal = sum(int(row["label"]) == 0 for row in rows)
    anomalous = sum(int(row["label"]) == 1 for row in rows)
    return {"total": len(rows), "normal_count": normal, "anomalous_count": anomalous}


def _score_rows(rows: Sequence[Mapping[str, Any]], scorer: SyntheticIsolationForestScorer) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for row in rows:
        assessment = scorer.score(row["features"])
        score = assessment.anomaly_score
        if score is None or not math.isfinite(float(score)) or not 0.0 <= float(score) <= 1.0:
            raise ValueError("scorer returned an invalid anomaly score")
        if assessment.decision != ("HOLD" if score >= ANOMALY_THRESHOLD else "ALLOW"):
            raise ValueError("model decision conflicts with the unchanged runtime threshold")
        results.append({
            "id": row["id"],
            "scenario": row["scenario"],
            "label": int(row["label"]),
            "score": float(score),
            "decision": assessment.decision,
            "features": dict(row["features"]),
        })
    return results


def build_evaluation_report(timestamp: Any = None) -> dict[str, Any]:
    """Build the reproducible validation/evaluation report using actual inference."""
    if len({TRAINING_SEED, VALIDATION_SEED, EVALUATION_SEED}) != 3:
        raise ValueError("training, validation and evaluation seeds must be separate")
    validation_rows = generate_dataset("validation")
    evaluation_rows = generate_dataset("evaluation")
    training_matrix = training_reference_vectors()
    validate_data(validation_rows)
    validate_data(evaluation_rows)
    fingerprints = validate_dataset_separation(training_matrix, validation_rows, evaluation_rows)

    scorer = SyntheticIsolationForestScorer()
    validation_results = _score_rows(validation_rows, scorer)
    evaluation_results = _score_rows(evaluation_rows, scorer)

    validation_labels = [row["label"] for row in validation_results]
    validation_scores = [row["score"] for row in validation_results]
    evaluation_labels = [row["label"] for row in evaluation_results]
    evaluation_scores = [row["score"] for row in evaluation_results]
    validation_metrics = compute_metrics(validation_labels, validation_scores)
    evaluation_metrics = compute_metrics(evaluation_labels, evaluation_scores)

    per_scenario: dict[str, dict[str, Any]] = {}
    for scenario in SCENARIOS:
        scenario_results = [row for row in evaluation_results if row["scenario"] == scenario]
        scenario_scores = [row["score"] for row in scenario_results]
        scenario_labels = [row["label"] for row in scenario_results]
        scenario_metrics = compute_metrics(scenario_labels, scenario_scores)
        per_scenario[scenario] = {
            "sample_count": len(scenario_results),
            "normal_count": sum(label == 0 for label in scenario_labels),
            "anomalous_count": sum(label == 1 for label in scenario_labels),
            "hold_count": sum(row["decision"] == "HOLD" for row in scenario_results),
            "mean_anomaly_score": float(np.mean(scenario_scores)),
            "metrics": scenario_metrics,
        }

    sample_counts = {
        **_sample_counts(evaluation_rows),
        "validation": {scenario: 40 for scenario in SCENARIOS},
        "evaluation": {scenario: 80 for scenario in SCENARIOS},
    }
    validation_sample_counts = _sample_counts(validation_rows)
    report_metrics = dict(evaluation_metrics)
    report_metrics["validation"] = validation_metrics
    report_metrics["evaluation"] = evaluation_metrics
    disclaimer = (
        "Synthetic generator performance is not real-fraud performance. High utilization and new-payee "
        "patterns are synthetic scenario labels, not evidence that a transaction is fraud. Scores are "
        "ranking signals, not calibrated fraud probabilities."
    )
    return {
        "dataset_id": DATASET_ID,
        "model_version": MODEL_VERSION,
        "training_dataset_id": TRAINING_DATASET_ID,
        "timestamp": _utc_timestamp(timestamp),
        "threshold": ANOMALY_THRESHOLD,
        "validation_used_for_training_or_selection": False,
        "threshold_tuned": False,
        "seed_metadata": {
            "training_seed": TRAINING_SEED,
            "validation_seed": VALIDATION_SEED,
            "evaluation_seed": EVALUATION_SEED,
            "validation_rows_per_scenario": 40,
            "evaluation_rows_per_scenario": 80,
        },
        "sample_counts": sample_counts,
        "validation_sample_counts": validation_sample_counts,
        "counts": {
            "training": int(training_matrix.shape[0]),
            "validation": validation_sample_counts["total"],
            "evaluation": sample_counts["total"],
        },
        "metrics": report_metrics,
        "validation_metrics": validation_metrics,
        "per_scenario": per_scenario,
        "dataset_fingerprints": fingerprints,
        "runtime": {
            "python": platform.python_version(),
            "python_runtime": sys.version,
            "numpy": np.__version__,
            "sklearn": sklearn.__version__,
        },
        "model": {
            "score_direction": "higher_is_more_anomalous",
            "score_is_probability": False,
            "decision_rule": "HOLD when anomaly score >= threshold",
            "disclaimer": disclaimer,
        },
        "individual_results": evaluation_results,
    }


__all__ = [
    "ANOMALY_THRESHOLD",
    "DATASET_ID",
    "EVALUATION_SEED",
    "FEATURE_NAMES",
    "SCENARIOS",
    "TRAINING_SEED",
    "VALIDATION_SEED",
    "build_evaluation_report",
    "compute_metrics",
    "generate_dataset",
    "training_reference_vectors",
    "validate_data",
    "validate_dataset_separation",
]
