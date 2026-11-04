"""Offline evaluation harness for the TrustGuard candidate risk model.

The candidate is trained on the unchanged synthetic training reference vectors,
selected using validation only, and (when it passes the pre-registered gates)
evaluated once on a separately seeded fresh holdout.  This module never changes
production scoring or the production threshold.  All model scores are ranking
signals, not calibrated fraud probabilities.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime
import hashlib
import importlib
import inspect
import json
import math
import platform
import sys
from typing import Any

import numpy as np
import sklearn

from risk_calibration import select_validation_threshold
from risk_evaluation import (
    ANOMALY_THRESHOLD,
    FEATURE_NAMES,
    SCENARIOS,
    SCENARIO_LABELS,
    TRAINING_SEED,
    VALIDATION_SEED,
    _fingerprint_vectors,
    _row_vector,
    _score_rows,
    _utc_timestamp,
    compute_metrics,
    generate_dataset,
    training_reference_vectors,
    validate_data,
    validate_dataset_separation,
)
from risk_scoring import (
    MODEL_VERSION as V1_MODEL_VERSION,
    TRAINING_DATASET_ID,
    SyntheticIsolationForestScorer,
)


DATASET_ID = "synthetic-risk-candidate-evaluation-v2"
FRESH_HOLDOUT_SEED = 20261107
FRESH_HOLDOUT_DATASET_ID = "synthetic-risk-fresh-evaluation-seed-20261107-v1"
MAX_FPR_DEFAULT = 0.01
FEATURES_VERSION = "trusted-risk-features-v1"

# This is deliberately resolved lazily.  A sibling implementation may be
# installed after this module is imported, and tests can inject a compatible
# candidate class without modifying this evaluator.
CandidateIsolationForestV2: Any = None

_NORMAL_VELOCITIES = (0.0, 0.2, 0.4)
_ANOMALOUS_VELOCITIES = (0.8, 1.0)


def _candidate_class() -> Any:
    """Return the candidate class supplied by ``risk_candidate_v2``."""
    global CandidateIsolationForestV2
    if CandidateIsolationForestV2 is None:
        try:
            module = importlib.import_module("risk_candidate_v2")
        except ModuleNotFoundError as exc:
            raise ImportError(
                "risk_candidate_v2.py with CandidateIsolationForestV2 is required"
            ) from exc
        CandidateIsolationForestV2 = getattr(module, "CandidateIsolationForestV2")
    return CandidateIsolationForestV2


def _json_safe(value: Any) -> Any:
    """Convert metadata and numpy values into strict-JSON-compatible values."""
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("candidate metadata contains a non-finite number")
        return number
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("candidate metadata contains a non-finite number")
        return value
    return str(value)


def _feature_matrix(rows: Sequence[Mapping[str, Any]]) -> np.ndarray:
    return np.asarray([_row_vector(row) for row in rows], dtype="float64")


def _fingerprint_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return _fingerprint_vectors(_feature_matrix(rows))


def _fresh_holdout_rows() -> list[dict[str, Any]]:
    """Copy the locked six-scenario generator using only seed 20261107."""
    rng = np.random.default_rng(FRESH_HOLDOUT_SEED)
    rows: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        label = SCENARIO_LABELS[scenario]
        for index in range(80):
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

            cumulative = max(cumulative, amount)
            features = {
                "amount_to_grant_ratio": amount,
                "cumulative_spending_ratio": cumulative,
                "recent_velocity_ratio": velocity,
                "new_payee": new_payee,
            }
            rows.append({
                "id": f"fresh-evaluation-{scenario}-{index:03d}",
                "scenario": scenario,
                "label": label,
                "features": features,
            })
    return rows


def generate_fresh_holdout() -> list[dict[str, Any]]:
    """Generate the independent 480-row fresh holdout exactly once per call."""
    rows = _fresh_holdout_rows()
    validate_data(rows)
    return rows


def _fit_candidate(training_matrix: np.ndarray) -> Any:
    """Instantiate and fit the candidate only on unlabeled training vectors."""
    candidate_type = _candidate_class()
    try:
        # The repository candidate accepts the training matrix at construction
        # and exposes a zero-argument sklearn-style fit().
        candidate = candidate_type(np.asarray(training_matrix, dtype="float64"))
    except TypeError:
        # Also support a conventional no-argument constructor with fit(matrix),
        # which keeps this orchestration layer compatible with injected tests.
        candidate = candidate_type()
    fit = getattr(candidate, "fit", None)
    if not callable(fit):
        raise TypeError("CandidateIsolationForestV2 must provide fit(training_vectors)")
    try:
        fit_parameters = inspect.signature(fit).parameters
    except (TypeError, ValueError):
        fit_parameters = {"training_matrix": object()}
    fitted = (
        fit()
        if not fit_parameters
        else fit(np.asarray(training_matrix, dtype="float64"))
    )
    # sklearn-style fit returns self; tolerate a custom fit that returns None.
    if fitted is not None and callable(getattr(fitted, "score", None)):
        candidate = fitted
    return candidate


def _candidate_score(candidate: Any, features: Mapping[str, Any]) -> float:
    value = candidate.score(features)
    if hasattr(value, "anomaly_score"):
        value = value.anomaly_score
    if isinstance(value, (bool, np.bool_)):
        raise ValueError("candidate returned an invalid anomaly score")
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("candidate returned an invalid anomaly score") from exc
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise ValueError("candidate returned an invalid anomaly score")
    return score


def _score_candidate_rows(
    rows: Sequence[Mapping[str, Any]], candidate: Any
) -> list[float]:
    # Keep this as the sole candidate score call per row.  Both threshold views
    # reuse this exact array, preventing re-inference and score drift.
    return [_candidate_score(candidate, row["features"]) for row in rows]


def _candidate_metadata(candidate: Any, training_matrix: np.ndarray) -> dict[str, Any]:
    metadata = getattr(candidate, "metadata", None)
    if callable(metadata):
        metadata = metadata()
    if metadata is None:
        metadata = {}
    metadata = _json_safe(metadata)
    if not isinstance(metadata, dict):
        metadata = {"value": metadata}
    metadata.setdefault("model_version", getattr(candidate, "model_version", "trustguard-isolation-forest-synthetic-v2"))
    metadata.setdefault("training_dataset_id", TRAINING_DATASET_ID)
    metadata.setdefault("training_seed", TRAINING_SEED)
    metadata.setdefault("training_row_count", int(training_matrix.shape[0]))
    metadata.setdefault("feature_names", list(FEATURE_NAMES))
    metadata.setdefault("features_version", getattr(candidate, "features_version", FEATURES_VERSION))
    metadata["fit_data_scope"] = "training_reference_vectors_only"
    metadata["labels_used_for_fit"] = False
    return _json_safe(metadata)


def _candidate_features_version(metadata: Mapping[str, Any], candidate: Any) -> str:
    for key in ("features_version", "feature_version", "featuresVersion"):
        value = metadata.get(key)
        if value is not None:
            return str(value)
    value = getattr(candidate, "features_version", None)
    return str(value) if value is not None else FEATURES_VERSION


def _scenario_metrics(
    rows: Sequence[Mapping[str, Any]],
    scores: Sequence[float],
    threshold: float,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for scenario in SCENARIOS:
        selected = [index for index, row in enumerate(rows) if row["scenario"] == scenario]
        labels = [int(rows[index]["label"]) for index in selected]
        values = [float(scores[index]) for index in selected]
        result[scenario] = {
            "sample_count": len(selected),
            "metrics": compute_metrics(labels, values, threshold=threshold),
        }
    return result


def _comparison(
    rows: Sequence[Mapping[str, Any]],
    score_sets: Mapping[str, Sequence[float]],
    thresholds: Mapping[str, float],
) -> dict[str, Any]:
    labels = [int(row["label"]) for row in rows]
    aggregate: dict[str, Any] = {}
    per_scenario: dict[str, dict[str, Any]] = {scenario: {} for scenario in SCENARIOS}
    for name in ("v1_production", "v1_calibrated", "v2_candidate"):
        aggregate[name] = compute_metrics(labels, score_sets[name], threshold=thresholds[name])
        scenarios = _scenario_metrics(rows, score_sets[name], thresholds[name])
        for scenario in SCENARIOS:
            per_scenario[scenario][name] = scenarios[scenario]
    return {"aggregate": aggregate, "per_scenario": per_scenario}


def _counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(rows),
        "normal_count": sum(int(row["label"]) == 0 for row in rows),
        "anomalous_count": sum(int(row["label"]) == 1 for row in rows),
        "by_scenario": {scenario: sum(row["scenario"] == scenario for row in rows) for scenario in SCENARIOS},
    }


def _validation_fingerprints(
    training_matrix: np.ndarray, validation_rows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    training = _fingerprint_vectors(training_matrix)
    validation = _fingerprint_rows(validation_rows)
    overlap = set(training["feature_row_hashes"]) & set(validation["feature_row_hashes"])
    if overlap:
        raise ValueError("exact feature-row overlap detected between training and validation")
    return {
        "training": training,
        "validation": validation,
        "cross_split_overlap": {"training_validation": len(overlap)},
    }


def _fresh_fingerprints(
    training_matrix: np.ndarray,
    validation_rows: Sequence[Mapping[str, Any]],
    fresh_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    # Use the repository's canonical three-way separation validator, then name
    # the third split fresh_holdout rather than the forbidden old evaluation.
    locked = validate_dataset_separation(training_matrix, validation_rows, fresh_rows)
    return {
        "training": locked["training"],
        "validation": locked["validation"],
        "fresh_holdout": locked["evaluation"],
        "cross_split_overlap": {
            "training_validation": locked["cross_split_overlap"]["training_validation"],
            "training_fresh_holdout": locked["cross_split_overlap"]["training_evaluation"],
            "validation_fresh_holdout": locked["cross_split_overlap"]["validation_evaluation"],
        },
    }


def _freeze_digest(record: Mapping[str, Any]) -> str:
    encoded = json.dumps(_json_safe(record), sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scenario_recall(comparison: Mapping[str, Any], scenario: str, name: str) -> float | None:
    metric = comparison["per_scenario"][scenario][name]["metrics"]["recall"]
    return None if metric is None else float(metric)


def _selection_gate(
    v1_selection: Mapping[str, Any],
    v2_selection: Mapping[str, Any],
    validation_comparison: Mapping[str, Any],
    max_fpr: float,
) -> tuple[bool, list[str], dict[str, Any]]:
    reasons: list[str] = []
    v1_metrics = v1_selection.get("selected_validation_metrics")
    v2_metrics = v2_selection.get("selected_validation_metrics")
    v1_threshold = v1_selection.get("selected_candidate_threshold")
    v2_threshold = v2_selection.get("selected_candidate_threshold")
    if v1_metrics is None or v1_threshold is None:
        reasons.append("v1_calibrated_threshold_unavailable")
    if v2_metrics is None or v2_threshold is None:
        reasons.append("candidate_threshold_unavailable")
    candidate_fpr = None if v2_metrics is None else v2_metrics.get("false_positive_rate")
    if candidate_fpr is None or float(candidate_fpr) > max_fpr:
        reasons.append("candidate_validation_fpr_exceeds_ceiling")

    candidate_recall = None if v2_metrics is None else v2_metrics.get("recall")
    baseline_recall = None if v1_metrics is None else v1_metrics.get("recall")
    if candidate_recall is None or baseline_recall is None or not float(candidate_recall) > float(baseline_recall):
        reasons.append("candidate_overall_validation_recall_does_not_improve")

    tradeoffs: dict[str, Any] = {
        "overall": {
            "v1_calibrated_recall": baseline_recall,
            "v2_candidate_recall": candidate_recall,
            "strict_improvement": bool(
                candidate_recall is not None
                and baseline_recall is not None
                and float(candidate_recall) > float(baseline_recall)
            ),
        },
        "scenarios": {},
    }
    for scenario in ("high_grant_utilization", "elevated_transaction_velocity"):
        old = _scenario_recall(validation_comparison, scenario, "v1_calibrated")
        new = _scenario_recall(validation_comparison, scenario, "v2_candidate")
        improved = old is not None and new is not None and new > old
        tradeoffs["scenarios"][scenario] = {
            "v1_calibrated_recall": old,
            "v2_candidate_recall": new,
            "strict_improvement": bool(improved),
        }
        if not improved:
            reasons.append(f"candidate_{scenario}_recall_does_not_improve")
    return not reasons, reasons, tradeoffs


def build_candidate_report(timestamp: Any = None, max_fpr: float = MAX_FPR_DEFAULT) -> dict[str, Any]:
    """Train, select, freeze, and optionally evaluate the v2 candidate.

    No fresh-holdout data is generated when the validation gate rejects the
    candidate.  When selected, the fresh holdout is generated and scored once;
    its results are reported as-is and never flow back into selection.
    """
    if len({TRAINING_SEED, VALIDATION_SEED, FRESH_HOLDOUT_SEED}) != 3:
        raise ValueError("training, validation and fresh holdout seeds must be separate")
    if isinstance(max_fpr, (bool, np.bool_)) or not math.isfinite(float(max_fpr)) or not 0.0 <= float(max_fpr) <= 1.0:
        raise ValueError("max_fpr must be finite and in the range 0..1")
    ceiling = float(max_fpr)

    # Only the validation split is generated before candidate selection.  The
    # candidate fit receives no labels and no validation vectors.
    training_matrix = np.asarray(training_reference_vectors(), dtype="float64")
    validation_rows = generate_dataset("validation")
    validate_data(validation_rows)
    validation_fingerprints = _validation_fingerprints(training_matrix, validation_rows)

    v1_scorer = SyntheticIsolationForestScorer()
    candidate = _fit_candidate(training_matrix)
    candidate_metadata = _candidate_metadata(candidate, training_matrix)
    features_version = _candidate_features_version(candidate_metadata, candidate)

    v1_validation_results = _score_rows(validation_rows, v1_scorer)
    v1_validation_scores = [float(row["score"]) for row in v1_validation_results]
    validation_labels = [int(row["label"]) for row in validation_rows]
    v2_validation_scores = _score_candidate_rows(validation_rows, candidate)

    v1_selection = select_validation_threshold(
        validation_labels, v1_validation_scores, max_fpr=ceiling
    )
    v2_selection = select_validation_threshold(
        validation_labels, v2_validation_scores, max_fpr=ceiling
    )
    v1_calibrated_threshold = v1_selection["selected_candidate_threshold"]
    v2_proposed_threshold = v2_selection["selected_candidate_threshold"]

    # Build validation comparisons with a valid threshold for every named view.
    # A missing calibrated threshold is represented by the production threshold
    # only for diagnostic validation metrics; it can never pass the gate.
    v1_calibration_metric_threshold = (
        float(v1_calibrated_threshold)
        if v1_calibrated_threshold is not None
        else float(ANOMALY_THRESHOLD)
    )
    v2_metric_threshold = (
        float(v2_proposed_threshold)
        if v2_proposed_threshold is not None
        else float(ANOMALY_THRESHOLD)
    )
    thresholds_for_metrics = {
        "v1_production": float(ANOMALY_THRESHOLD),
        "v1_calibrated": v1_calibration_metric_threshold,
        "v2_candidate": v2_metric_threshold,
    }
    validation_comparison = _comparison(
        validation_rows,
        {
            "v1_production": v1_validation_scores,
            "v1_calibrated": v1_validation_scores,
            "v2_candidate": v2_validation_scores,
        },
        thresholds_for_metrics,
    )
    accepted, failure_reasons, tradeoffs = _selection_gate(
        v1_selection, v2_selection, validation_comparison, ceiling
    )
    status = "SELECTED" if accepted else "NO_CANDIDATE"
    selected_threshold = float(v2_proposed_threshold) if accepted and v2_proposed_threshold is not None else None

    threshold_record = {
        "baseline_threshold": float(ANOMALY_THRESHOLD),
        "v1_calibrated_threshold": v1_calibrated_threshold,
        "candidate_proposed_threshold": v2_proposed_threshold,
        "selected_candidate_threshold": selected_threshold,
        "max_validation_fpr": ceiling,
    }
    freeze_record = {
        "selection_status": status,
        "thresholds": threshold_record,
        "candidate_model_metadata": candidate_metadata,
        "features_version": features_version,
    }
    # This digest is deliberately computed before the fresh generator is called.
    freeze_digest = _freeze_digest(freeze_record)

    fresh_comparison: dict[str, Any] | None = None
    fresh_fingerprints: dict[str, Any] | None = None
    fresh_rows: list[dict[str, Any]] | None = None
    if accepted:
        fresh_rows = generate_fresh_holdout()
        fresh_fingerprints = _fresh_fingerprints(training_matrix, validation_rows, fresh_rows)
        # Each fresh sample is scored exactly once by each model.  The v1 array
        # is shared by production and calibrated threshold views.
        v1_fresh_results = _score_rows(fresh_rows, v1_scorer)
        v1_fresh_scores = [float(row["score"]) for row in v1_fresh_results]
        v2_fresh_scores = _score_candidate_rows(fresh_rows, candidate)
        fresh_comparison = _comparison(
            fresh_rows,
            {
                "v1_production": v1_fresh_scores,
                "v1_calibrated": v1_fresh_scores,
                "v2_candidate": v2_fresh_scores,
            },
            thresholds_for_metrics,
        )

    timestamp_value = _utc_timestamp(timestamp)
    methodology = (
        "Offline synthetic candidate evaluation only. CandidateIsolationForestV2 is fit on the "
        "768 unlabeled training reference vectors before validation scoring; validation labels are "
        "used only for threshold selection and the pre-registered improvement gate. The candidate "
        "selection is frozen, including its model metadata digest, before the independent fresh "
        "holdout (seed 20261107) is generated. The old evaluation holdout seed 20261106 and its "
        "calibration labels are not used. Production remains on the v1 threshold 0.65; no model or "
        "runtime configuration is activated. Scores are anomaly-ranking signals, not probabilities, "
        "and synthetic scenario labels are not observed fraud outcomes."
    )

    all_fingerprints = fresh_fingerprints if accepted else validation_fingerprints
    counts: dict[str, Any] = {
        "training": int(training_matrix.shape[0]),
        "validation": _counts(validation_rows),
        "fresh_holdout": _counts(fresh_rows) if fresh_rows is not None else None,
    }
    report: dict[str, Any] = {
        "dataset_id": DATASET_ID,
        "fresh_holdout_dataset_id": FRESH_HOLDOUT_DATASET_ID,
        "model_version": V1_MODEL_VERSION,
        "candidate_model_version": candidate_metadata.get("model_version"),
        "training_dataset_id": TRAINING_DATASET_ID,
        "timestamp": timestamp_value,
        "status": status,
        "selection_status": status,
        "reason": "candidate_passed_validation_gate" if accepted else "improvement_failure:" + ";".join(failure_reasons),
        "selection_reason": "candidate_passed_validation_gate" if accepted else "improvement_failure:" + ";".join(failure_reasons),
        "production_activated": False,
        "baseline_threshold": float(ANOMALY_THRESHOLD),
        "selected_candidate_threshold": selected_threshold,
        "max_validation_fpr": ceiling,
        "thresholds": threshold_record,
        "selected_thresholds": threshold_record,
        "candidate_model_metadata": candidate_metadata,
        "features_version": features_version,
        "candidate_freeze_digest_sha256": freeze_digest,
        "candidate_freeze_record": freeze_record,
        "validation_comparison": validation_comparison["aggregate"],
        "fresh_holdout_comparison": None if fresh_comparison is None else fresh_comparison["aggregate"],
        "per_scenario": {
            "validation": validation_comparison["per_scenario"],
            "fresh_holdout": None if fresh_comparison is None else fresh_comparison["per_scenario"],
        },
        "validation_tradeoffs": tradeoffs,
        "threshold_selection": {
            "v1_calibrated": v1_selection,
            "v2_candidate": v2_selection,
        },
        "counts": counts,
        "sample_counts": {
            "validation": counts["validation"]["by_scenario"],
            "fresh_holdout": None if fresh_rows is None else counts["fresh_holdout"]["by_scenario"],
        },
        "seed_metadata": {
            "training_seed": TRAINING_SEED,
            "validation_seed": VALIDATION_SEED,
            "fresh_holdout_seed": FRESH_HOLDOUT_SEED,
            "old_evaluation_seed": 20261106,
            "old_holdout_seed_not_used": True,
        },
        "dataset_fingerprints": all_fingerprints,
        "runtime": {
            "python": platform.python_version(),
            "python_runtime": sys.version,
            "numpy": np.__version__,
            "sklearn": sklearn.__version__,
        },
        "model": {
            "score_direction": "higher_is_more_anomalous",
            "score_is_probability": False,
            "decision_rule": "threshold views are offline simulations; production threshold remains 0.65",
            "disclaimer": "Synthetic scenario performance is not real-fraud performance and scores are not calibrated fraud probabilities.",
        },
        "methodology": methodology,
    }
    # Keep explicit no-holdout semantics visible and avoid any score arrays in
    # a rejected report.  Selected reports retain aggregate metrics only.
    report["fresh_holdout_generated"] = bool(accepted)
    report["fresh_holdout_scored"] = bool(accepted)
    return _json_safe(report)


__all__ = [
    "DATASET_ID",
    "FEATURES_VERSION",
    "FRESH_HOLDOUT_DATASET_ID",
    "FRESH_HOLDOUT_SEED",
    "MAX_FPR_DEFAULT",
    "build_candidate_report",
    "generate_fresh_holdout",
]
