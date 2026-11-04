"""Offline validation threshold calibration for the TrustGuard synthetic scorer.

This module deliberately leaves the production scorer and its 0.65 runtime
threshold unchanged.  It selects a candidate threshold from an independent
validation split, then evaluates that frozen candidate exactly once on the
locked evaluation holdout.  Scores remain anomaly-ranking scores, not
probabilities.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
import json
import math
from pathlib import Path
import platform
import sys
from typing import Any

import numpy as np
import sklearn

from risk_evaluation import (
    DATASET_ID as EVALUATION_DATASET_ID,
    SCENARIOS,
    _score_rows,
    _utc_timestamp,
    compute_metrics,
    generate_dataset,
    training_reference_vectors,
    validate_data,
    validate_dataset_separation,
)
from risk_scoring import (
    ANOMALY_THRESHOLD,
    MODEL_VERSION,
    TRAINING_DATASET_ID,
    TRAINING_SEED,
    SyntheticIsolationForestScorer,
)
from risk_evaluation import EVALUATION_SEED, VALIDATION_SEED


DATASET_ID = "synthetic-risk-calibration-calv1"
_MAX_FPR_DEFAULT = 0.01
_LOCKED_REPORT_PATH = Path(__file__).resolve().parent / "evaluation" / "synthetic_report.json"


def _finite_unit_interval(value: Any, name: str) -> float:
    """Return a finite float in [0, 1], rejecting bools and other values."""
    if isinstance(value, (bool, np.bool_)):
        raise ValueError(f"{name} must be finite and in the range 0..1")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be finite and in the range 0..1") from exc
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{name} must be finite and in the range 0..1")
    return number


def _validation_inputs(
    validation_labels: Sequence[Any], validation_scores: Sequence[Any]
) -> tuple[list[int], list[float]]:
    """Validate labels and scores through the canonical evaluator metric path."""
    try:
        labels = list(validation_labels)
        scores = list(validation_scores)
    except TypeError as exc:
        raise ValueError("labels and scores must be sequences") from exc
    # compute_metrics owns the repository's complete input contract.  The
    # threshold is immaterial here; this call also normalizes numpy scalars.
    compute_metrics(labels, scores, threshold=0.0)
    return [int(value) for value in labels], [float(value) for value in scores]


def _candidate_values(
    validation_scores: Sequence[float], candidate_thresholds: Sequence[Any] | None
) -> list[float]:
    if candidate_thresholds is not None:
        if isinstance(candidate_thresholds, (str, bytes, bytearray)):
            raise ValueError("candidate_thresholds must be a sequence")
        try:
            supplied = list(candidate_thresholds)
        except TypeError as exc:
            raise ValueError("candidate_thresholds must be a sequence") from exc
        if not supplied:
            # An explicitly empty candidate list is meaningful: callers asked
            # for no candidates, so selection must not invent a fallback.
            return []
        return [_finite_unit_interval(value, "candidate threshold") for value in supplied]

    # Include both sides of every observed score.  Since predictions use
    # score >= threshold, nextafter(score, 1.0) is the smallest representable
    # threshold that excludes that exact score.
    values = {0.0, 1.0}
    for score in validation_scores:
        score_value = float(score)
        values.add(score_value)
        successor = math.nextafter(score_value, 1.0)
        if 0.0 <= successor <= 1.0:
            values.add(successor)
    return sorted(values)


def select_validation_threshold(
    validation_labels: Sequence[Any],
    validation_scores: Sequence[Any],
    max_fpr: float = _MAX_FPR_DEFAULT,
    candidate_thresholds: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Select a threshold using validation labels and scores only.

    Feasible candidates must have defined recall and false-positive rate and
    must satisfy ``false_positive_rate <= max_fpr``.  Selection maximizes
    recall, then minimizes false-positive rate, then chooses the higher
    threshold as a deterministic conservative tie-break.
    """
    ceiling = _finite_unit_interval(max_fpr, "max_fpr")
    labels, scores = _validation_inputs(validation_labels, validation_scores)
    candidates = _candidate_values(scores, candidate_thresholds)

    candidate_results: list[dict[str, Any]] = []
    for threshold in candidates:
        metrics = compute_metrics(labels, scores, threshold=threshold)
        recall = metrics["recall"]
        false_positive_rate = metrics["false_positive_rate"]
        feasible = (
            recall is not None
            and false_positive_rate is not None
            and false_positive_rate <= ceiling
        )
        candidate_results.append({
            "threshold": float(threshold),
            "metrics": metrics,
            "feasible": bool(feasible),
        })

    feasible_results = [result for result in candidate_results if result["feasible"]]
    selected: dict[str, Any] | None = None
    reason: str
    if feasible_results:
        # Higher recall wins; lower FPR wins next; higher threshold is the
        # conservative deterministic tie-break when the first two agree.
        selected = min(
            feasible_results,
            key=lambda result: (
                -float(result["metrics"]["recall"]),
                float(result["metrics"]["false_positive_rate"]),
                -float(result["threshold"]),
            ),
        )
        reason = "selected_max_recall_then_min_fpr_then_higher_threshold"
    elif not candidate_results:
        reason = "no_candidates_provided"
    elif all(
        result["metrics"]["recall"] is None
        or result["metrics"]["false_positive_rate"] is None
        for result in candidate_results
    ):
        reason = "class_missing"
    else:
        reason = "no_feasible_candidate"

    return {
        "status": "SELECTED" if selected is not None else "NO_VALID_CANDIDATE",
        "selected_candidate_threshold": (
            float(selected["threshold"]) if selected is not None else None
        ),
        "selected_validation_metrics": (
            selected["metrics"] if selected is not None else None
        ),
        "candidate_results": candidate_results,
        "reason": reason,
        "ceiling": ceiling,
    }


def _load_locked_baseline_fingerprints() -> dict[str, Any]:
    """Load and validate the original checked-in holdout lock metadata."""
    try:
        with _LOCKED_REPORT_PATH.open("r", encoding="utf-8") as handle:
            original = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"locked baseline report is unavailable or invalid: {_LOCKED_REPORT_PATH}"
        ) from exc

    if original.get("model_version") != MODEL_VERSION:
        raise ValueError("locked baseline model version does not match the scorer")
    if original.get("training_dataset_id") != TRAINING_DATASET_ID:
        raise ValueError("locked baseline training dataset does not match the scorer")
    if original.get("threshold") != ANOMALY_THRESHOLD:
        raise ValueError("locked baseline threshold does not match the production threshold")
    fingerprints = original.get("dataset_fingerprints")
    if not isinstance(fingerprints, dict) or not all(
        isinstance(fingerprints.get(split), dict)
        for split in ("training", "validation", "evaluation")
    ):
        raise ValueError("locked baseline report has incomplete dataset fingerprints")
    return fingerprints


def _assert_locked_fingerprints(
    fingerprints: dict[str, Any], expected: dict[str, Any]
) -> None:
    """Reject any changed training, validation, or evaluation feature split."""
    for split in ("training", "validation", "evaluation"):
        if fingerprints.get(split) != expected.get(split):
            raise ValueError(f"{split} dataset fingerprint does not match the locked baseline")
    if fingerprints.get("cross_split_overlap") != expected.get("cross_split_overlap"):
        raise ValueError("cross-split overlap fingerprint does not match the locked baseline")


def _scenario_metrics(
    rows: Sequence[dict[str, Any]],
    scores: Sequence[float],
    threshold: float,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for scenario in SCENARIOS:
        indices = [index for index, row in enumerate(rows) if row["scenario"] == scenario]
        labels = [int(rows[index]["label"]) for index in indices]
        scenario_scores = [float(scores[index]) for index in indices]
        result[scenario] = {
            "sample_count": len(indices),
            "metrics": compute_metrics(labels, scenario_scores, threshold=threshold),
        }
    return result


def build_calibration_report(max_fpr: float = _MAX_FPR_DEFAULT, timestamp: Any = None) -> dict[str, Any]:
    """Build a validation-calibrated, locked-holdout synthetic report.

    The returned candidate threshold is a report-time simulation only.  This
    function never changes ``risk_scoring.ANOMALY_THRESHOLD`` or production
    decision behavior.
    """
    if len({TRAINING_SEED, VALIDATION_SEED, EVALUATION_SEED}) != 3:
        raise ValueError("training, validation and evaluation seeds must be separate")
    ceiling = _finite_unit_interval(max_fpr, "max_fpr")

    # Freeze selection before the evaluation split is generated or scored.
    validation_rows = generate_dataset("validation")
    validate_data(validation_rows)
    scorer = SyntheticIsolationForestScorer()
    validation_results = _score_rows(validation_rows, scorer)
    validation_labels = [int(row["label"]) for row in validation_results]
    validation_scores = [float(row["score"]) for row in validation_results]
    selection = select_validation_threshold(
        validation_labels,
        validation_scores,
        max_fpr=ceiling,
    )

    # Generate, fingerprint, and score the locked holdout exactly once.  No
    # holdout label or score is passed to the selector above.
    evaluation_rows = generate_dataset("evaluation")
    validate_data(evaluation_rows)
    training_matrix = training_reference_vectors()
    fingerprints = validate_dataset_separation(
        training_matrix, validation_rows, evaluation_rows
    )
    _assert_locked_fingerprints(fingerprints, _load_locked_baseline_fingerprints())
    evaluation_results = _score_rows(evaluation_rows, scorer)
    evaluation_labels = [int(row["label"]) for row in evaluation_results]
    evaluation_scores = [float(row["score"]) for row in evaluation_results]

    baseline_validation_metrics = compute_metrics(
        validation_labels, validation_scores, threshold=ANOMALY_THRESHOLD
    )
    candidate_threshold = selection["selected_candidate_threshold"]
    candidate_validation_metrics = selection["selected_validation_metrics"]
    baseline_holdout_metrics = compute_metrics(
        evaluation_labels, evaluation_scores, threshold=ANOMALY_THRESHOLD
    )
    candidate_holdout_metrics = (
        compute_metrics(evaluation_labels, evaluation_scores, threshold=candidate_threshold)
        if candidate_threshold is not None
        else None
    )

    scenario_baseline = _scenario_metrics(
        evaluation_rows, evaluation_scores, ANOMALY_THRESHOLD
    )
    scenario_candidate = (
        _scenario_metrics(evaluation_rows, evaluation_scores, candidate_threshold)
        if candidate_threshold is not None
        else None
    )
    per_scenario: dict[str, dict[str, Any]] = {}
    for scenario in SCENARIOS:
        per_scenario[scenario] = {
            "sample_count": scenario_baseline[scenario]["sample_count"],
            "baseline": scenario_baseline[scenario]["metrics"],
            "candidate": (
                scenario_candidate[scenario]["metrics"]
                if scenario_candidate is not None
                else None
            ),
        }

    validation_counts = {
        scenario: sum(row["scenario"] == scenario for row in validation_rows)
        for scenario in SCENARIOS
    }
    evaluation_counts = {
        scenario: sum(row["scenario"] == scenario for row in evaluation_rows)
        for scenario in SCENARIOS
    }
    timestamp_value = _utc_timestamp(timestamp)
    methodology = (
        "Offline synthetic calibration only. The existing IsolationForest scorer is run unchanged; "
        "training seed 20261104, validation seed 20261105, and locked evaluation seed 20261106 are "
        "distinct. Candidate thresholds are derived only from validation scores (0, 1, each observed "
        "score, and its math.nextafter(score, 1.0) boundary), and the candidate is frozen before the "
        "evaluation dataset is generated or scored. The evaluation holdout is scored once with the "
        "same exact score array for baseline and candidate metrics, so ROC-AUC and average precision "
        "are ranking metrics identical across thresholds. Labels are deterministic synthetic scenario "
        "labels, not observed fraud outcomes. Exact anomaly scores are ranking signals, not calibrated "
        "fraud probabilities. HOLD below is a simulated threshold decision only; no production threshold "
        "or runtime scorer behavior is changed."
    )

    counts = {
        "training": int(training_matrix.shape[0]),
        "validation": len(validation_rows),
        "evaluation": len(evaluation_rows),
        "holdout": len(evaluation_rows),
        "validation_by_scenario": validation_counts,
        "evaluation_by_scenario": evaluation_counts,
    }
    thresholds = {
        "baseline": float(ANOMALY_THRESHOLD),
        "selected_candidate_threshold": candidate_threshold,
        "max_validation_fpr": ceiling,
    }
    return {
        "dataset_id": DATASET_ID,
        "calibration_dataset_id": DATASET_ID,
        "evaluation_dataset_id": EVALUATION_DATASET_ID,
        "model_version": MODEL_VERSION,
        "training_dataset_id": TRAINING_DATASET_ID,
        "status": selection["status"],
        "reason": selection["reason"],
        "thresholds": thresholds,
        "baseline_threshold": float(ANOMALY_THRESHOLD),
        "selected_candidate_threshold": candidate_threshold,
        "max_validation_fpr": ceiling,
        "validation_comparison": {
            "baseline": baseline_validation_metrics,
            "candidate": candidate_validation_metrics,
        },
        "holdout_comparison": {
            "baseline": baseline_holdout_metrics,
            "candidate": candidate_holdout_metrics,
        },
        "threshold": float(ANOMALY_THRESHOLD),
        "baseline_metrics": baseline_holdout_metrics,
        "candidate_metrics": candidate_holdout_metrics,
        "validation_metrics": baseline_validation_metrics,
        "holdout_metrics": baseline_holdout_metrics,
        "candidate_holdout_metrics": candidate_holdout_metrics,
        "per_scenario": per_scenario,
        "candidate_results": selection["candidate_results"],
        "threshold_selection": selection,
        "counts": counts,
        "sample_counts": {
            "validation": validation_counts,
            "evaluation": evaluation_counts,
        },
        "seeds": {
            "training_seed": TRAINING_SEED,
            "validation_seed": VALIDATION_SEED,
            "evaluation_seed": EVALUATION_SEED,
        },
        "dataset_fingerprints": fingerprints,
        "timestamp": timestamp_value,
        "runtime": {
            "python": platform.python_version(),
            "python_runtime": sys.version,
            "numpy": np.__version__,
            "sklearn": sklearn.__version__,
        },
        "methodology": methodology,
    }


__all__ = [
    "DATASET_ID",
    "build_calibration_report",
    "select_validation_threshold",
]
