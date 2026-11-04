from __future__ import annotations

import copy
import inspect
import json
import math
from pathlib import Path
from types import SimpleNamespace

import pytest

import risk_calibration
import risk_scoring
from risk_evaluation import compute_metrics

FIXED_TIMESTAMP = "2026-11-04T17:10:47+00:00"
ROOT = Path(__file__).resolve().parents[1]
BASELINE_REPORT = ROOT / "evaluation" / "synthetic_report.json"


def _selected_metrics(selection: dict) -> dict:
    metrics = selection["selected_validation_metrics"]
    assert metrics is not None
    return metrics


def test_selector_maximizes_recall_under_validation_fpr_ceiling():
    labels = [0, 0, 0, 0, 1, 1, 1, 1]
    scores = [0.10, 0.20, 0.30, 0.40, 0.45, 0.55, 0.70, 0.90]
    selection = risk_calibration.select_validation_threshold(
        labels,
        scores,
        max_fpr=0.25,
        candidate_thresholds=[0.20, 0.40, 0.55, 0.60, 0.70, 0.90],
    )

    assert selection["status"] == "SELECTED"
    assert selection["selected_candidate_threshold"] == pytest.approx(0.40)
    metrics = _selected_metrics(selection)
    assert metrics["false_positive_rate"] <= 0.25
    feasible = [item for item in selection["candidate_results"] if item["feasible"]]
    assert metrics["recall"] == pytest.approx(
        max(item["metrics"]["recall"] for item in feasible)
    )
    assert selection["reason"]


def test_selector_ties_are_deterministic_lower_fpr_then_higher_threshold():
    labels = [0, 0, 0, 0, 1, 1, 1, 1]
    scores = [0.10, 0.40, 0.60, 0.90, 0.20, 0.20, 0.80, 0.90]
    candidates = [0.30, 0.70, 0.90]

    first = risk_calibration.select_validation_threshold(
        labels, scores, max_fpr=0.75, candidate_thresholds=candidates
    )
    second = risk_calibration.select_validation_threshold(
        labels, scores, max_fpr=0.75, candidate_thresholds=list(reversed(candidates))
    )

    # 0.30 and 0.70 both recall half of the positives, but 0.70 has the
    # lower FPR.  Reversing candidate order must not affect the result.
    assert first["selected_candidate_threshold"] == pytest.approx(0.70)
    assert second["selected_candidate_threshold"] == first["selected_candidate_threshold"]
    assert _selected_metrics(first)["false_positive_rate"] < 0.75
    assert _selected_metrics(first)["recall"] == pytest.approx(0.5)


@pytest.mark.parametrize("ceiling", [-0.01, 1.01, float("nan"), float("inf"), -float("inf")])
def test_selector_rejects_malformed_fpr_ceiling(ceiling):
    with pytest.raises(ValueError):
        risk_calibration.select_validation_threshold([0, 1], [0.1, 0.9], max_fpr=ceiling)


@pytest.mark.parametrize(
    "candidate_thresholds",
    [([-0.01, 0.5],), ([0.5, 1.01],), ([float("nan")],)],
)
def test_selector_rejects_malformed_candidate_bounds(candidate_thresholds):
    with pytest.raises(ValueError):
        risk_calibration.select_validation_threshold(
            [0, 1], [0.1, 0.9], candidate_thresholds=candidate_thresholds[0]
        )


def test_selector_rejects_nonfinite_or_out_of_range_scores():
    for scores in ([float("nan"), 0.9], [float("inf"), 0.9], [-0.1, 0.9], [1.1, 0.9]):
        with pytest.raises(ValueError):
            risk_calibration.select_validation_threshold([0, 1], scores)


def test_selector_has_no_fallback_when_every_threshold_violates_zero_fpr_ceiling():
    # Both normal examples score exactly 1.0, so every threshold in [0, 1]
    # predicts at least one negative as positive under score >= threshold.
    selection = risk_calibration.select_validation_threshold(
        [0, 0, 1, 1],
        [1.0, 1.0, 0.8, 0.9],
        max_fpr=0.0,
        candidate_thresholds=[0.0, 0.25, 0.5, 0.75, 1.0],
    )

    assert selection["status"] == "NO_VALID_CANDIDATE"
    assert selection["selected_candidate_threshold"] is None
    assert selection["selected_validation_metrics"] is None
    assert selection["selected_candidate_threshold"] != risk_scoring.ANOMALY_THRESHOLD
    assert selection["reason"] == "no_feasible_candidate"


def test_selector_rejects_absent_negative_class_as_no_selection():
    selection = risk_calibration.select_validation_threshold(
        [1, 1, 1],
        [0.1, 0.5, 0.9],
        max_fpr=0.01,
        candidate_thresholds=[0.1, 0.5, 0.9],
    )

    assert selection["status"] == "NO_VALID_CANDIDATE"
    assert selection["selected_candidate_threshold"] is None
    assert selection["selected_validation_metrics"] is None
    assert selection["reason"] == "class_missing"
    assert all(item["metrics"]["false_positive_rate"] is None for item in selection["candidate_results"])


def test_selector_api_is_validation_only_and_holdout_perturbations_cannot_change_candidate():
    signature = inspect.signature(risk_calibration.select_validation_threshold)
    assert list(signature.parameters) == [
        "validation_labels",
        "validation_scores",
        "max_fpr",
        "candidate_thresholds",
    ]
    validation_labels = [0, 0, 1, 1]
    validation_scores = [0.1, 0.2, 0.7, 0.8]
    first = risk_calibration.select_validation_threshold(
        validation_labels, validation_scores, max_fpr=0.5, candidate_thresholds=[0.2, 0.7]
    )
    # These are deliberately different hypothetical holdout labels.  They are
    # not an argument to the selector and therefore cannot tune its result.
    holdout_labels_a = [0, 0, 1, 1]
    holdout_labels_b = [1, 1, 0, 0]
    assert holdout_labels_a != holdout_labels_b
    second = risk_calibration.select_validation_threshold(
        validation_labels, validation_scores, max_fpr=0.5, candidate_thresholds=[0.2, 0.7]
    )
    assert first == second


def _install_report_isolation_doubles(monkeypatch):
    validation_rows = [
        {"id": "validation-0", "scenario": "routine_known_payee", "label": 0, "features": {}},
        {"id": "validation-1", "scenario": "routine_new_payee", "label": 1, "features": {}},
    ]
    evaluation_rows = [
        {"id": "evaluation-0", "scenario": "routine_known_payee", "label": 0, "features": {}},
        {"id": "evaluation-1", "scenario": "routine_new_payee", "label": 1, "features": {}},
    ]
    datasets = {"validation": validation_rows, "evaluation": evaluation_rows}
    events = []
    selector_calls = []
    score_calls = []
    metric_calls = []
    original_compute_metrics = risk_calibration.compute_metrics

    def fake_generate_dataset(split):
        events.append(("generate", split))
        return copy.deepcopy(datasets[split])

    def fake_score_rows(rows, _scorer):
        split = "evaluation" if rows[0]["id"].startswith("evaluation") else "validation"
        events.append(("score", split))
        score_calls.extend(row["id"] for row in rows)
        values = {"validation-0": 0.20, "validation-1": 0.80, "evaluation-0": 0.80, "evaluation-1": 0.90}
        return [
            {
                **row,
                "score": values[row["id"]],
                "decision": "HOLD" if values[row["id"]] >= risk_scoring.ANOMALY_THRESHOLD else "ALLOW",
            }
            for row in rows
        ]

    def fake_selector(labels, scores, *, max_fpr=0.01, candidate_thresholds=None):
        events.append(("select", tuple(labels), tuple(scores), max_fpr))
        selector_calls.append((tuple(labels), tuple(scores), max_fpr))
        selected_metrics = original_compute_metrics(labels, scores, threshold=0.4)
        return {
            "status": "SELECTED",
            "selected_candidate_threshold": 0.4,
            "selected_validation_metrics": selected_metrics,
            "candidate_results": [],
            "reason": "test_validation_only_selection",
        }

    def recording_compute_metrics(labels, scores, threshold=risk_scoring.ANOMALY_THRESHOLD):
        metric_calls.append((tuple(labels), tuple(scores), threshold))
        return original_compute_metrics(labels, scores, threshold=threshold)

    monkeypatch.setattr(risk_calibration, "generate_dataset", fake_generate_dataset)
    monkeypatch.setattr(risk_calibration, "validate_data", lambda rows: None)
    monkeypatch.setattr(risk_calibration, "_score_rows", fake_score_rows)
    monkeypatch.setattr(risk_calibration, "select_validation_threshold", fake_selector)
    monkeypatch.setattr(risk_calibration, "compute_metrics", recording_compute_metrics)
    monkeypatch.setattr(risk_calibration, "training_reference_vectors", lambda: __import__("numpy").zeros((1, 4)))
    monkeypatch.setattr(risk_calibration, "validate_dataset_separation", lambda *args: {"training": {}, "validation": {}, "evaluation": {}, "cross_split_overlap": {}})
    monkeypatch.setattr(risk_calibration, "_assert_locked_fingerprints", lambda *args: None)
    monkeypatch.setattr(
        risk_calibration,
        "_scenario_metrics",
        lambda *args: {
            scenario: {"sample_count": 0, "metrics": {}}
            for scenario in risk_calibration.SCENARIOS
        },
    )
    monkeypatch.setattr(risk_calibration, "SyntheticIsolationForestScorer", lambda: SimpleNamespace())
    return datasets, events, selector_calls, score_calls, metric_calls


def test_report_selects_before_holdout_generation_and_scores_holdout_once(monkeypatch):
    datasets, events, selector_calls, score_calls, metric_calls = _install_report_isolation_doubles(monkeypatch)
    report = risk_calibration.build_calibration_report(max_fpr=0.01, timestamp=FIXED_TIMESTAMP)

    assert [event[0:2] for event in events] == [
        ("generate", "validation"),
        ("score", "validation"),
        ("select", (0, 1)),
        ("generate", "evaluation"),
        ("score", "evaluation"),
    ]
    assert len(selector_calls) == 1
    assert selector_calls[0][0:2] == ((0, 1), (0.20, 0.80))
    assert all(item[1] != "evaluation" for item in events[:3])
    assert score_calls.count("evaluation-0") == 1
    assert score_calls.count("evaluation-1") == 1

    # The holdout has one false positive at the selected threshold.  This is
    # reported rather than fed back into selection.
    assert report["selected_candidate_threshold"] == pytest.approx(0.4)
    assert report["threshold_selection"]["selected_validation_metrics"]["false_positive_rate"] == 0.0
    assert report["candidate_holdout_metrics"]["false_positive_rate"] == 1.0
    holdout_metric_calls = [
        call for call in metric_calls if call[0] == (0, 1) and call[1] == (0.80, 0.90)
    ]
    assert {call[2] for call in holdout_metric_calls} == {0.4, risk_scoring.ANOMALY_THRESHOLD}
    assert all(call[1] == (0.80, 0.90) for call in holdout_metric_calls)

    # Changing holdout labels while retaining validation scores must not alter
    # the already-defined validation candidate.
    datasets["evaluation"][0]["label"] = 1
    second = risk_calibration.build_calibration_report(max_fpr=0.01, timestamp=FIXED_TIMESTAMP)
    assert second["selected_candidate_threshold"] == report["selected_candidate_threshold"]
    assert selector_calls[0][0:2] == selector_calls[1][0:2]
    assert second["candidate_holdout_metrics"] != report["candidate_holdout_metrics"]


def test_report_is_reproducible_has_frozen_candidate_metrics_and_preserves_runtime_threshold(monkeypatch):
    # Keep this an actual-model test, but share the scorer instance so its
    # documented lazy IsolationForest cache avoids fitting twice.
    scorer = risk_scoring.SyntheticIsolationForestScorer()
    monkeypatch.setattr(risk_calibration, "SyntheticIsolationForestScorer", lambda: scorer)
    first = risk_calibration.build_calibration_report(timestamp=FIXED_TIMESTAMP)
    second = risk_calibration.build_calibration_report(timestamp=FIXED_TIMESTAMP)

    assert first == second
    assert first["timestamp"] == FIXED_TIMESTAMP
    assert first["baseline_threshold"] == 0.65
    assert first["thresholds"]["baseline"] == 0.65
    assert first["thresholds"]["max_validation_fpr"] == 0.01
    assert first["status"] == "SELECTED"
    selected = first["threshold_selection"]["selected_validation_metrics"]
    assert selected["false_positive_rate"] <= first["max_validation_fpr"]
    feasible = [item for item in first["candidate_results"] if item["feasible"]]
    assert selected["recall"] == pytest.approx(
        max(item["metrics"]["recall"] for item in feasible)
    )
    assert first["holdout_comparison"]["candidate"]["threshold"] == first["selected_candidate_threshold"]
    assert first["holdout_comparison"]["baseline"]["threshold"] == risk_scoring.ANOMALY_THRESHOLD
    assert risk_scoring.ANOMALY_THRESHOLD == 0.65
    baseline = json.loads(BASELINE_REPORT.read_text(encoding="utf-8"))
    assert first["dataset_fingerprints"] == baseline["dataset_fingerprints"]
    assert first["model_version"] == baseline["model_version"]
    assert first["training_dataset_id"] == baseline["training_dataset_id"]


def test_report_dataset_fingerprints_match_locked_baseline_evaluation_report():
    baseline = json.loads(BASELINE_REPORT.read_text(encoding="utf-8"))
    assert risk_calibration._load_locked_baseline_fingerprints() == baseline["dataset_fingerprints"]
    assert baseline["threshold"] == 0.65


def test_cli_persists_exact_report_parameters_without_activating_candidate(monkeypatch, tmp_path, capsys):
    from scripts import calibrate_risk_threshold

    calls = []
    fixture_report = {
        "status": "SELECTED",
        "selected_candidate_threshold": 0.70,
        "baseline_threshold": 0.65,
        "max_validation_fpr": 0.02,
        "timestamp": FIXED_TIMESTAMP,
        "validation": {"false_positive_rate": 0.0},
        "holdout": {"false_positive_rate": 0.5},
    }

    def fake_builder(*, max_fpr, timestamp):
        calls.append((max_fpr, timestamp))
        return dict(fixture_report)

    monkeypatch.setattr(calibrate_risk_threshold, "build_calibration_report", fake_builder)
    output = tmp_path / "calibration-report.json"
    assert calibrate_risk_threshold.main(
        ["--max-validation-fpr", "0.02", "--timestamp", FIXED_TIMESTAMP, "--output", str(output)]
    ) == 0

    assert calls == [(0.02, FIXED_TIMESTAMP)]
    assert json.loads(output.read_text(encoding="utf-8")) == fixture_report
    assert output.read_text(encoding="utf-8").endswith("\n")
    stdout = capsys.readouterr().out.lower()
    assert "candidate is not active" in stdout
    assert "production threshold remains 0.65" in stdout
    assert "active threshold" not in stdout
