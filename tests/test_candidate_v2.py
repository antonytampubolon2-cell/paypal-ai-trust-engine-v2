from __future__ import annotations

import copy
import hashlib
import importlib
import inspect
import json
import math
from collections.abc import Mapping
from pathlib import Path

import numpy as np
import pytest

import risk_candidate_v2 as candidate_module
import risk_evaluation
import risk_scoring
from risk_scoring import FEATURE_NAMES, TRAINING_DATASET_ID, TRAINING_SEED


FIXED_TIMESTAMP = "2026-11-04T17:10:47+00:00"
SCENARIO_LABELS = {
    "routine_known_payee": 0,
    "routine_new_payee": 0,
    "high_grant_utilization": 1,
    "elevated_transaction_velocity": 1,
    "new_payee_high_utilization": 1,
    "combined_extreme": 1,
}
CONTINUOUS_FEATURES = FEATURE_NAMES[:-1]
PAYEE_FEATURE = FEATURE_NAMES[-1]


def _features(
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


def _fresh_evaluation_module():
    """Load the optional candidate evaluator only when the candidate agent has added it."""
    return pytest.importorskip("risk_candidate_evaluation")


def _metadata_sha256(metadata: Mapping) -> str:
    for key in ("training_matrix_sha256", "training_fingerprint"):
        value = metadata.get(key)
        if isinstance(value, str) and value:
            return value
    raise AssertionError(f"candidate metadata has no training fingerprint: {metadata!r}")


def _metric(entry: Mapping, name: str):
    """Find an exact metric field in a comparison entry without assuming nesting."""
    if name in entry:
        return entry[name]
    for key in ("metrics", "validation_metrics", "fresh_holdout_metrics", "evaluation_metrics"):
        nested = entry.get(key)
        if isinstance(nested, Mapping) and name in nested:
            return nested[name]
    raise AssertionError(f"comparison entry has no {name!r}: {entry!r}")


def _comparison_entry(comparison: Mapping, *needles: str) -> Mapping:
    """Find a model comparison entry by tolerant model-name matching."""
    wanted = tuple(needle.lower() for needle in needles)
    for key, value in comparison.items():
        if isinstance(value, Mapping) and all(needle in str(key).lower() for needle in wanted):
            return value
    for key, value in comparison.items():
        if isinstance(value, Mapping) and any(needle in str(key).lower() for needle in wanted):
            return value
    raise AssertionError(f"comparison has no entry matching {needles!r}: {comparison!r}")


def _report_candidate_entry(report: Mapping, section: str) -> Mapping:
    comparison = report[section]
    assert isinstance(comparison, Mapping)
    for names in (("candidate", "v2"), ("candidate",), ("v2",)):
        try:
            return _comparison_entry(comparison, *names)
        except AssertionError:
            pass
    raise AssertionError(f"{section} has no candidate entry: {comparison!r}")


def _report_calibrated_entry(report: Mapping, section: str) -> Mapping:
    comparison = report[section]
    assert isinstance(comparison, Mapping)
    for names in (("calibrated", "v1"), ("calibrated",), ("validation", "v1")):
        try:
            return _comparison_entry(comparison, *names)
        except AssertionError:
            pass
    raise AssertionError(f"{section} has no calibrated-v1 entry: {comparison!r}")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("new_payee"),
        lambda value: value.update(extra_feature=0.1),
        lambda value: value.update(amount_to_grant_ratio=True),
        lambda value: value.update(amount_to_grant_ratio=np.bool_(False)),
        lambda value: value.update(amount_to_grant_ratio=float("nan")),
        lambda value: value.update(amount_to_grant_ratio=float("inf")),
        lambda value: value.update(amount_to_grant_ratio=-0.01),
        lambda value: value.update(amount_to_grant_ratio=1.01),
        lambda value: value.update(new_payee=0.5),
    ],
)
def test_raw_features_missing_extras_bool_nan_out_of_range_and_nonbinary_are_rejected(mutate):
    features = _features()
    mutate(features)
    with pytest.raises(ValueError):
        candidate_module.CandidateIsolationForestV2().transform_features(features)


def test_training_matrix_rejects_bad_width_nonfinite_range_and_nonbinary_payee():
    reference = risk_evaluation.training_reference_vectors()
    invalid_matrices = []

    invalid_width = reference[:, :3]
    invalid_matrices.append(invalid_width)

    invalid_nan = reference.copy()
    invalid_nan[0, 0] = np.nan
    invalid_matrices.append(invalid_nan)

    invalid_range = reference.copy()
    invalid_range[0, 1] = 1.01
    invalid_matrices.append(invalid_range)

    invalid_payee = reference.copy()
    invalid_payee[0, FEATURE_NAMES.index(PAYEE_FEATURE)] = 0.25
    invalid_matrices.append(invalid_payee)

    for matrix in invalid_matrices:
        with pytest.raises(ValueError):
            candidate_module.CandidateIsolationForestV2(training_matrix=matrix)


def test_payee_history_remains_exact_raw_binary_with_fixed_offset_and_scale():
    matrix = risk_evaluation.training_reference_vectors()
    matrix[:, FEATURE_NAMES.index(PAYEE_FEATURE)] = 1.0
    scorer = candidate_module.CandidateIsolationForestV2(training_matrix=matrix)

    zero = scorer.transform_features(_features(new_payee=0.0))
    one = scorer.transform_features(_features(new_payee=1.0))
    assert zero[-1] == 0.0
    assert one[-1] == 1.0

    metadata = scorer.metadata()
    representation = metadata["representation"]
    assert representation["binary_features_preserved_raw"] == [PAYEE_FEATURE]
    assert representation["new_payee_history_preserved"] is True
    assert representation["quantile_boundaries"][PAYEE_FEATURE] == 0.0
    assert representation["scales"][PAYEE_FEATURE] == 1.0
    assert representation["binary_formula"] == "new_payee_raw_0_or_1"


def test_training_is_deterministic_for_metadata_transforms_and_scores():
    first = candidate_module.CandidateIsolationForestV2()
    second = candidate_module.CandidateIsolationForestV2()
    probes = (
        _features(),
        _features(amount=0.9, cumulative=0.95, velocity=1.0, new_payee=1.0),
        _features(amount=0.7, cumulative=0.85, velocity=0.8, new_payee=0.0),
    )

    assert first.metadata() == second.metadata()
    for features in probes:
        assert np.array_equal(first.transform_features(features), second.transform_features(features))
        assert first.score(features) == pytest.approx(second.score(features), abs=0.0)
        assert first.score_per_feature(features) == second.score_per_feature(features)

    metadata = first.metadata()
    assert metadata["training_dataset_id"] == TRAINING_DATASET_ID
    assert metadata["training_rows"] == 768
    assert metadata["hyperparameters"] == {
        "n_estimators": 128,
        "max_samples": 256,
        "contamination": 0.04,
        "n_jobs": 1,
        "random_state_base": TRAINING_SEED,
        "random_states": [TRAINING_SEED + index for index in range(4)],
        "sigmoid_scale": 8.0,
    }
    assert metadata["validation_or_evaluation_used_for_fit"] is False
    assert metadata["no_labels_passed_to_fit"] is True


def test_isolation_forest_fit_uses_only_768_training_rows_as_four_univariate_inputs(monkeypatch):
    reference = risk_evaluation.training_reference_vectors()
    source_calls = []
    fit_calls = []
    original_fit = candidate_module.IsolationForest.fit

    def reference_only():
        source_calls.append(True)
        return reference.copy()

    def capture_fit(model, x, *args, **kwargs):
        fit_calls.append((np.asarray(x).copy(), args, dict(kwargs)))
        return original_fit(model, x, *args, **kwargs)

    def forbidden_dataset_generation(*args, **kwargs):
        raise AssertionError("candidate fitting must not generate validation/evaluation rows")

    monkeypatch.setattr(candidate_module, "training_reference_vectors", reference_only)
    monkeypatch.setattr(candidate_module.IsolationForest, "fit", capture_fit)
    monkeypatch.setattr(risk_evaluation, "generate_dataset", forbidden_dataset_generation)

    scorer = candidate_module.CandidateIsolationForestV2()
    scorer.fit()

    assert len(source_calls) == 1
    assert len(fit_calls) == len(FEATURE_NAMES) == 4
    assert all(call[0].shape == (768, 1) for call in fit_calls)
    assert all(call[1] == () and call[2] == {} for call in fit_calls)
    assert all(np.isfinite(call[0]).all() for call in fit_calls)
    assert all(call[0].shape[1] == 1 for call in fit_calls)
    assert len(scorer.forests) == 4
    assert all(forest.n_estimators == 128 for forest in scorer.forests)
    assert all(forest.max_samples == 256 for forest in scorer.forests)
    assert all(forest.contamination == 0.04 for forest in scorer.forests)
    assert [forest.random_state for forest in scorer.forests] == [TRAINING_SEED + i for i in range(4)]

    # Repeated fit calls must not refit or consult any other split.
    scorer.fit()
    assert len(fit_calls) == 4


def test_score_is_bounded_aggregates_marginal_scores_and_ranks_isolated_extremes_higher():
    scorer = candidate_module.CandidateIsolationForestV2()
    routine = _features()
    extreme = _features(amount=1.0, cumulative=1.0, velocity=1.0, new_payee=1.0)

    routine_parts = scorer.score_per_feature(routine)
    extreme_parts = scorer.score_per_feature(extreme)
    assert set(routine_parts) == set(FEATURE_NAMES)
    assert all(0.0 <= value <= 1.0 and math.isfinite(value) for value in routine_parts.values())
    assert all(0.0 <= value <= 1.0 and math.isfinite(value) for value in extreme_parts.values())
    assert scorer.score(routine) == pytest.approx(max(routine_parts.values()))
    assert scorer.score(extreme) == pytest.approx(max(extreme_parts.values()))
    assert scorer.score(extreme) > scorer.score(routine)

    # Each continuous dimension is scored in its own forest; a strong isolated
    # utilization or velocity signal must not be diluted by routine dimensions.
    for name in ("cumulative_spending_ratio", "recent_velocity_ratio"):
        isolated = dict(routine)
        isolated[name] = 1.0
        assert scorer.score_per_feature(isolated)[name] > routine_parts[name]


def test_candidate_does_not_call_legacy_evaluation_split_or_use_20261106(monkeypatch):
    source = inspect.getsource(candidate_module)
    assert "20261106" not in source
    assert 'generate_dataset("evaluation")' not in source
    assert "split=\"evaluation\"" not in source

    original_generator = risk_evaluation.generate_dataset
    calls = []

    def guarded_generator(split):
        calls.append(split)
        if split == "evaluation":
            raise AssertionError("legacy 20261106 evaluation split is forbidden for v2 training")
        return original_generator(split)

    # Candidate construction must remain independent of all holdout generators.
    # The reference-vector function is the only data source it is allowed to use.
    # This guard is deliberately installed even though the call should remain empty.
    monkeypatch.setattr(risk_evaluation, "generate_dataset", guarded_generator)
    candidate_module.CandidateIsolationForestV2().fit()
    assert "evaluation" not in calls


@pytest.mark.parametrize("split", ["validation"])
def test_fresh_holdout_has_20261107_six_scenarios_480_rows_and_expected_labels(split):
    evaluator = _fresh_evaluation_module()
    assert hasattr(evaluator, "generate_fresh_holdout")
    rows = evaluator.generate_fresh_holdout()
    again = evaluator.generate_fresh_holdout()
    assert rows == again
    assert len(rows) == 480
    assert {row["scenario"] for row in rows} == set(SCENARIO_LABELS)
    assert {row["label"] for row in rows} == {0, 1}
    counts = {scenario: 0 for scenario in SCENARIO_LABELS}
    for row in rows:
        assert set(row) == {"id", "scenario", "label", "features"}
        assert row["label"] == SCENARIO_LABELS[row["scenario"]]
        assert set(row["features"]) == set(FEATURE_NAMES)
        assert row["id"].startswith("fresh-") or row["id"].startswith("evaluation-")
        assert "20261106" not in row["id"]
        counts[row["scenario"]] += 1
    assert counts == {scenario: 80 for scenario in SCENARIO_LABELS}
    risk_evaluation.validate_data(rows)
    assert getattr(evaluator, "FRESH_HOLDOUT_SEED", 20261107) == 20261107


def test_training_validation_fresh_holdout_row_hashes_are_disjoint_and_seed_ids_are_distinct():
    evaluator = _fresh_evaluation_module()
    training = risk_evaluation.training_reference_vectors()
    validation = risk_evaluation.generate_dataset("validation")
    fresh = evaluator.generate_fresh_holdout()
    fingerprints = risk_evaluation.validate_dataset_separation(training, validation, fresh)

    assert fingerprints["training"]["count"] == 768
    assert fingerprints["validation"]["count"] == 240
    assert fingerprints["evaluation"]["count"] == 480
    assert fingerprints["cross_split_overlap"] == {
        "training_validation": 0,
        "training_evaluation": 0,
        "validation_evaluation": 0,
    }
    assert len({TRAINING_SEED, risk_evaluation.VALIDATION_SEED, 20261107}) == 3
    assert risk_evaluation.EVALUATION_SEED == 20261106
    assert "20261106" not in json.dumps(fresh, sort_keys=True)


def test_candidate_report_is_reproducible_has_required_fields_and_strict_json():
    evaluator = _fresh_evaluation_module()
    first = evaluator.build_candidate_report(timestamp=FIXED_TIMESTAMP, max_fpr=0.01)
    second = evaluator.build_candidate_report(timestamp=FIXED_TIMESTAMP, max_fpr=0.01)
    assert first == second
    assert {
        "status",
        "selected_candidate_threshold",
        "validation_comparison",
        "fresh_holdout_comparison",
        "candidate_model_metadata",
    }.issubset(first)
    assert first.get("timestamp") == FIXED_TIMESTAMP
    assert isinstance(first["candidate_model_metadata"], Mapping)
    assert _metadata_sha256(first["candidate_model_metadata"])
    json.dumps(first, sort_keys=True, allow_nan=False)


def test_selected_candidate_gate_requires_validation_fpr_and_strict_recall_improvement():
    evaluator = _fresh_evaluation_module()
    report = evaluator.build_candidate_report(timestamp=FIXED_TIMESTAMP, max_fpr=0.01)
    status = report["status"]
    assert status in {"SELECTED", "NO_VALID_CANDIDATE"}

    if status == "NO_VALID_CANDIDATE":
        assert report["selected_candidate_threshold"] is None
        assert report.get("fresh_holdout_comparison") in (None, {})
        return

    threshold = report["selected_candidate_threshold"]
    assert isinstance(threshold, (int, float)) and not isinstance(threshold, bool)
    assert 0.0 <= float(threshold) <= 1.0
    candidate_validation = _report_candidate_entry(report, "validation_comparison")
    assert _metric(candidate_validation, "false_positive_rate") <= 0.01

    # The selection gate is intentionally strict against validation-calibrated
    # v1, not merely against the production .65 baseline.
    candidate_fresh = _report_candidate_entry(report, "fresh_holdout_comparison")
    calibrated_fresh = _report_calibrated_entry(report, "fresh_holdout_comparison")
    assert _metric(candidate_fresh, "recall") > _metric(calibrated_fresh, "recall")
    per_scenario = report["per_scenario"]["fresh_holdout"]
    for scenario in ("high_grant_utilization", "elevated_transaction_velocity"):
        candidate_scenario = per_scenario[scenario]["v2_candidate"]
        calibrated_scenario = per_scenario[scenario]["v1_calibrated"]
        assert _metric(candidate_scenario, "recall") > _metric(calibrated_scenario, "recall")


def test_candidate_choice_is_frozen_before_fresh_generation_and_legacy_evaluation_is_forbidden(monkeypatch):
    evaluator = _fresh_evaluation_module()
    events = []

    original_fresh = evaluator.generate_fresh_holdout

    def record_fresh(*args, **kwargs):
        assert "selected" in events, "threshold choice must be frozen before fresh holdout generation"
        events.append("fresh")
        return original_fresh(*args, **kwargs)

    monkeypatch.setattr(evaluator, "generate_fresh_holdout", record_fresh)

    # Candidate evaluators normally re-export the validation selector.  Patch
    # either that alias or the calibration module alias, while keeping the
    # production calibration implementation as the observable selector.
    selector_modules = [evaluator]
    try:
        selector_modules.append(importlib.import_module("risk_calibration"))
    except ModuleNotFoundError:
        pass
    patched_selector = False
    for module in selector_modules:
        if hasattr(module, "select_validation_threshold"):
            original_selector = module.select_validation_threshold

            def record_selector(*args, _original=original_selector, **kwargs):
                result = _original(*args, **kwargs)
                events.append("selected")
                return result

            monkeypatch.setattr(module, "select_validation_threshold", record_selector)
            patched_selector = True

    # If selection is implemented inline, the source must still identify a
    # validation-only selector rather than the retired evaluation split.
    source = inspect.getsource(evaluator.build_candidate_report)
    assert 'generate_dataset("evaluation")' not in source
    assert "split=\"evaluation\"" not in source
    evaluator.build_candidate_report(timestamp=FIXED_TIMESTAMP, max_fpr=0.01)
    assert "fresh" in events
    if patched_selector:
        assert events.index("selected") < events.index("fresh")


def test_rejected_candidate_discloses_no_fresh_holdout(monkeypatch):
    evaluator = _fresh_evaluation_module()
    selectors = []
    for module in (evaluator, importlib.import_module("risk_calibration")):
        if hasattr(module, "select_validation_threshold"):
            selectors.append(module)
    if not selectors:
        pytest.skip("candidate evaluator does not expose a validation selector hook")

    no_candidate = {
        "status": "NO_VALID_CANDIDATE",
        "selected_candidate_threshold": None,
        "selected_validation_metrics": None,
        "candidate_results": [],
        "reason": "no_feasible_candidate",
    }
    for module in selectors:
        monkeypatch.setattr(module, "select_validation_threshold", lambda *args, **kwargs: no_candidate)

    def forbidden_fresh(*args, **kwargs):
        raise AssertionError("a rejected candidate must not disclose or score a fresh holdout")

    monkeypatch.setattr(evaluator, "generate_fresh_holdout", forbidden_fresh)
    report = evaluator.build_candidate_report(timestamp=FIXED_TIMESTAMP, max_fpr=0.01)
    assert report["status"] in {"NO_CANDIDATE", "NO_VALID_CANDIDATE"}
    assert report["selected_candidate_threshold"] is None
    assert report.get("fresh_holdout_comparison") in (None, {})


def test_metadata_fingerprint_and_production_threshold_and_score_class_survive_fresh_evaluation():
    evaluator = _fresh_evaluation_module()
    scorer = candidate_module.CandidateIsolationForestV2()
    before_metadata = copy.deepcopy(scorer.metadata())
    before_sha = _metadata_sha256(before_metadata)
    before_threshold = risk_scoring.ANOMALY_THRESHOLD
    before_model_version = risk_scoring.MODEL_VERSION
    before_score = risk_scoring.SyntheticIsolationForestScorer.score

    evaluator.generate_fresh_holdout()
    after_metadata = scorer.metadata()
    assert _metadata_sha256(after_metadata) == before_sha
    assert after_metadata == before_metadata
    assert risk_scoring.ANOMALY_THRESHOLD == before_threshold == 0.65
    assert risk_scoring.MODEL_VERSION == before_model_version
    assert risk_scoring.SyntheticIsolationForestScorer.score is before_score


def test_candidate_script_writes_fixture_metadata_and_report_to_custom_tmp_paths(monkeypatch, tmp_path):
    pytest.importorskip("risk_candidate_evaluation")
    from scripts import evaluate_candidate_v2

    fixture_metadata = {
        "model_version": "fixture-candidate",
        "training_matrix_sha256": hashlib.sha256(b"fixture").hexdigest(),
    }
    fixture_report = {
        "status": "NO_VALID_CANDIDATE",
        "selected_candidate_threshold": None,
        "validation_comparison": {},
        "fresh_holdout_comparison": None,
        "candidate_model_metadata": fixture_metadata,
        "timestamp": FIXED_TIMESTAMP,
    }
    monkeypatch.setattr(evaluate_candidate_v2, "build_candidate_report", lambda **kwargs: fixture_report)
    report_path = tmp_path / "nested" / "candidate-report.json"
    metadata_path = tmp_path / "nested" / "candidate-metadata.json"

    assert evaluate_candidate_v2.main([
        "--timestamp", FIXED_TIMESTAMP,
        "--output", str(report_path),
        "--metadata-output", str(metadata_path),
    ]) == 0
    assert json.loads(report_path.read_text(encoding="utf-8")) == fixture_report
    assert json.loads(metadata_path.read_text(encoding="utf-8")) == fixture_metadata
    assert report_path.read_text(encoding="utf-8").endswith("\n")
    assert metadata_path.read_text(encoding="utf-8").endswith("\n")
