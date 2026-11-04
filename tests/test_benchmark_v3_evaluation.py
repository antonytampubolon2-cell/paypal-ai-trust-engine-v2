from __future__ import annotations

import copy
from pathlib import Path

import pytest

import benchmark_v3_evaluation as evaluation

FIXED_TIMESTAMP = "2026-11-04T17:10:47+00:00"
ROOT = Path(__file__).resolve().parents[1]


def test_exact_binomial_fpr_upper_bound_and_null_intervals():
    interval = evaluation.exact_binomial_ci(0, 160, one_sided_upper=True)
    assert interval["lower"] == 0.0
    assert interval["upper"] == pytest.approx(0.0185491341, abs=1e-10)
    assert evaluation.exact_binomial_ci(0, 0)["defined"] is False
    with pytest.raises(ValueError):
        evaluation.exact_binomial_ci(2, 1)


def test_selector_is_validation_only_and_never_uses_holdout_labels():
    first = evaluation.select_validation_threshold(
        [0, 0, 1, 1], [0.10, 0.20, 0.70, 0.80], max_fpr=0.5
    )
    second = evaluation.select_validation_threshold(
        [0, 0, 1, 1], [0.10, 0.20, 0.70, 0.80], max_fpr=0.5
    )
    assert first == second
    assert first["status"] == "SELECTED"
    assert first["selected_candidate_threshold"] is not None


def test_metadata_mismatch_is_rejected_without_fallback():
    class FakeModel:
        def metadata(self):
            return {
                "model_version": "trustguard-isolation-forest-synthetic-v2-candidate",
                "feature_version": evaluation.FEATURE_VERSION,
                "representation": "raw",
                "n_estimators": 128,
            }

    with pytest.raises(ValueError, match="model version"):
        evaluation._metadata(FakeModel(), evaluation.CONFIGS[0], [{"x": 1}])


def test_report_freezes_before_holdout_and_does_not_write_old_artifacts(monkeypatch, tmp_path):
    import benchmark_v3_data as data

    artifacts_before = {str(path): path.read_bytes() for path in (ROOT / "evaluation").glob("*.json")}
    events: list[str] = []
    original_generate = data.generate_split

    def recording_generate(split: str):
        events.append(f"generate:{split}")
        return original_generate(split)

    def freeze(record):
        events.append("freeze")
        assert record["feature_version"] == evaluation.FEATURE_VERSION
        assert record["dataset_fingerprints"]["training"]["count"] == 512
        assert record["dataset_fingerprints"]["validation"]["count"] == 384

    monkeypatch.setattr(data, "generate_split", recording_generate)
    report = evaluation.build_report(timestamp=FIXED_TIMESTAMP, freeze_callback=freeze)
    assert report["status"] == "SELECTED"
    assert events.index("freeze") < events.index("generate:holdout")
    assert events.count("generate:holdout") == 1
    assert artifacts_before == {str(path): path.read_bytes() for path in (ROOT / "evaluation").glob("*.json")}
    assert report["holdout_count"] == 640
    assert report["holdout_metrics"]["confusion_matrix"]


def test_fixed_timestamp_reports_are_deterministic():
    first = evaluation.build_report(timestamp=FIXED_TIMESTAMP)
    second = evaluation.build_report(timestamp=FIXED_TIMESTAMP)
    assert first == second
    assert first["timestamp"] == FIXED_TIMESTAMP
    assert first["counts"] == {"training": 512, "validation": 384, "holdout": 640}
    assert first["holdout_metrics"]["bootstrap_confidence_intervals"]["f1"]["replicates"] == 100
    assert first["feature_version"] == "trustguard-canonical-ledger-v3-research"


def test_missing_feature_version_is_rejected():
    from types import SimpleNamespace
    with pytest.raises(ValueError, match="feature version"):
        evaluation._feature_version(SimpleNamespace())


@pytest.mark.parametrize("label", [0.7, "1", True, 2])
def test_hidden_labels_cannot_be_silently_coerced(label):
    import benchmark_v3_data as data
    row = data.generate_split("validation")[0]
    row["hidden_label"] = label
    with pytest.raises(ValueError, match="hidden_label"):
        evaluation._validate_row(row)


def test_identical_histories_are_not_allowed_across_splits():
    import benchmark_v3_data as data
    row = data.generate_split("training")[0]
    other = copy.deepcopy(row)
    other["id"] = "other-split-id"
    with pytest.raises(ValueError, match="overlap"):
        evaluation._check_split_separation([row], [other])


def test_one_sided_confidence_interval_has_zero_lower_endpoint():
    interval = evaluation.exact_binomial_ci(6, 398, one_sided_upper=True)
    assert interval["lower"] == 0.0
    assert interval["upper"] > 6 / 398


def test_scenario_annotations_use_actual_v3_error_counts():
    import benchmark_v3_data as data
    rows = data.generate_split("validation")[:2]
    rows[0]["hidden_label"] = 0
    rows[1]["hidden_label"] = 1
    metrics = evaluation._scenario_metrics(rows, [0.9, 0.1], 0.8)["routine"]
    assert metrics["confusion_matrix"]["fp"] == 1
    assert metrics["confusion_matrix"]["fn"] == 1
    annotations = metrics["error_annotations"]
    assert annotations["false_positive_scenario"]
    assert annotations["false_negative_scenario"]
    assert annotations["false_positive_count"] == annotations["false_negative_count"] == 1


def test_robustness_executes_supported_boundaries_and_rejects_invalid_inputs():
    import benchmark_v3_data as data
    from risk_candidate_v3 import ResearchIsolationForestV3
    model = ResearchIsolationForestV3("raw").fit(
        [row["features"] for row in data.generate_split("training")], feature_version=data.FEATURE_VERSION)
    result = evaluation._robustness(model, data.generate_split("validation"), 0.8)
    assert result["data_source"] == "independently_generated_synthetic_histories"
    assert result["known_vs_unseen"]["unseen"]["sample_count"] > 0
    assert len(result["boundary_outcomes"]) == 3
    assert all(result["unsupported_input_rejections"].values())
    assert len(result["single_feature_reliance"]["absolute_permutation_auc_changes"]) == 4


def test_pipeline_fits_only_training_features_without_targets(monkeypatch):
    import benchmark_v3_data as data
    from risk_candidate_v3 import ResearchIsolationForestV3
    expected = [row["features"] for row in data.generate_split("training")]
    expected_labels = [row["hidden_label"] for row in data.generate_split("validation")]
    fit_calls, selection_labels = [], []
    original_fit = ResearchIsolationForestV3.fit
    original_select = evaluation.select_validation_threshold

    def fit(self, features, *, feature_version):
        assert features == expected
        assert all(set(row) == set(data.FEATURE_NAMES) for row in features)
        fit_calls.append(self.representation)
        return original_fit(self, features, feature_version=feature_version)

    def select(labels, scores, **kwargs):
        assert list(labels) == expected_labels
        selection_labels.append(list(labels))
        return original_select(labels, scores, **kwargs)

    monkeypatch.setattr(ResearchIsolationForestV3, "fit", fit)
    monkeypatch.setattr(evaluation, "select_validation_threshold", select)
    evaluation.build_report(timestamp=FIXED_TIMESTAMP)
    assert fit_calls == ["raw", "interactions"]
    assert len(selection_labels) == 2


def test_no_valid_candidate_is_frozen_without_generating_holdout(monkeypatch):
    import benchmark_v3_data as data
    original_generate = data.generate_split
    events = []

    def generate(split):
        assert split != "holdout"
        events.append(split)
        return original_generate(split)

    monkeypatch.setattr(data, "generate_split", generate)
    monkeypatch.setattr(evaluation, "select_validation_threshold", lambda *args, **kwargs: {
        "status": "NO_VALID_CANDIDATE", "selected_candidate_threshold": None,
        "selected_validation_metrics": None})
    report = evaluation.build_report(timestamp=FIXED_TIMESTAMP, freeze_callback=lambda record: events.append("freeze"))
    assert events == ["training", "validation", "freeze"]
    assert report["status"] == "NO_VALID_CANDIDATE"
    assert report["selected_candidate_threshold"] is None
    assert report["holdout_metrics"] is None
