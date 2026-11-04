"""Strict, offline evaluator for the TrustGuard canonical-ledger v3 benchmark.

The evaluator deliberately keeps selection and holdout evaluation separate.  It
fits the two pre-registered ResearchIsolationForestV3 configurations on the
training feature rows, selects a configuration and threshold from validation
only, freezes that decision, and scores the generated holdout exactly once.
No report artifact is written by this module.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib
import inspect
import json
import math
import platform
import sys
from typing import Any

import numpy as np
from scipy.stats import beta
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

from risk_calibration import select_validation_threshold
from risk_evaluation import compute_metrics

DATASET_ID = "trustguard-canonical-ledger-v3-research"
FEATURE_VERSION = "trustguard-canonical-ledger-v3-research"
TRAINING_SEED = 20261110
VALIDATION_SEED = 20261111
HOLDOUT_SEED = 20261112
DIAGNOSTIC_SEED = 20261113
MAX_VALIDATION_FPR_DEFAULT = 0.01
BOOTSTRAP_REPLICATES = 100
BOOTSTRAP_SEED = DIAGNOSTIC_SEED
CONFIGS = (
    {"config_id": "raw", "representation": "raw", "random_state": 31001},
    {"config_id": "interactions", "representation": "interactions", "random_state": 31002},
)


# ---------------------------------------------------------------------------
# Small, public statistical helpers


def _as_probability(value: Any, name: str) -> float:
    if isinstance(value, (bool, np.bool_)):
        raise ValueError(f"{name} must be finite and in the range 0..1")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be finite and in the range 0..1") from exc
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be finite and in the range 0..1")
    return result


def exact_binomial_ci(successes: int, trials: int, *, confidence: float = 0.95,
                      one_sided_upper: bool = False) -> dict[str, Any]:
    """Return an exact Clopper--Pearson interval.

    ``trials == 0`` is represented as an undefined interval with an explicit
    reason.  The one-sided upper interval is useful for the preregistered FPR
    bound: with zero false positives out of 160 negatives it is about 0.01855.
    """
    if isinstance(successes, (bool, np.bool_)) or isinstance(trials, (bool, np.bool_)):
        raise ValueError("successes and trials must be integers")
    if not isinstance(successes, (int, np.integer)) or not isinstance(trials, (int, np.integer)):
        raise ValueError("successes and trials must be integers")
    successes, trials = int(successes), int(trials)
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("successes must be between zero and trials")
    confidence = _as_probability(confidence, "confidence")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be strictly between zero and one")
    if trials == 0:
        return {"lower": None, "upper": None, "defined": False,
                "reason": "zero denominator", "method": "exact_clopper_pearson"}
    alpha = 1.0 - confidence
    if one_sided_upper:
        lower = 0.0
        upper = 1.0 if successes == trials else float(beta.ppf(confidence, successes + 1, trials - successes))
    else:
        lower = 0.0 if successes == 0 else float(beta.ppf(alpha / 2.0, successes, trials - successes + 1))
        upper = 1.0 if successes == trials else float(beta.ppf(1.0 - alpha / 2.0, successes + 1, trials - successes))
    return {"lower": lower, "upper": upper, "defined": True,
            "reason": None, "method": "exact_clopper_pearson",
            "confidence": confidence, "successes": successes, "trials": trials,
            "one_sided_upper": bool(one_sided_upper)}


def _metric_intervals(metrics: Mapping[str, Any]) -> dict[str, Any]:
    cm = metrics.get("confusion_matrix", metrics)
    tn, fp, fn, tp = (int(cm.get(k, 0)) for k in ("tn", "fp", "fn", "tp"))
    return {
        "precision": exact_binomial_ci(tp, tp + fp),
        "recall": exact_binomial_ci(tp, tp + fn),
        "false_positive_rate": exact_binomial_ci(fp, fp + tn, one_sided_upper=True),
    }


def _with_intervals(metrics: Mapping[str, Any]) -> dict[str, Any]:
    result = _json_safe(dict(metrics))
    result["confidence_intervals"] = _metric_intervals(result)
    return result


# ---------------------------------------------------------------------------
# Compatibility and deterministic serialization helpers


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        value = float(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite value cannot be serialized")
        return value
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return str(value)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(_json_safe(value), sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _utc_timestamp(timestamp: Any) -> str:
    if timestamp is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(timestamp, datetime):
        value = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(timestamp, str):
        text = timestamp.strip()
        try:
            value = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        if value.utcoffset() == timezone.utc.utcoffset(value):
            return text
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    raise ValueError("timestamp must be None, datetime, or ISO-8601 string")


def _load_data_module() -> Any:
    try:
        return importlib.import_module("benchmark_v3_data")
    except ModuleNotFoundError as exc:
        raise ImportError("benchmark_v3_data.py is required for the v3 evaluation") from exc


def _load_model_class() -> Any:
    try:
        module = importlib.import_module("risk_candidate_v3")
    except ModuleNotFoundError as exc:
        raise ImportError("risk_candidate_v3.py is required for the v3 evaluation") from exc
    try:
        return getattr(module, "ResearchIsolationForestV3")
    except AttributeError as exc:
        raise ImportError("risk_candidate_v3 must export ResearchIsolationForestV3") from exc


def _source_hash(module: Any) -> str:
    try:
        source = inspect.getsource(module)
    except (OSError, TypeError):
        source = getattr(module, "__file__", repr(module))
    return hashlib.sha256(str(source).encode("utf-8")).hexdigest()


def _feature_version(data: Any) -> str:
    value = getattr(data, "FEATURE_VERSION", None)
    if value != FEATURE_VERSION:
        raise ValueError(f"incompatible feature version: {value!r}")
    return FEATURE_VERSION


def _rows_for_split(data: Any, split: str) -> list[dict[str, Any]]:
    generator = getattr(data, "generate_split", None)
    if not callable(generator):
        raise AttributeError("benchmark_v3_data must export generate_split")
    rows = generator(split)
    if isinstance(rows, (str, bytes, bytearray)) or not isinstance(rows, Sequence) or not rows:
        raise ValueError(f"{split} split must be a non-empty sequence")
    copied = [dict(row) for row in rows]
    for row in copied:
        _validate_row(row)
    return copied


def _validate_row(row: Mapping[str, Any]) -> None:
    required = {"id", "scenario", "description", "hidden_label", "features", "history", "latent_context"}
    if not isinstance(row, Mapping) or not required.issubset(row):
        raise ValueError("v3 row has an incomplete schema")
    if not isinstance(row["id"], str) or not row["id"]:
        raise ValueError("v3 row id is invalid")
    label = row["hidden_label"]
    if label is not None and (isinstance(label, (bool, np.bool_))
                              or not isinstance(label, (int, np.integer)) or label not in (0, 1)):
        raise ValueError("hidden_label must be 0, 1, or None")
    features = row["features"]
    data = _load_data_module()
    validator = getattr(data, "validate_features", None)
    if not callable(validator):
        raise AttributeError("benchmark_v3_data must export validate_features")
    validator(features)


def _features(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row["features"]) for row in rows]


def _fingerprint(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    feature_records = [_json_safe(row["features"]) for row in rows]
    row_hashes = [_sha256(item) for item in feature_records]
    return {"count": len(rows), "feature_row_hashes": row_hashes,
            "feature_row_hashes_sha256": _sha256(row_hashes),
            "feature_matrix_sha256": _sha256(feature_records)}


def _same_history(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    return _canonical_json(a.get("history")) == _canonical_json(b.get("history"))


def _check_split_separation(training: Sequence[Mapping[str, Any]], validation: Sequence[Mapping[str, Any]],
                            holdout: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    splits: dict[str, Sequence[Mapping[str, Any]]] = {"training": training, "validation": validation}
    if holdout is not None:
        splits["holdout"] = holdout
    fingerprints = {name: _fingerprint(rows) for name, rows in splits.items()}
    warnings: list[str] = []
    overlaps: dict[str, int] = {}
    names = list(splits)
    for left_index, left_name in enumerate(names):
        for right_name in names[left_index + 1:]:
            left_rows, right_rows = splits[left_name], splits[right_name]
            left_hashes = {h: row for h, row in zip(fingerprints[left_name]["feature_row_hashes"], left_rows)}
            right_hashes = {h: row for h, row in zip(fingerprints[right_name]["feature_row_hashes"], right_rows)}
            common = set(left_hashes) & set(right_hashes)
            overlaps[f"{left_name}_{right_name}"] = len(common)
            if common:
                raise ValueError(f"exact feature-row overlap detected between {left_name} and {right_name}")
    fingerprints["cross_split_overlap"] = overlaps
    fingerprints["overlap_warnings"] = warnings
    return fingerprints


# ---------------------------------------------------------------------------
# Model orchestration


def _new_model(config: Mapping[str, Any]) -> Any:
    cls = _load_model_class()
    kwargs = {"representation": config["representation"]}
    try:
        return cls(**kwargs)
    except TypeError:
        try:
            return cls(config["representation"])
        except TypeError as exc:
            raise TypeError("ResearchIsolationForestV3 must accept representation") from exc


def _fit_model(model: Any, training_features: Sequence[Mapping[str, Any]]) -> Any:
    fit = getattr(model, "fit", None)
    if not callable(fit):
        raise TypeError("ResearchIsolationForestV3 must expose fit")
    try:
        fitted = fit(list(training_features), feature_version=FEATURE_VERSION)
    except TypeError:
        raise TypeError("v3 fit must accept features and feature_version")
    return model if fitted is None else fitted


def _metadata(model: Any, config: Mapping[str, Any], training_features: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    getter = getattr(model, "metadata", None)
    if not callable(getter):
        raise ValueError("v3 model metadata() is required")
    metadata = _json_safe(getter())
    if not isinstance(metadata, dict):
        raise ValueError("v3 metadata must be a mapping")
    # Strict compatibility is intentional: a mismatched model is rejected,
    # never silently replaced by another representation or legacy model.
    validator = getattr(model, "validate_metadata", None)
    if callable(validator):
        validator(metadata)
    elif metadata.get("model_version") != "trustguard-isolation-forest-synthetic-v3-research":
        raise ValueError("candidate metadata model version mismatch")
    if metadata.get("model_version") != "trustguard-isolation-forest-synthetic-v3-research":
        raise ValueError("candidate metadata model version mismatch")
    representation = metadata.get("representation", metadata.get("feature_representation"))
    feature_version = metadata.get("feature_version", metadata.get("features_version"))
    if representation != config["representation"]:
        raise ValueError("candidate metadata representation mismatch")
    if feature_version != FEATURE_VERSION:
        raise ValueError("candidate metadata feature version mismatch")
    hyperparameters = metadata.get("hyperparameters", {})
    n_estimators = metadata.get("n_estimators", metadata.get("trees", hyperparameters.get("n_estimators", 128)))
    if n_estimators != 128:
        raise ValueError("candidate metadata must declare 128 trees")
    seed = metadata.get("random_state", metadata.get("seed", hyperparameters.get("random_state")))
    if seed is not None and int(seed) != int(config["random_state"]):
        raise ValueError("candidate metadata random seed mismatch")
    metadata.setdefault("representation", config["representation"])
    metadata.setdefault("feature_version", FEATURE_VERSION)
    metadata["fit_data_scope"] = "training_features_only"
    metadata["labels_used_for_fit"] = False
    metadata["training_row_count"] = len(training_features)
    metadata["config_id"] = config["config_id"]
    return metadata


def _score_many(model: Any, features: Sequence[Mapping[str, Any]]) -> np.ndarray:
    scorer = getattr(model, "score_many", None)
    if not callable(scorer):
        raise TypeError("v3 model must expose score_many")
    try:
        values = scorer(list(features), feature_version=FEATURE_VERSION)
    except TypeError:
        raise TypeError("v3 score_many must accept features and feature_version")
    values = np.asarray(values, dtype="float64")
    if values.ndim != 1 or values.shape[0] != len(features) or not np.isfinite(values).all() or not ((values >= 0.0) & (values <= 1.0)).all():
        raise ValueError("v3 model returned invalid scores")
    return values


def _labels(rows: Sequence[Mapping[str, Any]]) -> list[int]:
    if any(row["hidden_label"] is None for row in rows):
        raise ValueError("selection requires complete validation labels")
    return [int(row["hidden_label"]) for row in rows]


def _missing_label_metrics(rows: Sequence[Mapping[str, Any]], scores: Sequence[float], threshold: float) -> dict[str, Any]:
    present = [(int(row["hidden_label"]), float(score)) for row, score in zip(rows, scores) if row["hidden_label"] is not None]
    if not present:
        return {"sample_count": len(rows), "labeled_count": 0, "metrics": None,
                "undefined_reasons": {"all_metrics": "no labels"}}
    labels, values = zip(*present)
    result = _with_intervals(compute_metrics(labels, values, threshold=threshold))
    result["sample_count"] = len(rows)
    result["labeled_count"] = len(present)
    if len(present) != len(rows):
        result.setdefault("undefined_reasons", {})["missing_labels"] = "some labels missing"
    return result


def _scenario_metrics(rows: Sequence[Mapping[str, Any]], scores: Sequence[float], threshold: float) -> dict[str, Any]:
    scenarios: dict[str, Any] = {}
    for scenario in sorted({str(row["scenario"]) for row in rows}):
        selected = [i for i, row in enumerate(rows) if row["scenario"] == scenario]
        scenarios[scenario] = _missing_label_metrics([rows[i] for i in selected], [scores[i] for i in selected], threshold)
        metrics = scenarios[scenario].get("metrics") or scenarios[scenario]
        cm = metrics.get("confusion_matrix", {})
        scenarios[scenario]["error_annotations"] = {
            "false_positive_scenario": int(cm.get("fp", 0)) > 0,
            "false_negative_scenario": int(cm.get("fn", 0)) > 0,
            "false_positive_count": int(cm.get("fp", 0)),
            "false_negative_count": int(cm.get("fn", 0)),
            "synthetic_scenario_note": "scenario labels are generated assumptions, not real fraud outcomes",
        }
    return scenarios


def _bootstrap_ci(labels: Sequence[int], scores: Sequence[float], threshold: float) -> dict[str, Any]:
    labels, scores = list(labels), list(scores)
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    values = {"f1": [], "roc_auc": [], "average_precision": []}
    if len(set(labels)) < 2:
        return {name: {"lower": None, "upper": None, "defined": False, "reason": "single-class labels", "method": "deterministic iid bootstrap", "replicates": BOOTSTRAP_REPLICATES} for name in values}
    for _ in range(BOOTSTRAP_REPLICATES):
        indexes = rng.integers(0, len(labels), size=len(labels))
        sampled_labels = [labels[int(i)] for i in indexes]
        sampled_scores = [scores[int(i)] for i in indexes]
        metrics = compute_metrics(sampled_labels, sampled_scores, threshold=threshold)
        if metrics["f1"] is not None:
            values["f1"].append(float(metrics["f1"]))
        if len(set(sampled_labels)) >= 2:
            values["roc_auc"].append(float(roc_auc_score(sampled_labels, sampled_scores)))
        if any(sampled_labels):
            values["average_precision"].append(float(average_precision_score(sampled_labels, sampled_scores)))
    output: dict[str, Any] = {}
    for name, samples in values.items():
        output[name] = {
            "lower": float(np.quantile(samples, 0.025)) if samples else None,
            "upper": float(np.quantile(samples, 0.975)) if samples else None,
            "defined": bool(samples),
            "reason": None if samples else "all bootstrap replicates undefined",
            "method": "deterministic iid bootstrap",
            "replicates": BOOTSTRAP_REPLICATES,
            "seed": BOOTSTRAP_SEED,
        }
    return output


def _ranking_metrics(labels: Sequence[int], scores: Sequence[float]) -> dict[str, Any]:
    if len(set(labels)) < 2:
        return {"roc_auc": None, "average_precision": None, "undefined_reasons": {"roc_auc": "single-class labels", "average_precision": "zero or single-class labels"}}
    return {"roc_auc": float(roc_auc_score(labels, scores)), "average_precision": float(average_precision_score(labels, scores)), "undefined_reasons": {"roc_auc": None, "average_precision": None}}


def _diagnostic_rows(data: Any, validation_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    for name in ("generate_diagnostic_split", "generate_diagnostics", "generate_diagnostic_data"):
        fn = getattr(data, name, None)
        if callable(fn):
            try:
                rows = fn(seed=DIAGNOSTIC_SEED)
            except TypeError:
                rows = fn()
            if rows:
                return [dict(row) for row in rows]
    raise AttributeError("v3 requires separately seeded diagnostic data; validation fallback is forbidden")


def _robustness(model: Any, validation_rows: Sequence[Mapping[str, Any]], threshold: float) -> dict[str, Any]:
    rows = _diagnostic_rows(_load_data_module(), validation_rows)
    for row in rows:
        _validate_row(row)
    base_features = _features(rows)
    base_scores = _score_many(model, base_features)
    labels = [row["hidden_label"] for row in rows]
    labeled_indexes = [i for i, label in enumerate(labels) if label is not None]
    known_scenarios = {row["scenario"] for row in validation_rows}
    known_idx = [i for i, row in enumerate(rows) if row["scenario"] in known_scenarios]
    unseen_idx = [i for i, row in enumerate(rows) if row["scenario"] not in known_scenarios]
    result: dict[str, Any] = {
        "seed": DIAGNOSTIC_SEED,
        "sample_count": len(rows),
        "data_source": "independently_generated_synthetic_histories",
        "label_source": "original synthetic diagnostic labels retained; no labels fabricated",
        "known_vs_unseen": {
            "known": _missing_label_metrics([rows[i] for i in known_idx], [base_scores[i] for i in known_idx], threshold),
            "unseen": _missing_label_metrics([rows[i] for i in unseen_idx], [base_scores[i] for i in unseen_idx], threshold) if unseen_idx else {"sample_count": 0, "metrics": None, "undefined_reasons": {"all_metrics": "no unseen diagnostic rows"}},
        },
        "contract_checks": {
            "new_domain_boundaries": {"amount_minor_min": 1, "ratio_max": 1.0, "new_payee_values": [0, 1]},
            "ood_inputs_separate_from_errors": True,
        },
        "ablations": {},
        "permutation": {},
        "simple_old_rule": {"rule": "cumulative_spending_ratio >= 0.8 OR recent_velocity_ratio >= 0.8", "accuracy": None, "note": "diagnostic synthetic rule; expected to be imperfect"},
    }
    feature_names = list(base_features[0]) if base_features else []
    for name in feature_names:
        altered = [dict(features) for features in base_features]
        for feature in altered:
            value = float(feature[name])
            if name == "amount_to_grant_ratio":
                feature[name] = 0.0001
                feature["cumulative_spending_ratio"] = max(
                    float(feature["cumulative_spending_ratio"]), 0.0001
                )
            elif name == "cumulative_spending_ratio":
                feature[name] = max(float(feature["amount_to_grant_ratio"]), 0.0001)
            else:
                feature[name] = 0.0
        scores = _score_many(model, altered)
        flips = int(sum((base_scores[i] >= threshold) != (scores[i] >= threshold) for i in range(len(rows))))
        base_rank = _ranking_metrics([int(labels[i]) for i in labeled_indexes], [float(base_scores[i]) for i in labeled_indexes]) if labeled_indexes and all(labels[i] is not None for i in labeled_indexes) else {}
        altered_rank = _ranking_metrics([int(labels[i]) for i in labeled_indexes], [float(scores[i]) for i in labeled_indexes]) if labeled_indexes and all(labels[i] is not None for i in labeled_indexes) else {}
        result["ablations"][name] = {"score_delta_mean": float(np.mean(scores - base_scores)), "decision_flips": flips, "delta_roc_auc": (None if base_rank.get("roc_auc") is None or altered_rank.get("roc_auc") is None else float(altered_rank["roc_auc"] - base_rank["roc_auc"])), "note": "reliance diagnostic; no causal claim"}
        permuted = [dict(features) for features in base_features]
        if len(permuted) > 1:
            rotated = [feature[name] for feature in permuted[1:]] + [permuted[0][name]]
            for feature, value in zip(permuted, rotated, strict=True):
                feature[name] = value
            if name == "amount_to_grant_ratio":
                for feature in permuted:
                    feature[name] = min(float(feature[name]), float(feature["cumulative_spending_ratio"]))
            elif name == "cumulative_spending_ratio":
                for feature in permuted:
                    feature[name] = max(float(feature[name]), float(feature["amount_to_grant_ratio"]))
            permuted_scores = _score_many(model, permuted)
            permuted_flips = int(sum((base_scores[i] >= threshold) != (permuted_scores[i] >= threshold) for i in range(len(rows))))
            permuted_rank = _ranking_metrics([int(labels[i]) for i in labeled_indexes], [float(permuted_scores[i]) for i in labeled_indexes]) if labeled_indexes and all(labels[i] is not None for i in labeled_indexes) else {}
            permuted_delta = None if base_rank.get("roc_auc") is None or permuted_rank.get("roc_auc") is None else float(permuted_rank["roc_auc"] - base_rank["roc_auc"])
        else:
            permuted_delta, permuted_flips = None, 0
        result["permutation"][name] = {"delta_roc_auc": permuted_delta, "decision_flips": permuted_flips, "note": "deterministic synthetic permutation diagnostic; no causal claim"}
    # Perturb copied histories, preserving exact minor units and saturation at five.
    data = _load_data_module()
    jittered, velocity_changed = [], []
    for i, row in enumerate(rows):
        history = deepcopy(row["history"])
        active = [prior for prior in history["prior_transactions"]
                  if prior["status"] in data.ACTIVE_STATES
                  and prior["grant_id"] == history["grantid"] and prior["currency"] == history["currency"]
                  and prior["transaction_id"] != history["currenttxid"]]
        used = sum(prior["amount_minor"] for prior in active)
        old_amount = history["amount_minor"]
        history["amount_minor"] = max(1, min(history["grantlimit_minor"] - used,
            round(old_amount * (1.005 if i % 2 else 0.995))))
        jittered.append(data.features_from_history(history))
        history = deepcopy(row["history"])
        deadline = history["now"] - 600.0
        if i % 2 == 0:
            older = next((prior for prior in history["prior_transactions"]
                          if prior["status"] in data.ACTIVE_STATES and prior["created_at"] < deadline), None)
            if older is not None:
                older["created_at"] = history["now"] - 1.0
            elif used + old_amount < history["grantlimit_minor"]:
                history["prior_transactions"].append({"transaction_id": f"diagnostic-added-{i}",
                    "grant_id": history["grantid"], "currency": history["currency"],
                    "paypal_merchant_id": None, "skyfire_service_id": None, "payee": "synthetic-diagnostic-other",
                    "amount_minor": 1, "created_at": history["now"] - 1.0, "status": "RESERVED"})
        else:
            recent = next((prior for prior in history["prior_transactions"]
                           if prior["status"] in data.ACTIVE_STATES and prior["created_at"] >= deadline), None)
            if recent is not None:
                recent["created_at"] = deadline - 1.0
        velocity_changed.append(data.features_from_history(history))
    result["contract_perturbations"] = {"small_ratio_jitter": {"score_delta_mean": float(np.mean(_score_many(model, jittered) - base_scores))}, "velocity_one_count_change": {"score_delta_mean": float(np.mean(_score_many(model, velocity_changed) - base_scores))}}
    old_rule = [int(float(row["features"]["cumulative_spending_ratio"]) >= 0.8 or float(row["features"]["recent_velocity_ratio"]) >= 0.8) for row in rows]
    old_labeled = [(prediction, int(labels[i])) for i, prediction in enumerate(old_rule) if labels[i] is not None]
    result["simple_old_rule"]["accuracy"] = (float(sum(prediction == label for prediction, label in old_labeled) / len(old_labeled)) if old_labeled else None)
    result["new_domain_boundaries"] = {
        "amount_to_grant_ratio": [0.0001, 1.0],
        "cumulative_spending_ratio": [0.0001, 1.0],
        "recent_velocity_ratio": [0.0, 1.0],
        "new_payee": [0.0, 1.0],
        "ood_flags": [model.ood_features({"amount_to_grant_ratio": 0.0001, "cumulative_spending_ratio": 0.0001, "recent_velocity_ratio": 0.0, "new_payee": 0.0}, feature_version=FEATURE_VERSION), model.ood_features({"amount_to_grant_ratio": 1.0, "cumulative_spending_ratio": 1.0, "recent_velocity_ratio": 1.0, "new_payee": 1.0}, feature_version=FEATURE_VERSION)],
    }
    boundaries = [
        {"amount_to_grant_ratio": 0.0001, "cumulative_spending_ratio": 0.0002, "recent_velocity_ratio": 0.0, "new_payee": 0.0},
        {"amount_to_grant_ratio": 1.0, "cumulative_spending_ratio": 1.0, "recent_velocity_ratio": 0.0, "new_payee": 1.0},
        {"amount_to_grant_ratio": 0.01, "cumulative_spending_ratio": 1.0, "recent_velocity_ratio": 1.0, "new_payee": 0.0},
    ]
    boundary_scores = _score_many(model, boundaries)
    result["boundary_outcomes"] = [{"features": features, "score": float(value), "screening_decision": "HOLD" if value >= threshold else "ALLOW"}
                                  for features, value in zip(boundaries, boundary_scores, strict=True)]
    valid = dict(base_features[0])
    unsupported = {
        "zero_amount": {**valid, "amount_to_grant_ratio": 0.0},
        "nonfinite_amount": {**valid, "amount_to_grant_ratio": float("nan")},
        "nonledger_velocity": {**valid, "recent_velocity_ratio": 0.1},
        "nonbinary_payee": {**valid, "new_payee": 0.5},
        "hidden_label_in_features": {**valid, "hidden_label": 1},
    }
    result["unsupported_input_rejections"] = {}
    for name, features in unsupported.items():
        try:
            _score_many(model, [features])
        except (ValueError, TypeError):
            result["unsupported_input_rejections"][name] = True
        else:
            raise ValueError(f"v3 scorer accepted unsupported diagnostic input: {name}")
    reliance = {name: abs(values["delta_roc_auc"]) for name, values in result["permutation"].items()
                if values["delta_roc_auc"] is not None}
    result["single_feature_reliance"] = {"absolute_permutation_auc_changes": reliance,
        "largest_change_feature": max(reliance, key=reliance.get) if reliance else None,
        "interpretation": "dependence diagnostic, not causal attribution or a production validity test"}
    result["ood_flags"] = {"in_domain": "inputs within feature validation bounds", "out_of_domain": "unsupported inputs must be flagged separately and not converted into labels"}
    return result


# ---------------------------------------------------------------------------
# Main report


def build_report(timestamp: Any = None, max_validation_fpr: float = MAX_VALIDATION_FPR_DEFAULT,
                 freeze_callback: Any = None) -> dict[str, Any]:
    """Build a deterministic v3 report without writing an artifact."""
    ceiling = _as_probability(max_validation_fpr, "max_validation_fpr")
    if ceiling < 0.0 or ceiling > 1.0:
        raise ValueError("max_validation_fpr must be in the range 0..1")
    data = _load_data_module()
    _feature_version(data)
    timestamp_value = _utc_timestamp(timestamp)
    training_rows = _rows_for_split(data, "training")
    validation_rows = _rows_for_split(data, "validation")
    training_features = _features(training_rows)
    validation_features = _features(validation_rows)
    _check_split_separation(training_rows, validation_rows)
    models: dict[str, Any] = {}
    candidate_metadata: dict[str, Any] = {}
    selections: dict[str, Any] = {}
    validation_scores: dict[str, np.ndarray] = {}
    labels = _labels(validation_rows)
    for config in CONFIGS:
        model = _fit_model(_new_model(config), training_features)
        models[config["config_id"]] = model
        candidate_metadata[config["config_id"]] = _metadata(model, config, training_features)
        validation_scores[config["config_id"]] = _score_many(model, validation_features)
        selections[config["config_id"]] = select_validation_threshold(labels, validation_scores[config["config_id"]], max_fpr=ceiling)
    feasible = []
    for config in CONFIGS:
        selection = selections[config["config_id"]]
        if selection.get("status") == "SELECTED":
            metrics = selection.get("selected_validation_metrics") or {}
            feasible.append((config, selection, metrics))
    selected_config = None
    selected_selection = None
    selected_metadata = None
    if feasible:
        selected_config, selected_selection, selected_metrics = min(
            feasible,
            key=lambda item: (-float(item[2]["recall"]), float(item[2]["false_positive_rate"]), item[0]["config_id"], -float(item[1]["selected_candidate_threshold"])),
        )
        selected_metadata = candidate_metadata[selected_config["config_id"]]
    status = "SELECTED" if selected_config is not None else "NO_VALID_CANDIDATE"
    source_hashes = {"benchmark_v3_data": _source_hash(data),
        "risk_candidate_v3": _source_hash(importlib.import_module("risk_candidate_v3")),
        "benchmark_v3_evaluation": _source_hash(sys.modules[__name__]),
        "risk_calibration_selector": _source_hash(importlib.import_module("risk_calibration"))}
    freeze_record: dict[str, Any] = {
        "status": status,
        "timestamp": timestamp_value,
        "feature_version": FEATURE_VERSION,
        "selected_representation": None if selected_config is None else selected_config["representation"],
        "selected_candidate_threshold": None if selected_selection is None else selected_selection["selected_candidate_threshold"],
        "selected_config_id": None if selected_config is None else selected_config["config_id"],
        "candidate_model_metadata": selected_metadata,
        "dataset_fingerprints": {"training": _fingerprint(training_rows), "validation": _fingerprint(validation_rows)},
        "seeds": {"training": TRAINING_SEED, "validation": VALIDATION_SEED, "holdout": HOLDOUT_SEED, "diagnostics": DIAGNOSTIC_SEED},
        "source_module_hashes": source_hashes,
        "preregistered_configs": list(CONFIGS),
        "generator_metadata": data.metadata(),
        "unseen_joint_region_definition": "cumulative_spending_ratio > 0.90 and recent_velocity_ratio == 1.0; absent from training templates",
        "generator_assumptions": "Fixed v3 synthetic canonical-ledger generator; training/validation are generated before selection and holdout is generated only after freeze.",
    }
    freeze_digest = _sha256(freeze_record)
    freeze_record["freeze_digest_sha256"] = freeze_digest
    if freeze_callback is not None:
        if not callable(freeze_callback):
            raise TypeError("freeze_callback must be callable")
        # The CLI persists a versioned freeze artifact for both successful and
        # explicit NO_VALID_CANDIDATE runs.  This callback is always before any
        # possible holdout generation.
        freeze_callback(deepcopy(freeze_record))
    holdout_rows: list[dict[str, Any]] | None = None
    holdout_metrics: dict[str, Any] | None = None
    per_scenario: dict[str, Any] | None = None
    robustness: dict[str, Any] | None = None
    holdout_fingerprint: dict[str, Any] | None = None
    if selected_config is not None:
        holdout_rows = _rows_for_split(data, "holdout")
        all_fingerprints = _check_split_separation(training_rows, validation_rows, holdout_rows)
        holdout_fingerprint = all_fingerprints["holdout"]
        scores = _score_many(models[selected_config["config_id"]], _features(holdout_rows))
        holdout_labels = _labels(holdout_rows)
        threshold = float(selected_selection["selected_candidate_threshold"])
        holdout_metrics = _with_intervals(compute_metrics(holdout_labels, scores, threshold=threshold))
        holdout_metrics["bootstrap_confidence_intervals"] = _bootstrap_ci(holdout_labels, scores, threshold)
        holdout_metrics["ranking_metrics"] = _ranking_metrics(holdout_labels, scores)
        per_scenario = _scenario_metrics(holdout_rows, scores, threshold)
        known_scenarios = {row["scenario"] for row in training_rows + validation_rows}
        known = [i for i, row in enumerate(holdout_rows) if row["scenario"] in known_scenarios]
        unseen = [i for i, row in enumerate(holdout_rows) if row["scenario"] not in known_scenarios]
        holdout_metrics["known_vs_unseen"] = {
            "known": _missing_label_metrics([holdout_rows[i] for i in known], [scores[i] for i in known], threshold),
            "unseen": _missing_label_metrics([holdout_rows[i] for i in unseen], [scores[i] for i in unseen], threshold),
        }
        holdout_metrics["known_vs_unseen"]["definition"] = "scenario names absent from training/validation; not a guarantee of feature-support OOD"
        joint_region = [i for i, row in enumerate(holdout_rows)
                        if row["features"]["cumulative_spending_ratio"] > 0.90
                        and row["features"]["recent_velocity_ratio"] == 1.0]
        holdout_metrics["unseen_joint_region"] = _missing_label_metrics(
            [holdout_rows[i] for i in joint_region], [scores[i] for i in joint_region], threshold)
        robustness = _robustness(models[selected_config["config_id"]], validation_rows, threshold)
    validation_comparison = {
        config["config_id"]: {
            "representation": config["representation"],
            "selection": selections[config["config_id"]],
            "metadata": candidate_metadata[config["config_id"]],
        }
        for config in CONFIGS
    }
    report = {
        "dataset_id": DATASET_ID,
        "status": status,
        "selected_representation": None if selected_config is None else selected_config["representation"],
        "selected_candidate_threshold": None if selected_selection is None else selected_selection["selected_candidate_threshold"],
        "feature_version": FEATURE_VERSION,
        "training_count": len(training_rows),
        "validation_count": len(validation_rows),
        "holdout_count": None if holdout_rows is None else len(holdout_rows),
        "counts": {"training": len(training_rows), "validation": len(validation_rows), "holdout": None if holdout_rows is None else len(holdout_rows)},
        "seeds": {"training": TRAINING_SEED, "validation": VALIDATION_SEED, "holdout": HOLDOUT_SEED, "diagnostics": DIAGNOSTIC_SEED},
        "validation_comparison": validation_comparison,
        "holdout_metrics": holdout_metrics,
        "confidence_intervals": None if holdout_metrics is None else holdout_metrics["confidence_intervals"],
        "per_scenario": per_scenario,
        "candidate_model_metadata": selected_metadata,
        "candidate_models_metadata": candidate_metadata,
        "freeze_record": freeze_record,
        "freeze_digest_sha256": freeze_digest,
        "dataset_fingerprints": {"training": freeze_record["dataset_fingerprints"]["training"], "validation": freeze_record["dataset_fingerprints"]["validation"], "holdout": holdout_fingerprint},
        "robustness": robustness,
        "generator_assumptions": freeze_record["generator_assumptions"],
        "provenance": {"source_module_hashes": source_hashes, "prior_v2_audit": "v2 candidate audit findings are historical context only; no v2 artifact or holdout is reused", "provenance_version": "v3-evaluation-provenance-1"},
        "methodology": "Synthetic reference benchmark only; intervals assume iid binomial/bootstrap sampling and are nominal summaries, not guarantees for a real population. Scenario strata, shared counterpart features and forced opposite-label pairs limit iid interpretation. No causal claim is made from ablations. Candidate/threshold and training/validation/holdout labels are not retuned from final holdout outcomes.",
        "timestamp": timestamp_value,
        "runtime": {"python": platform.python_version(), "numpy": np.__version__, "sklearn": __import__("sklearn").__version__},
    }
    return _json_safe(report)


__all__ = [
    "BOOTSTRAP_REPLICATES", "CONFIGS", "DIAGNOSTIC_SEED", "FEATURE_VERSION",
    "HOLDOUT_SEED", "MAX_VALIDATION_FPR_DEFAULT", "TRAINING_SEED", "VALIDATION_SEED",
    "build_report", "exact_binomial_ci",
]
