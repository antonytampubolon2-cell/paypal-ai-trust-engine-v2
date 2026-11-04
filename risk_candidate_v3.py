"""Research-only TrustGuard v3 IsolationForest ranking candidate.

The canonical v3 ledger schema is the existing four-field raw schema, validated
by ``benchmark_v3_data`` when that benchmark module is available.  Historical
v2 work used the raw-schema identifier ``trusted-risk-features-v1`` in one place
and ``trusted-upper-tail-marginals-v2`` as a representation identifier in another; those
names are historical context only and are deliberately not accepted or emitted
by this v3 implementation.  This module never loads old training data, labels,
scenario rows, holdout splits, or production scorer registrations.

Fitting is explicit: construct a model, then call ``fit(training_features,
feature_version=FEATURE_VERSION)``.  The estimator is unsupervised and receives
only a numeric feature matrix.  Scores are bounded anomaly rankings, not policy
decisions or calibrated probabilities.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import math
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from benchmark_v3_data import (
    FEATURE_NAMES,
    FEATURE_VERSION as _BENCHMARK_FEATURE_VERSION,
    validate_features as _benchmark_validate_features,
)

FEATURE_VERSION = "trustguard-canonical-ledger-v3-research"
MODEL_VERSION = "trustguard-isolation-forest-synthetic-v3-research"
RAW_FEATURE_NAMES = FEATURE_NAMES
INTERACTION_FEATURE_NAMES = (
    "amount_to_grant_ratio",
    "cumulative_spending_ratio",
    "recent_velocity_ratio",
    "new_payee",
    "amount_to_cumulative_ratio",
    "cumulative_velocity_interaction",
    "new_payee_velocity_interaction",
)
VALID_REPRESENTATIONS = ("raw", "interactions")
N_ESTIMATORS = 128
CONTAMINATION = 0.04
N_JOBS = 1
MAX_SAMPLES_CAP = 256
SIGMOID_SCALE = 8.0
RAW_RANDOM_STATE = 31001
INTERACTIONS_RANDOM_STATE = 31002
RANDOM_STATES = {"raw": RAW_RANDOM_STATE, "interactions": INTERACTIONS_RANDOM_STATE}
VELOCITY_VALUES = frozenset((0.0, 0.2, 0.4, 0.6, 0.8, 1.0))

__all__ = [
    "CONTAMINATION",
    "FEATURE_NAMES",
    "FEATURE_VERSION",
    "INTERACTION_FEATURE_NAMES",
    "INTERACTIONS_RANDOM_STATE",
    "MAX_SAMPLES_CAP",
    "MODEL_VERSION",
    "N_ESTIMATORS",
    "N_JOBS",
    "RAW_RANDOM_STATE",
    "RAW_FEATURE_NAMES",
    "ResearchIsolationForestV3",
    "SIGMOID_SCALE",
    "validate_features",
    "validate_metadata",
]


def _is_number(value: Any) -> bool:
    """Return whether *value* is a supported non-boolean finite-number type."""
    return isinstance(value, (int, float, np.integer, np.floating)) and not isinstance(
        value, (bool, np.bool_)
    )


def _canonical_feature_vector(features: Mapping[str, Any]) -> np.ndarray:
    """Validate one canonical v3 mapping and return it in fixed column order."""
    if not isinstance(features, Mapping) or set(features) != set(FEATURE_NAMES):
        raise ValueError("features must contain exactly the canonical four v3 fields")

    values: list[float] = []
    for name in FEATURE_NAMES:
        value = features[name]
        if not _is_number(value):
            raise ValueError(f"feature {name!r} must be a non-boolean number")
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"feature {name!r} must be finite")
        values.append(number)

    amount, cumulative, velocity, new_payee = values
    if not (0.0 < amount <= 1.0):
        raise ValueError("amount_to_grant_ratio must satisfy 0 < amount <= 1")
    if not (amount <= cumulative <= 1.0):
        raise ValueError("cumulative_spending_ratio must satisfy amount <= cumulative <= 1")
    if velocity not in VELOCITY_VALUES:
        raise ValueError("recent_velocity_ratio must be one of 0, .2, .4, .6, .8, or 1")
    if new_payee not in (0.0, 1.0):
        raise ValueError("new_payee must be exactly 0 or 1")
    return np.asarray(values, dtype=np.float64)


def _validate_one(features: Mapping[str, Any]) -> np.ndarray:
    """Apply the workstream validator plus local checks that enforce the contract."""
    vector = _canonical_feature_vector(features)
    if not callable(_benchmark_validate_features):
        raise ValueError("canonical v3 feature validator is unavailable")
    try:
        result = _benchmark_validate_features(dict(features))
    except (TypeError, ValueError, KeyError, AssertionError) as exc:
        raise ValueError("features fail benchmark_v3_data validation") from exc
    if result is not True:
        raise ValueError("features fail benchmark_v3_data validation")
    return vector


def validate_features(features: Mapping[str, Any]) -> bool:
    """Validate the exact canonical v3 feature mapping.

    ``True`` is returned for convenience; malformed mappings raise ``ValueError``.
    The function intentionally does not normalize, impute, or clip caller data.
    """
    _validate_one(features)
    return True


def _require_feature_version(feature_version: Any) -> None:
    if feature_version != FEATURE_VERSION:
        raise ValueError(
            f"unsupported feature_version; expected {FEATURE_VERSION!r}"
        )
    # If the benchmark module is present, a disagreement is an implementation
    # error rather than a reason to silently accept another version.
    if _BENCHMARK_FEATURE_VERSION != FEATURE_VERSION:
        raise ValueError("benchmark_v3_data FEATURE_VERSION is incompatible")


def _interaction_vector(raw: np.ndarray) -> np.ndarray:
    amount, cumulative, velocity, new_payee = (float(value) for value in raw)
    return np.asarray(
        (
            amount,
            cumulative,
            velocity,
            new_payee,
            amount / cumulative,
            cumulative * velocity,
            new_payee * velocity,
        ),
        dtype=np.float64,
    )


def _raw_matrix_from_training(training_features: Any) -> np.ndarray:
    """Accept only an Nx4 numeric matrix or a non-empty list of feature mappings."""
    if training_features is None or isinstance(training_features, Mapping):
        raise ValueError("training_features must be a non-empty matrix or list of features")
    if isinstance(training_features, (str, bytes)):
        raise ValueError("training_features must be a non-empty matrix or list of features")

    try:
        rows = list(training_features)
    except (TypeError, ValueError) as exc:
        raise ValueError("training_features must be iterable") from exc
    if not rows:
        raise ValueError("training_features must not be empty")

    if all(isinstance(row, Mapping) for row in rows):
        matrix = np.vstack([_validate_one(row) for row in rows])
        return np.ascontiguousarray(matrix, dtype=np.float64)
    if any(isinstance(row, Mapping) for row in rows):
        raise ValueError("training_features cannot mix mappings and numeric rows")

    # Check nested values before np.asarray: a mixed list such as
    # ``[[0.1, 0.2, 0.2, True], ...]`` otherwise gets silently coerced to
    # float64 and loses the fact that the caller supplied a boolean.
    for row in rows:
        if isinstance(row, (str, bytes)):
            raise ValueError("training_features must be numeric")
        try:
            if any(isinstance(value, (bool, np.bool_)) for value in row):
                raise ValueError("boolean training feature values are invalid")
        except TypeError:
            pass

    # Reject boolean matrices before float conversion (which would otherwise
    # silently turn True/False into 1/0).  Conversion also rejects strings and
    # ragged rows without allowing hidden label/scenario fields.
    try:
        raw = np.asarray(rows)
    except (TypeError, ValueError) as exc:
        raise ValueError("training_features must be numeric") from exc
    if raw.ndim != 2 or raw.shape[0] == 0 or raw.shape[1] != len(FEATURE_NAMES):
        raise ValueError("training matrix must be a non-empty Nx4 matrix")
    if raw.dtype.kind == "b":
        raise ValueError("boolean training feature values are invalid")
    if raw.dtype.kind == "O" and any(
        isinstance(value, (bool, np.bool_)) for value in raw.flat
    ):
        raise ValueError("boolean training feature values are invalid")
    try:
        numeric = np.asarray(raw, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise ValueError("training_features must be numeric") from exc
    if not np.isfinite(numeric).all():
        raise ValueError("training feature values must be finite")
    # Run row-level validation so matrix input has exactly the same domains and
    # relational constraints as mapping input.
    validated = np.vstack(
        [
            _validate_one(dict(zip(FEATURE_NAMES, row, strict=True)))
            for row in numeric
        ]
    )
    return np.ascontiguousarray(validated, dtype=np.float64)


def _raw_matrix_from_many(features_many: Any) -> np.ndarray:
    if features_many is None or isinstance(features_many, (str, bytes, Mapping)):
        raise ValueError("score_many expects a non-empty list of feature mappings")
    if isinstance(features_many, np.ndarray):
        raise ValueError("score_many expects a list of feature mappings")
    try:
        rows = list(features_many)
    except (TypeError, ValueError) as exc:
        raise ValueError("score_many expects a non-empty list of feature mappings") from exc
    if not rows:
        raise ValueError("score_many expects a non-empty list of feature mappings")
    if not all(isinstance(row, Mapping) for row in rows):
        raise ValueError("score_many expects only feature mappings")
    return np.ascontiguousarray(np.vstack([_validate_one(row) for row in rows]), dtype=np.float64)


def _digest_array(digest: "hashlib._Hash", array: Any) -> None:
    values = np.ascontiguousarray(np.asarray(array))
    digest.update(str(values.dtype).encode("ascii"))
    digest.update(json.dumps(list(values.shape), separators=(",", ":")).encode("ascii"))
    digest.update(values.tobytes(order="C"))


def _forest_fingerprint(forest: IsolationForest) -> str:
    digest = hashlib.sha256()
    for estimator in forest.estimators_:
        tree = estimator.tree_
        digest.update(str(tree.node_count).encode("ascii"))
        for attribute in (
            "children_left",
            "children_right",
            "feature",
            "threshold",
            "impurity",
            "n_node_samples",
            "weighted_n_node_samples",
            "value",
        ):
            _digest_array(digest, getattr(tree, attribute))
    _digest_array(digest, np.asarray([forest.offset_], dtype=np.float64))
    return digest.hexdigest()


def _metadata_checks(metadata: Any) -> bool:
    if not isinstance(metadata, Mapping):
        raise ValueError("metadata must be a mapping")
    if metadata.get("model_version") != MODEL_VERSION:
        raise ValueError("metadata model_version is incompatible")
    if metadata.get("feature_version") != FEATURE_VERSION:
        raise ValueError("metadata feature_version is incompatible")
    representation = metadata.get("representation")
    if representation not in VALID_REPRESENTATIONS:
        raise ValueError("metadata representation is incompatible")
    hyperparameters = metadata.get("hyperparameters")
    if not isinstance(hyperparameters, Mapping):
        raise ValueError("metadata hyperparameters are missing")
    if hyperparameters.get("n_estimators") != N_ESTIMATORS:
        raise ValueError("metadata n_estimators is incompatible")
    if hyperparameters.get("contamination") != CONTAMINATION:
        raise ValueError("metadata contamination is incompatible")
    if hyperparameters.get("n_jobs") != N_JOBS:
        raise ValueError("metadata n_jobs is incompatible")
    if hyperparameters.get("random_state") != RANDOM_STATES[representation]:
        raise ValueError("metadata random_state is incompatible")
    max_samples = hyperparameters.get("max_samples")
    if not isinstance(max_samples, int) or isinstance(max_samples, bool):
        raise ValueError("metadata max_samples is invalid")
    if not 0 < max_samples <= MAX_SAMPLES_CAP:
        raise ValueError("metadata max_samples is incompatible")
    for key in ("training_matrix_sha256", "forest_state_fingerprint"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"metadata {key} is missing")
    names = metadata.get("feature_names")
    expected_names = list(FEATURE_NAMES if representation == "raw" else INTERACTION_FEATURE_NAMES)
    if names != expected_names:
        raise ValueError("metadata feature_names are incompatible")
    return True


def validate_metadata(metadata: Mapping[str, Any]) -> bool:
    """Validate metadata from this exact v3 model; never load or deserialize it."""
    return _metadata_checks(metadata)


class ResearchIsolationForestV3:
    """Explicitly fitted v3 research IsolationForest with raw or interaction features."""

    model_version = MODEL_VERSION
    feature_version = FEATURE_VERSION

    def __init__(
        self,
        representation: str = "raw",
        *,
        n_estimators: int = N_ESTIMATORS,
        random_state: int | None = None,
    ) -> None:
        if representation not in VALID_REPRESENTATIONS:
            raise ValueError("representation must be exactly 'raw' or 'interactions'")
        if (
            isinstance(n_estimators, bool)
            or not isinstance(n_estimators, (int, np.integer))
            or n_estimators != N_ESTIMATORS
        ):
            raise ValueError("n_estimators is fixed at 128")
        expected_seed = RANDOM_STATES[representation]
        if random_state is not None and random_state != expected_seed:
            raise ValueError(
                f"random_state is fixed at {expected_seed} for {representation!r}"
            )
        self.representation = representation
        self.n_estimators = N_ESTIMATORS
        self.random_state = expected_seed
        self.forest: IsolationForest | None = None
        self.model: IsolationForest | None = None
        self._training_matrix: np.ndarray | None = None
        self._training_matrix_sha256: str | None = None
        self._training_raw_min: np.ndarray | None = None
        self._training_raw_max: np.ndarray | None = None
        self._forest_state_fingerprint: str | None = None
        self._max_samples: int | None = None
        self._fit_feature_version: str | None = None

    @classmethod
    def validate_feature_metadata(cls, metadata: Mapping[str, Any]) -> bool:
        return validate_metadata(metadata)

    @classmethod
    def validate_metadata(cls, metadata: Mapping[str, Any]) -> bool:
        return validate_metadata(metadata)

    @property
    def fitted(self) -> bool:
        return self.forest is not None

    def _matrix_for_representation(self, raw_matrix: np.ndarray) -> np.ndarray:
        if self.representation == "raw":
            return np.ascontiguousarray(raw_matrix, dtype=np.float64)
        return np.ascontiguousarray(
            np.vstack([_interaction_vector(row) for row in raw_matrix]), dtype=np.float64
        )

    def fit(
        self,
        training_features: Any,
        *,
        feature_version: str,
    ) -> "ResearchIsolationForestV3":
        """Fit only on explicitly supplied canonical feature rows, without labels."""
        _require_feature_version(feature_version)
        raw_matrix = _raw_matrix_from_training(training_features)
        matrix_sha256 = hashlib.sha256(raw_matrix.tobytes(order="C")).hexdigest()
        if self.forest is not None:
            if matrix_sha256 != self._training_matrix_sha256 or feature_version != self._fit_feature_version:
                raise RuntimeError("this model is already fitted on immutable training data")
            return self

        transformed = self._matrix_for_representation(raw_matrix)
        max_samples = min(MAX_SAMPLES_CAP, int(raw_matrix.shape[0]))
        forest = IsolationForest(
            n_estimators=N_ESTIMATORS,
            max_samples=max_samples,
            contamination=CONTAMINATION,
            n_jobs=N_JOBS,
            random_state=self.random_state,
        )
        # Intentionally no y argument: this candidate is unsupervised.
        forest.fit(transformed)

        retained = np.ascontiguousarray(raw_matrix.copy(), dtype=np.float64)
        retained.setflags(write=False)
        self._training_matrix = retained
        self._training_matrix_sha256 = matrix_sha256
        self._training_raw_min = np.min(retained, axis=0)
        self._training_raw_max = np.max(retained, axis=0)
        self._max_samples = max_samples
        self.forest = forest
        self.model = forest
        self._forest_state_fingerprint = _forest_fingerprint(forest)
        self._fit_feature_version = feature_version
        return self

    def _require_fitted(self) -> IsolationForest:
        if self.forest is None:
            raise RuntimeError("model must be explicitly fitted before scoring")
        return self.forest

    def _validated_raw(self, features: Mapping[str, Any], feature_version: str) -> np.ndarray:
        _require_feature_version(feature_version)
        if self._fit_feature_version is not None and feature_version != self._fit_feature_version:
            raise ValueError("feature_version does not match the fitted model")
        return _validate_one(features)

    @staticmethod
    def _bounded_scores(decisions: np.ndarray) -> np.ndarray:
        arguments = np.clip(-np.asarray(decisions, dtype=np.float64) * SIGMOID_SCALE, -60.0, 60.0)
        # np.errstate keeps this robust for arbitrary estimator outputs while
        # preserving the specified sigmoid(-decision_function * 8) transform.
        with np.errstate(over="ignore", under="ignore", invalid="raise"):
            values = 1.0 / (1.0 + np.exp(-arguments))
        return np.asarray(values, dtype=np.float64)

    def score(self, features: Mapping[str, Any], *, feature_version: str) -> float:
        """Return one bounded ranking score and no policy decision."""
        forest = self._require_fitted()
        raw = self._validated_raw(features, feature_version)
        transformed = self._matrix_for_representation(raw.reshape(1, -1))
        decision = forest.decision_function(transformed)
        return float(self._bounded_scores(decision)[0])

    def score_many(self, features_many: Sequence[Mapping[str, Any]], *, feature_version: str) -> np.ndarray:
        """Score a non-empty feature list in one vectorized estimator call."""
        forest = self._require_fitted()
        _require_feature_version(feature_version)
        raw_matrix = _raw_matrix_from_many(features_many)
        transformed = self._matrix_for_representation(raw_matrix)
        return self._bounded_scores(forest.decision_function(transformed))

    def ood_features(
        self, features: Mapping[str, Any], *, feature_version: str
    ) -> dict[str, bool]:
        """Flag legal raw values outside the fitted training min/max per field."""
        self._require_fitted()
        raw = self._validated_raw(features, feature_version)
        assert self._training_raw_min is not None and self._training_raw_max is not None
        return {
            name: bool(value < lower or value > upper)
            for name, value, lower, upper in zip(
                FEATURE_NAMES, raw, self._training_raw_min, self._training_raw_max, strict=True
            )
        }

    def metadata(self) -> dict[str, Any]:
        """Return JSON-safe provenance and frozen model configuration metadata."""
        self._require_fitted()
        assert (
            self._training_matrix is not None
            and self._training_matrix_sha256 is not None
            and self._forest_state_fingerprint is not None
            and self._max_samples is not None
            and self._training_raw_min is not None
            and self._training_raw_max is not None
        )
        feature_names = list(
            FEATURE_NAMES if self.representation == "raw" else INTERACTION_FEATURE_NAMES
        )
        hyperparameters = {
            "n_estimators": N_ESTIMATORS,
            "max_samples": self._max_samples,
            "max_samples_cap": MAX_SAMPLES_CAP,
            "contamination": CONTAMINATION,
            "n_jobs": N_JOBS,
            "random_state": self.random_state,
            "sigmoid_scale": SIGMOID_SCALE,
        }
        minimums = {
            name: float(value) for name, value in zip(FEATURE_NAMES, self._training_raw_min, strict=True)
        }
        maximums = {
            name: float(value) for name, value in zip(FEATURE_NAMES, self._training_raw_max, strict=True)
        }
        return {
            "model_version": MODEL_VERSION,
            "feature_version": FEATURE_VERSION,
            "representation": self.representation,
            "feature_names": feature_names,
            "raw_feature_names": list(FEATURE_NAMES),
            "derived_feature_names": (
                [] if self.representation == "raw" else list(INTERACTION_FEATURE_NAMES[4:])
            ),
            "hyperparameters": hyperparameters,
            "training_rows": int(self._training_matrix.shape[0]),
            "training_matrix_sha256": self._training_matrix_sha256,
            "training_fingerprint": self._training_matrix_sha256,
            "forest_state_fingerprint": self._forest_state_fingerprint,
            "forest_fitted_state_fingerprint": self._forest_state_fingerprint,
            "score_transform": "sigmoid(-decision_function * 8)",
            "training_raw_min": minimums,
            "training_raw_max": maximums,
            "validation_or_evaluation_used_for_fit": False,
            "no_labels_passed_to_fit": True,
        }
