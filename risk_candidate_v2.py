"""Offline candidate v2 anomaly scorer for TrustGuard.

This module is deliberately separate from the production scorer.  It is a
candidate-ranking implementation only: it returns a bounded ranking score and
never returns an ALLOW/HOLD decision or changes production integration.

The candidate is fit only from :func:`risk_evaluation.training_reference_vectors`.
Validation and evaluation datasets are intentionally not imported or generated
here, so model fitting cannot see holdout rows or labels.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import platform
import sys
from typing import Any

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from risk_evaluation import training_reference_vectors
from risk_scoring import FEATURE_NAMES, TRAINING_DATASET_ID, TRAINING_SEED


MODEL_VERSION = "trustguard-isolation-forest-synthetic-v2-candidate"
FEATURE_REPRESENTATION_ID = "trusted-upper-tail-marginals-v2"

# These are fixed design choices, not parameters selected from validation data.
QUANTILE = 0.75
N_ESTIMATORS = 128
MAX_SAMPLES = 256
CONTAMINATION = 0.04
N_JOBS = 1
SIGMOID_SCALE = 8.0


# Keep public aliases useful to an offline validation orchestrator while using
# the same canonical feature and training identifiers as the existing scorer.
__all__ = [
    "CANDIDATE_VERSION",
    "CONTAMINATION",
    "FEATURE_NAMES",
    "FEATURE_REPRESENTATION_ID",
    "MAX_SAMPLES",
    "MODEL_VERSION",
    "N_ESTIMATORS",
    "N_JOBS",
    "QUANTILE",
    "SIGMOID_SCALE",
    "TRAINING_DATASET_ID",
    "TRAINING_SEED",
    "CandidateIsolationForestV2",
]
CANDIDATE_VERSION = MODEL_VERSION


class CandidateIsolationForestV2:
    """A frozen, training-only, marginal IsolationForest candidate.

    Each continuous raw feature is transformed independently using its training
    q75 and upper-tail range.  The binary ``new_payee`` history feature is
    preserved raw as 0/1, then each representation is scored by its own
    one-dimensional IsolationForest.
    The final score is the maximum of the four bounded marginal scores.  This
    preserves a strong upper-tail signal instead of allowing unrelated routine
    dimensions to dilute it in one multivariate forest.

    ``train_matrix`` is provided only for deterministic tests or an offline
    injected fixture.  In normal use it is loaded from
    ``risk_evaluation.training_reference_vectors()``.  No labels are accepted
    or passed to sklearn.
    """

    model_version = MODEL_VERSION
    training_dataset_id = TRAINING_DATASET_ID
    feature_representation_id = FEATURE_REPRESENTATION_ID

    def __init__(
        self,
        train_matrix: Any | None = None,
        *,
        training_matrix: Any | None = None,
    ) -> None:
        if train_matrix is not None and training_matrix is not None:
            raise ValueError("provide only one of train_matrix or training_matrix")
        supplied_matrix = train_matrix if train_matrix is not None else training_matrix
        if supplied_matrix is None:
            supplied_matrix = training_reference_vectors()

        matrix = self._validate_training_matrix(supplied_matrix)
        # Retain an independent copy so callers can inspect the exact fitting
        # input without being able to mutate the internal matrix accidentally.
        self.training_vectors = matrix.copy()
        self._training_matrix = matrix.copy()

        # q75 is the effective transformation offset.  raw_q75 retains the
        # learned q75 for every source feature, including binary new_payee,
        # whose representation intentionally uses offset 0 instead.
        self.q75: np.ndarray | None = None
        self.raw_q75: np.ndarray | None = None
        self.max_values: np.ndarray | None = None
        self.scales: np.ndarray | None = None
        self.quantile_boundaries: np.ndarray | None = None
        self.forests: list[IsolationForest] = []
        self.models = self.forests
        self._fitted = False
        self._forest_fitted_state_fingerprint: str | None = None

    @staticmethod
    def _validate_training_matrix(matrix: Any) -> np.ndarray:
        """Validate and copy an injected raw training matrix."""
        try:
            values = np.asarray(matrix, dtype="float64")
        except (TypeError, ValueError) as exc:
            raise ValueError("training matrix must be numeric") from exc

        expected_width = len(FEATURE_NAMES)
        if values.ndim != 2 or values.shape[1] != expected_width or values.shape[0] == 0:
            raise ValueError("training matrix must be a non-empty Nx4 matrix")
        if not np.isfinite(values).all() or not ((values >= 0.0) & (values <= 1.0)).all():
            raise ValueError("training matrix values must be finite and in the range 0..1")
        new_payee = values[:, FEATURE_NAMES.index("new_payee")]
        if not np.isin(new_payee, (0.0, 1.0)).all():
            raise ValueError("training matrix new_payee values must be binary")
        return np.ascontiguousarray(values, dtype="float64")

    @staticmethod
    def _validate_features(features: Mapping[str, Any]) -> np.ndarray:
        """Validate the exact four-feature raw input schema and return a vector."""
        if not isinstance(features, Mapping) or set(features) != set(FEATURE_NAMES):
            raise ValueError("trusted risk feature shape is invalid")

        vector: list[float] = []
        for name in FEATURE_NAMES:
            value = features[name]
            # bool is an int subclass, so reject it explicitly.  numpy scalar
            # numeric types are accepted as ordinary finite numeric inputs.
            if isinstance(value, (bool, np.bool_)) or not isinstance(
                value, (int, float, np.integer, np.floating)
            ):
                raise ValueError("trusted risk feature is invalid")
            number = float(value)
            if not math.isfinite(number) or not 0.0 <= number <= 1.0:
                raise ValueError("trusted risk feature is out of range")
            vector.append(number)

        new_payee = vector[FEATURE_NAMES.index("new_payee")]
        if new_payee not in (0.0, 1.0):
            raise ValueError("trusted risk feature new_payee must be binary")
        return np.asarray(vector, dtype="float64")

    def _fit(self) -> None:
        """Fit fixed marginal forests exactly once, using raw training rows only."""
        if self._fitted:
            return

        training = self._training_matrix
        raw_q75 = np.quantile(training, QUANTILE, axis=0)
        maxima = np.max(training, axis=0)
        continuous_width = len(FEATURE_NAMES) - 1
        ranges = maxima[:continuous_width] - raw_q75[:continuous_width]
        # Continuous upper-tail ranges use a deterministic fallback for a
        # constant feature.  new_payee is different by design: it is binary
        # metadata/history and must remain exactly raw 0/1 even when its raw
        # training q75 is 1.
        scales = np.where(ranges > 0.0, ranges, 1.0)
        q75 = np.zeros(len(FEATURE_NAMES), dtype="float64")
        q75[:continuous_width] = raw_q75[:continuous_width]
        effective_scales = np.ones(len(FEATURE_NAMES), dtype="float64")
        effective_scales[:continuous_width] = scales
        transformed_training = training.copy()
        transformed_training[:, :continuous_width] = np.maximum(
            0.0,
            (training[:, :continuous_width] - q75[:continuous_width])
            / effective_scales[:continuous_width],
        )

        forests: list[IsolationForest] = []
        for index in range(len(FEATURE_NAMES)):
            forest = IsolationForest(
                n_estimators=N_ESTIMATORS,
                max_samples=MAX_SAMPLES,
                contamination=CONTAMINATION,
                n_jobs=N_JOBS,
                random_state=TRAINING_SEED + index,
            )
            # Deliberately pass no y/labels: this is unsupervised fitting.
            forest.fit(transformed_training[:, index].reshape(-1, 1))
            forests.append(forest)

        self.q75 = np.asarray(q75, dtype="float64")
        self.raw_q75 = np.asarray(raw_q75, dtype="float64")
        self.max_values = np.asarray(maxima, dtype="float64")
        self.scales = np.asarray(effective_scales, dtype="float64")
        self.quantile_boundaries = self.q75.copy()
        self.forests = forests
        self.models = self.forests
        self._forest_fitted_state_fingerprint = self._fitted_state_fingerprint(forests)
        self._fitted = True

    # Public explicit fit plus a lazy private path make the class convenient in
    # an offline orchestrator while avoiding repeated fitting during scoring.
    def fit(self) -> "CandidateIsolationForestV2":
        self._fit()
        return self

    train = fit

    def _ensure_fitted(self) -> None:
        if not self._fitted:
            self._fit()

    def transform_features(self, features: Mapping[str, Any]) -> np.ndarray:
        """Return the q75/range transformed vector for a raw feature mapping."""
        raw = self._validate_features(features)
        self._ensure_fitted()
        assert self.q75 is not None and self.scales is not None
        # No upper cap is intentional: a raw value above q75 may transform to
        # any positive value, preserving the magnitude of an upper-tail signal.
        transformed = raw.copy()
        continuous_width = len(FEATURE_NAMES) - 1
        transformed[:continuous_width] = np.maximum(
            0.0,
            (raw[:continuous_width] - self.q75[:continuous_width])
            / self.scales[:continuous_width],
        )
        # Preserve new_payee exactly as its canonical raw binary metadata.
        transformed[-1] = raw[-1]
        return np.asarray(transformed, dtype="float64")

    @staticmethod
    def _bounded_anomaly(margin: float) -> float:
        """Convert sklearn's higher-is-normal margin into a bounded ranking."""
        bounded_argument = max(-60.0, min(60.0, -float(margin) * SIGMOID_SCALE))
        return float(1.0 / (1.0 + math.exp(-bounded_argument)))

    def score_per_feature(self, features: Mapping[str, Any]) -> dict[str, float]:
        """Return marginal ranking signals without adding decisions or labels."""
        transformed = self.transform_features(features)
        values: dict[str, float] = {}
        for index, name in enumerate(FEATURE_NAMES):
            margin = float(
                self.forests[index].decision_function(
                    transformed[index].reshape(1, 1)
                )[0]
            )
            values[name] = self._bounded_anomaly(margin)
        return values

    def feature_scores(self, features: Mapping[str, Any]) -> dict[str, float]:
        """Alias for the optional purely ranking-oriented marginal explanation."""
        return self.score_per_feature(features)

    def score(self, features: Mapping[str, Any]) -> float:
        """Return only the bounded anomaly ranking score; never ALLOW/HOLD."""
        per_feature = self.score_per_feature(features)
        return float(max(per_feature.values()))

    @staticmethod
    def _update_digest_with_array(digest: "hashlib._Hash", array: Any) -> None:
        values = np.asarray(array)
        digest.update(str(values.dtype).encode("ascii"))
        digest.update(json.dumps(list(values.shape), separators=(",", ":")).encode("ascii"))
        digest.update(np.ascontiguousarray(values).tobytes(order="C"))

    @classmethod
    def _fitted_state_fingerprint(cls, forests: list[IsolationForest]) -> str:
        """Hash deterministic learned forest state without serializing estimators."""
        digest = hashlib.sha256()
        for forest in forests:
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
                    cls._update_digest_with_array(digest, getattr(tree, attribute))
            digest.update(str(forest.offset_).encode("ascii"))
        return digest.hexdigest()

    def metadata(self) -> dict[str, Any]:
        """Return JSON-serializable frozen-design and training provenance."""
        self._ensure_fitted()
        assert (
            self.q75 is not None
            and self.raw_q75 is not None
            and self.max_values is not None
            and self.scales is not None
        )
        training_matrix = self._training_matrix
        matrix_sha256 = hashlib.sha256(training_matrix.tobytes(order="C")).hexdigest()
        seeds = [TRAINING_SEED + index for index in range(len(FEATURE_NAMES))]
        hyperparameters = {
            "n_estimators": N_ESTIMATORS,
            "max_samples": MAX_SAMPLES,
            "contamination": CONTAMINATION,
            "n_jobs": N_JOBS,
            "random_state_base": TRAINING_SEED,
            "random_states": seeds,
            "sigmoid_scale": SIGMOID_SCALE,
        }
        return {
            "model_version": MODEL_VERSION,
            "version": MODEL_VERSION,
            "training_dataset_id": TRAINING_DATASET_ID,
            "feature_names": list(FEATURE_NAMES),
            "feature_representation_id": FEATURE_REPRESENTATION_ID,
            "representation": {
                "kind": "trusted_upper_tail_marginals",
                "quantile": QUANTILE,
                "continuous_features": list(FEATURE_NAMES[:-1]),
                "binary_features_preserved_raw": [FEATURE_NAMES[-1]],
                "raw_quantile_boundaries": {
                    name: float(value) for name, value in zip(FEATURE_NAMES, self.raw_q75)
                },
                "quantile_boundaries": {
                    name: float(value) for name, value in zip(FEATURE_NAMES, self.q75)
                },
                "maxima": {
                    name: float(value) for name, value in zip(FEATURE_NAMES, self.max_values)
                },
                "scales": {
                    name: float(value) for name, value in zip(FEATURE_NAMES, self.scales)
                },
                "continuous_formula": "max(0, (x - training_q75) / training_max_minus_q75_or_1)",
                "binary_formula": "new_payee_raw_0_or_1",
                "upper_cap": None,
                "new_payee_history_preserved": True,
            },
            "quantile": QUANTILE,
            "raw_quantile_boundaries": {
                name: float(value) for name, value in zip(FEATURE_NAMES, self.raw_q75)
            },
            "quantile_boundaries": {
                name: float(value) for name, value in zip(FEATURE_NAMES, self.q75)
            },
            "scales": {
                name: float(value) for name, value in zip(FEATURE_NAMES, self.scales)
            },
            "aggregation": "max",
            "score_transform": "sigmoid(-decision_function * 8)",
            "hyperparameters": hyperparameters,
            "fit_seed": TRAINING_SEED,
            "per_feature_fit_seeds": seeds,
            "training_rows": int(training_matrix.shape[0]),
            "training_matrix_sha256": matrix_sha256,
            "training_fingerprint": matrix_sha256,
            "forest_fitted_state_fingerprint": self._forest_fitted_state_fingerprint,
            "runtime_versions": {
                "python": platform.python_version(),
                "numpy": np.__version__,
                "sklearn": sklearn.__version__,
            },
            "no_labels_passed_to_fit": True,
            "validation_or_evaluation_used_for_fit": False,
        }
