"""Local, deterministic anomaly screening trained only on synthetic feature vectors.

Scores are ranking signals from a synthetic baseline; they are not calibrated fraud
probabilities and are not evidence of fraud.
"""
from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from typing import Mapping

MODEL_VERSION = "trustguard-isolation-forest-synthetic-v1"
TRAINING_DATASET_ID = "synthetic-normal-transaction-features-seed-20261104-v1"
TRAINING_SEED = 20261104
FEATURE_NAMES = (
    "amount_to_grant_ratio",
    "cumulative_spending_ratio",
    "recent_velocity_ratio",
    "new_payee",
)
ANOMALY_THRESHOLD = 0.65


@dataclass(frozen=True)
class RiskAssessment:
    model_version: str
    training_dataset_id: str
    anomaly_score: float | None
    decision: str


class SyntheticIsolationForestScorer:
    """Lazily fit a fixed IsolationForest on generated synthetic routine patterns."""

    model_version = MODEL_VERSION
    training_dataset_id = TRAINING_DATASET_ID

    def __init__(self) -> None:
        self._model = None
        self._lock = threading.Lock()

    @staticmethod
    def _fit_model():
        # Synthetic baseline only: 768 routine-like rows, generated from fixed
        # distributions and seed. No real customer, merchant, or payment data.
        import numpy as np
        from sklearn.ensemble import IsolationForest

        rng = np.random.default_rng(TRAINING_SEED)
        count = 768
        baseline = np.column_stack((
            rng.beta(2.0, 4.0, count) * 0.70,       # amount / grant limit
            rng.beta(1.5, 3.0, count) * 0.82,       # cumulative grant utilization
            rng.beta(1.2, 8.0, count),               # recent velocity, normalized
            rng.binomial(1, 0.25, count),             # new-payee indicator
        )).astype("float64")
        model = IsolationForest(
            n_estimators=128,
            max_samples=256,
            contamination=0.04,
            random_state=TRAINING_SEED,
            n_jobs=1,
        )
        model.fit(baseline)
        return model

    def _get_model(self):
        if self._model is None:
            with self._lock:
                if self._model is None:
                    self._model = self._fit_model()
        return self._model

    def score(self, features: Mapping[str, float]) -> RiskAssessment:
        """Run actual sklearn inference; return a bounded anomaly ranking score."""
        import numpy as np

        if not isinstance(features, Mapping) or set(features) != set(FEATURE_NAMES):
            raise ValueError("trusted risk feature shape is invalid")
        vector = []
        for name in FEATURE_NAMES:
            value = features[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("trusted risk feature is invalid")
            number = float(value)
            if not math.isfinite(number) or not 0.0 <= number <= 1.0:
                raise ValueError("trusted risk feature is out of range")
            vector.append(number)

        margin = float(self._get_model().decision_function(np.asarray([vector], dtype="float64"))[0])
        # A sigmoid maps the IsolationForest margin to a convenient 0..1 ranking
        # scale; it is intentionally not calibrated or labeled as a probability.
        bounded = max(-60.0, min(60.0, margin * 8.0))
        score = 1.0 / (1.0 + math.exp(bounded))
        decision = "HOLD" if score >= ANOMALY_THRESHOLD else "ALLOW"
        return RiskAssessment(MODEL_VERSION, TRAINING_DATASET_ID, score, decision)


__all__ = [
    "ANOMALY_THRESHOLD", "FEATURE_NAMES", "MODEL_VERSION", "TRAINING_DATASET_ID",
    "RiskAssessment", "SyntheticIsolationForestScorer", "EXPLANATION_VERSION", "explain_assessment",
]


EXPLANATION_VERSION = "trusted-feature-explanation-v1"


def explain_assessment(features: Mapping[str, float], decision: str, anomaly_score: float | None) -> dict:
    """Describe observed trusted feature signals, not causal model attributions.

    The supplied decision is never changed. These fixed rule annotations explain
    context for the decision; they do not estimate fraud likelihood or SHAP values.
    """
    valid = isinstance(features, Mapping) and set(features) == set(FEATURE_NAMES)
    if valid:
        valid = all(not isinstance(features[name], bool)
                    and isinstance(features[name], (int, float))
                    and math.isfinite(float(features[name]))
                    and 0.0 <= float(features[name]) <= 1.0 for name in FEATURE_NAMES)
    reasons = ["ANOMALY_BELOW_THRESHOLD" if decision == "ALLOW" else
               "MODEL_UNAVAILABLE" if anomaly_score is None else "ANOMALY_THRESHOLD_EXCEEDED"]
    signals = []
    if not valid:
        reasons.append("TRUSTED_FEATURES_MISSING_OR_INVALID")
    else:
        rules = (
            ("amount_to_grant_ratio", 0.70, "HIGH_AMOUNT_TO_GRANT_RATIO", "Transaction amount uses at least 70% of the authenticated grant limit."),
            ("cumulative_spending_ratio", 0.82, "HIGH_CUMULATIVE_GRANT_UTILIZATION", "Reserved and spent amounts use at least 82% of the authenticated grant limit."),
            ("recent_velocity_ratio", 0.60, "ELEVATED_RECENT_TRANSACTION_VELOCITY", "The ledger records at least three other active transactions within ten minutes."),
            ("new_payee", 1.0, "NEW_PAYEE_FOR_GRANT", "No other active transaction for this grant and currency uses this payee."),
        )
        for feature, threshold, code, description in rules:
            value = float(features[feature])
            if value >= threshold:
                signals.append({"feature": feature, "value": value, "reason_code": code, "description": description})
                reasons.append(code)
        if decision == "HOLD" and anomaly_score is not None and not signals:
            reasons.append("ANOMALOUS_FEATURE_COMBINATION")
    if decision == "ALLOW":
        summary = "Anomaly ranking is below the screening threshold; ALLOW does not prove absence of fraud or authorize payment."
    elif anomaly_score is None:
        summary = "Screening could not produce a valid model assessment; fail-closed HOLD remains in effect."
    else:
        summary = "Anomaly ranking reached the screening threshold; HOLD requires review. Listed signals describe observed feature context, not proven causes of fraud."
    return {"version": EXPLANATION_VERSION, "reason_codes": reasons, "summary": summary,
            "feature_signals": signals,
            "method": "Deterministic trusted-feature rule annotations; not causal IsolationForest attribution. Synthetic-model anomaly ranking is not a calibrated fraud probability."}
