"""Synthetic, ledger-shaped data for the TrustGuard canonical-ledger v3 benchmark.

The benchmark intentionally keeps labels outside the four model features.  Histories
are made from the same fields consumed by :class:`trustguard.Ledger`, which makes
``features_from_history`` suitable for parity checks without importing or changing
production scoring code.
"""
from __future__ import annotations

from copy import deepcopy
import math
import random
from typing import Any, Mapping

from risk_scoring import FEATURE_NAMES

FEATURE_VERSION = "trustguard-canonical-ledger-v3-research"
TRAIN_SEED = 20261110
VALIDATION_SEED = 20261111
HOLDOUT_SEED = 20261112
DIAGNOSTIC_SEED = 20261113

ACTIVE_STATES = (
    "RESERVED",
    "SCREENED_ALLOW",
    "HOLD",
    "DISPATCH_STARTED",
    "CREATED",
    "APPROVED",
    "COMPLETED",
    "UNKNOWN",
)

SCENARIOS = (
    "routine",
    "legitimate_high_utilization",
    "legitimate_high_velocity",
    "new_payee_benign",
    "abusive_high_utilization",
    "burst_abuse",
    "low_signal_anomaly",
    "interaction_mixed",
)
HOLDOUT_ONLY_SCENARIOS = (
    "high_utilization_velocity_combo",
    "quiet_new_payee_combo",
)

_DESCRIPTION = {
    "routine": "Ordinary utilization and low recent activity.",
    "legitimate_high_utilization": "Legitimate activity near the authenticated grant limit.",
    "legitimate_high_velocity": "Legitimate burst of recent transactions.",
    "new_payee_benign": "Ordinary transaction with a probabilistically new payee.",
    "abusive_high_utilization": "A high-utilization context with probabilistic abuse labels.",
    "burst_abuse": "A high-velocity context with probabilistic abuse labels.",
    "low_signal_anomaly": "An ordinary-feature context with a higher latent anomaly rate.",
    "interaction_mixed": "A smooth feature/context interaction with irreducible label noise.",
    "high_utilization_velocity_combo": "Holdout combination of high utilization and high velocity.",
    "quiet_new_payee_combo": "Holdout combination of quiet activity and a new payee.",
}

# The production module imports this same four-name tuple from risk_scoring.  Keep a
# local immutable copy only for validation order/documentation; do not add a schema.
_FEATURE_SET = frozenset(FEATURE_NAMES)


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{field} must be a finite number")
    return result


def validate_features(features: Mapping[str, Any]) -> bool:
    """Validate the exact production four-feature contract.

    A true result is returned for convenient use by callers; malformed feature
    mappings raise ``ValueError`` rather than being silently coerced.
    """
    if not isinstance(features, Mapping) or set(features) != _FEATURE_SET:
        raise ValueError("features must contain exactly FEATURE_NAMES")
    values = {name: _number(features[name], name) for name in FEATURE_NAMES}
    for name, value in values.items():
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be in the range 0..1")
    if values["amount_to_grant_ratio"] <= 0.0:
        raise ValueError("amount_to_grant_ratio must be positive")
    if values["amount_to_grant_ratio"] > values["cumulative_spending_ratio"]:
        raise ValueError("amount_to_grant_ratio cannot exceed cumulative_spending_ratio")
    if values["recent_velocity_ratio"] not in {0.0, 0.2, 0.4, 0.6, 0.8, 1.0}:
        raise ValueError("recent_velocity_ratio must be a multiple of 0.2")
    if values["new_payee"] not in {0.0, 1.0}:
        raise ValueError("new_payee must be binary")
    return True


def _required_history(history: Mapping[str, Any]) -> None:
    required = {
        "grantlimit_minor",
        "amount_minor",
        "now",
        "grantid",
        "currenttxid",
        "currency",
        "payee",
        "prior_transactions",
    }
    if not isinstance(history, Mapping) or not required.issubset(history):
        raise ValueError("history is missing required canonical fields")
    limit = history["grantlimit_minor"]
    amount = history["amount_minor"]
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("grantlimit_minor must be a positive integer")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        raise ValueError("amount_minor must be a positive integer")
    if not isinstance(history["grantid"], str) or not history["grantid"]:
        raise ValueError("grantid must be non-empty")
    if not isinstance(history["currenttxid"], str) or not history["currenttxid"]:
        raise ValueError("currenttxid must be non-empty")
    if not isinstance(history["currency"], str) or not history["currency"]:
        raise ValueError("currency must be non-empty")
    if not isinstance(history["payee"], str) or not history["payee"]:
        raise ValueError("payee must be non-empty")
    _number(history["now"], "now")
    if not isinstance(history["prior_transactions"], (list, tuple)):
        raise ValueError("prior_transactions must be a list")


def features_from_history(history: Mapping[str, Any]) -> dict[str, float]:
    """Reproduce ``Ledger.risk_features`` from a serializable canonical history.

    The filters deliberately mirror the runtime SQL semantics: active states,
    grant/currency matching, exclusion of the current transaction, a 600-second
    lower deadline with no upper deadline, and PayPal/Skyfire/legacy-payee
    ``COALESCE`` identity precedence.
    """
    _required_history(history)
    limit = history["grantlimit_minor"]
    amount = history["amount_minor"]
    now = float(history["now"])
    grant_id = history["grantid"]
    current_id = history["currenttxid"]
    currency = history["currency"]
    current_payee = history["payee"]

    used = 0
    velocity_count = 0
    prior_payee = False
    for prior in history["prior_transactions"]:
        if not isinstance(prior, Mapping):
            raise ValueError("each prior transaction must be a mapping")
        required = {
            "transaction_id", "grant_id", "currency", "paypal_merchant_id",
            "skyfire_service_id", "payee", "amount_minor", "created_at", "status",
        }
        if set(prior) != required:
            raise ValueError("prior transaction has missing or extra fields")
        prior_amount = prior["amount_minor"]
        if isinstance(prior_amount, bool) or not isinstance(prior_amount, int) or prior_amount <= 0:
            raise ValueError("prior amount_minor must be a positive integer")
        if not isinstance(prior["created_at"], (int, float)) or isinstance(prior["created_at"], bool):
            raise ValueError("prior created_at must be numeric")
        if not math.isfinite(float(prior["created_at"])):
            raise ValueError("prior created_at must be finite")
        if prior["transaction_id"] == current_id:
            continue
        active = prior["status"] in ACTIVE_STATES
        if not active or prior["grant_id"] != grant_id or prior["currency"] != currency:
            continue
        used += prior_amount
        if float(prior["created_at"]) >= now - 600.0:
            velocity_count += 1
        identity = next((prior[field] for field in ("paypal_merchant_id", "skyfire_service_id", "payee")
                         if prior[field] is not None), None)
        if identity == current_payee:
            prior_payee = True

    features = {
        "amount_to_grant_ratio": float(min(1.0, amount / limit)),
        "cumulative_spending_ratio": float(min(1.0, (used + amount) / limit)),
        "recent_velocity_ratio": float(min(1.0, velocity_count / 5.0)),
        "new_payee": 0.0 if prior_payee else 1.0,
    }
    validate_features(features)
    return features


def _seed_for_split(split: str) -> int:
    return {
        "training": TRAIN_SEED,
        "validation": VALIDATION_SEED,
        "holdout": HOLDOUT_SEED,
    }[split]


def _randint(rng: random.Random, low: int, high: int) -> int:
    return rng.randint(low, high)


def _template(rng: random.Random, *, amount_range: tuple[int, int], cumulative_range: tuple[int, int], recent_range: tuple[int, int], new_payee_probability: float) -> dict[str, Any]:
    amount = _randint(rng, *amount_range)
    cumulative = _randint(rng, max(amount, cumulative_range[0]), cumulative_range[1])
    recent = _randint(rng, *recent_range)
    new_payee = rng.random() < new_payee_probability
    return {
        "amount_minor": amount,
        "cumulative_minor": cumulative,
        "recent_count": recent,
        "new_payee": new_payee,
    }


def _prior_amounts(total: int, recent_count: int) -> list[int]:
    if total <= 0:
        return []
    count = min(recent_count, total)
    # Add one older item whenever possible.  The older item makes high utilization
    # compatible with zero recent velocity, while preserving positive cents.
    if total > count:
        count += 1
    if count == 0:
        count = 1
    amounts = [1] * count
    amounts[0] += total - count
    return amounts


def _history_from_template(template: Mapping[str, Any], *, split: str, scenario: str, index: int) -> dict[str, Any]:
    limit = 10_000
    amount = int(template["amount_minor"])
    cumulative = int(template["cumulative_minor"])
    recent_count = min(int(template["recent_count"]), max(0, cumulative - amount))
    grant_id = f"synthetic-grant-{split}-{scenario}-{index:03d}"
    current_id = f"synthetic-current-{split}-{scenario}-{index:03d}"
    current_payee = f"synthetic-payee-{split}-{scenario}-{index:03d}"
    now = 1_900_000_000.0 + index
    prior_amounts = _prior_amounts(cumulative - amount, recent_count)
    prior: list[dict[str, Any]] = []
    for item, prior_amount in enumerate(prior_amounts):
        is_recent = item < recent_count
        if bool(template["new_payee"]):
            payee = f"synthetic-other-payee-{split}-{scenario}-{index:03d}-{item:02d}"
        else:
            payee = current_payee if item == 0 else f"synthetic-known-payee-{split}-{scenario}-{index:03d}-{item:02d}"
        prior.append({
            "transaction_id": f"synthetic-prior-{split}-{scenario}-{index:03d}-{item:02d}",
            "grant_id": grant_id,
            "currency": "USD",
            "paypal_merchant_id": None,
            "skyfire_service_id": None,
            "payee": payee,
            "amount_minor": prior_amount,
            "created_at": now - (300.0 + item if is_recent else 700.0 + item),
            "status": ACTIVE_STATES[item % len(ACTIVE_STATES)],
        })
    return {
        "grantlimit_minor": limit,
        "amount_minor": amount,
        "now": now,
        "grantid": grant_id,
        "currenttxid": current_id,
        "currency": "USD",
        "payee": current_payee,
        "prior_transactions": prior,
    }


def _features_for(template: Mapping[str, Any], *, split: str, scenario: str, index: int) -> tuple[dict[str, float], dict[str, Any]]:
    history = _history_from_template(template, split=split, scenario=scenario, index=index)
    return features_from_history(history), history


def _label(rng: random.Random, probability: float) -> tuple[int, float]:
    probability = min(1.0, max(0.0, probability))
    return int(rng.random() < probability), probability


def _row(*, split: str, scenario: str, index: int, template: Mapping[str, Any], rng: random.Random, probability: float, context: Mapping[str, Any], forced_label: int | None = None) -> dict[str, Any]:
    features, history = _features_for(template, split=split, scenario=scenario, index=index)
    hidden_label, probability = _label(rng, probability)
    if forced_label is not None:
        hidden_label = forced_label
    latent = dict(context)
    latent.update({"label_probability": float(probability),
                   "label_sampling": "forced_ambiguity_pair" if forced_label is not None else "independent_bernoulli",
                   "forced_label": forced_label})
    return {
        "id": f"{split}-{scenario}-{index:03d}",
        "scenario": scenario,
        "description": _DESCRIPTION[scenario],
        "hidden_label": hidden_label,
        "features": features,
        "history": history,
        "latent_context": latent,
    }


def _ordinary_template(rng: random.Random, *, new_payee_probability: float = 0.30) -> dict[str, Any]:
    return _template(
        rng,
        amount_range=(100, 3_000),
        cumulative_range=(100, 6_500),
        recent_range=(0, 2),
        new_payee_probability=new_payee_probability,
    )


def _make_split(split: str, *, seed: int | None = None, include_unseen: bool | None = None) -> list[dict[str, Any]]:
    rng = random.Random(_seed_for_split(split) if seed is None else seed)
    per_scenario = 64 if split in {"training", "holdout"} else 48
    include_unseen = split == "holdout" if include_unseen is None else include_unseen
    scenarios = SCENARIOS + HOLDOUT_ONLY_SCENARIOS if include_unseen else SCENARIOS
    rows_by: dict[str, list[dict[str, Any]]] = {name: [] for name in scenarios}

    for index in range(per_scenario):
        routine_template = _ordinary_template(rng)
        rows_by["routine"].append(_row(
            split=split, scenario="routine", index=index, template=routine_template,
            rng=rng, probability=0.05, context={"context_family": "ordinary"},
        ))

        high_util_template = _template(
            rng, amount_range=(100, 3_000), cumulative_range=(7_000, 9_800),
            recent_range=(0, 3), new_payee_probability=0.30,
        )
        rows_by["legitimate_high_utilization"].append(_row(
            split=split, scenario="legitimate_high_utilization", index=index,
            template=high_util_template, rng=rng, probability=0.05,
            context={"context_family": "high_utilization", "counterpart": "abusive_high_utilization"},
            forced_label=0 if index == 0 else None,
        ))
        rows_by["abusive_high_utilization"].append(_row(
            split=split, scenario="abusive_high_utilization", index=index,
            template=high_util_template, rng=rng, probability=0.75,
            context={"context_family": "high_utilization", "counterpart": "legitimate_high_utilization"},
            forced_label=1 if index == 0 else None,
        ))

        high_velocity_template = _template(
            rng, amount_range=(100, 1_000), cumulative_range=(1_500, 9_000),
            recent_range=(5, 10), new_payee_probability=0.25,
        )
        rows_by["legitimate_high_velocity"].append(_row(
            split=split, scenario="legitimate_high_velocity", index=index,
            template=high_velocity_template, rng=rng, probability=0.05,
            context={"context_family": "high_velocity", "counterpart": "burst_abuse"},
            forced_label=0 if index == 0 else None,
        ))
        rows_by["burst_abuse"].append(_row(
            split=split, scenario="burst_abuse", index=index,
            template=high_velocity_template, rng=rng, probability=0.75,
            context={"context_family": "high_velocity", "counterpart": "legitimate_high_velocity"},
            forced_label=1 if index == 0 else None,
        ))

        new_payee_template = _ordinary_template(rng, new_payee_probability=0.65)
        rows_by["new_payee_benign"].append(_row(
            split=split, scenario="new_payee_benign", index=index,
            template=new_payee_template, rng=rng, probability=0.05,
            context={"context_family": "ordinary_new_payee"},
        ))
        low_signal_template = _ordinary_template(rng, new_payee_probability=0.50)
        rows_by["low_signal_anomaly"].append(_row(
            split=split, scenario="low_signal_anomaly", index=index,
            template=low_signal_template, rng=rng, probability=0.75,
            context={"context_family": "ordinary_low_signal"},
        ))

        interaction_template = _ordinary_template(rng, new_payee_probability=0.40)
        interaction_features, _ = _features_for(interaction_template, split=split, scenario="interaction_mixed", index=index)
        context_signal = rng.gauss(0.0, 1.0)
        irreducible_noise = rng.gauss(0.0, 0.55)
        logit = (
            -3.10
            + 2.00 * interaction_features["amount_to_grant_ratio"]
            + 2.80 * interaction_features["cumulative_spending_ratio"]
            + 1.30 * interaction_features["recent_velocity_ratio"]
            + 1.20 * interaction_features["new_payee"]
            + 0.85 * context_signal
            + irreducible_noise
        )
        interaction_probability = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, logit))))
        interaction_formula = {
            "link": "sigmoid",
            "intercept": -3.10,
            "feature_coefficients": {
                "amount_to_grant_ratio": 2.00,
                "cumulative_spending_ratio": 2.80,
                "recent_velocity_ratio": 1.30,
                "new_payee": 1.20,
            },
            "context_coefficient": 0.85,
            "noise_term": "irreducible_noise",
        }
        interaction_context = {
            "context_family": "smooth_interaction",
            "context_signal": float(context_signal),
            "irreducible_noise": float(irreducible_noise),
            "logit": float(logit),
            "formula_json": interaction_formula,
            "formula": "sigmoid(-3.10 + 2.00*amount + 2.80*cumulative + 1.30*velocity + 1.20*new_payee + 0.85*context_signal + irreducible_noise)",
        }
        rows_by["interaction_mixed"].append(_row(
            split=split, scenario="interaction_mixed", index=index,
            template=interaction_template, rng=rng, probability=interaction_probability,
            context=interaction_context,
        ))

        if include_unseen:
            combo_template = _template(
                rng, amount_range=(100, 3_000), cumulative_range=(6_500, 9_800),
                recent_range=(5, 10), new_payee_probability=0.50,
            )
            rows_by["high_utilization_velocity_combo"].append(_row(
                split=split, scenario="high_utilization_velocity_combo", index=index,
                template=combo_template, rng=rng, probability=0.65,
                context={"context_family": "unseen_combination"},
            ))
            quiet_template = _template(
                rng, amount_range=(100, 2_500), cumulative_range=(100, 6_000),
                recent_range=(0, 1), new_payee_probability=0.90,
            )
            rows_by["quiet_new_payee_combo"].append(_row(
                split=split, scenario="quiet_new_payee_combo", index=index,
                template=quiet_template, rng=rng, probability=0.35,
                context={"context_family": "unseen_combination"},
            ))

    return [row for scenario in scenarios for row in rows_by[scenario]]


def generate_split(split: str) -> list[dict[str, Any]]:
    """Generate one deterministic split without fitting, selecting, or scoring."""
    if split not in {"training", "validation", "holdout"}:
        raise ValueError("split must be 'training', 'validation', or 'holdout'")
    rows = _make_split(split)
    for row in rows:
        validate_features(row["features"])
    return deepcopy(rows)


def generate_diagnostic_split(seed: int = DIAGNOSTIC_SEED) -> list[dict[str, Any]]:
    """Generate separately seeded diagnostic histories, never validation copies."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("diagnostic seed must be an integer")
    rows = _make_split("diagnostic", seed=seed, include_unseen=True)
    for row in rows:
        validate_features(row["features"])
    return deepcopy(rows)


def metadata() -> dict[str, Any]:
    """Return the reproducibility contract and synthetic-generator assumptions."""
    return {
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "active_states": list(ACTIVE_STATES),
        "scenarios": list(SCENARIOS),
        "holdout_only_scenarios": list(HOLDOUT_ONLY_SCENARIOS),
        "seeds": {
            "training": TRAIN_SEED,
            "validation": VALIDATION_SEED,
            "holdout": HOLDOUT_SEED,
            "diagnostic": DIAGNOSTIC_SEED,
        },
        "row_counts": {"training": 512, "validation": 384, "holdout": 640},
        "rows_per_scenario": {"training": 64, "validation": 48, "holdout": 64},
        "generator_assumptions": {
            "currency": "USD",
            "grant_limit_minor": 10_000,
            "amounts_are_positive_cents": True,
            "cumulative_is_capped_at_grant_limit": True,
            "all_identifiers_are_synthetic": True,
            "model_inputs_are_features_only": True,
            "training_rows_include_all_hidden_label_mixture": True,
            "holdout_is_generated_independently_and_not_used_for_selection": True,
            "paired_ambiguity_rows_per_counterpart_and_split": 1,
        },
        "ranges": {
            "high_utilization": {"amount_ratio": [0.01, 0.30], "cumulative_ratio": [0.70, 0.98], "recent_prior_count": [0, 3]},
            "high_velocity": {"amount_ratio": [0.01, 0.10], "cumulative_ratio": [0.15, 0.90], "recent_prior_count": [5, 10]},
            "ordinary": {"amount_ratio": [0.01, 0.30], "cumulative_ratio": [0.01, 0.65], "recent_prior_count": [0, 2]},
        },
        "label_noise": {
            "probabilistic_labels": True,
            "routine_probability": 0.05,
            "legitimate_high_utilization_probability": 0.05,
            "abusive_high_utilization_probability": 0.75,
            "legitimate_high_velocity_probability": 0.05,
            "burst_abuse_probability": 0.75,
            "new_payee_benign_probability": 0.05,
            "low_signal_anomaly_probability": 0.75,
            "interaction_formula": {
                "link": "sigmoid",
                "intercept": -3.10,
                "feature_coefficients": {
                    "amount_to_grant_ratio": 2.00,
                    "cumulative_spending_ratio": 2.80,
                    "recent_velocity_ratio": 1.30,
                    "new_payee": 1.20,
                },
                "context_coefficient": 0.85,
                "noise_term": "irreducible_noise",
            },
            "interaction_formula_expression": "sigmoid(-3.10 + 2.00*amount + 2.80*cumulative + 1.30*velocity + 1.20*new_payee + 0.85*context_signal + irreducible_noise)",
            "interaction_labels_use_bernoulli_draw": True,
            "irreducible_noise": True,
            "paired_same_feature_histories_have_opposite_labels": True,
            "label_field": "hidden_label",
        },
    }


__all__ = [
    "ACTIVE_STATES",
    "DIAGNOSTIC_SEED",
    "FEATURE_NAMES",
    "FEATURE_VERSION",
    "HOLDOUT_ONLY_SCENARIOS",
    "HOLDOUT_SEED",
    "SCENARIOS",
    "TRAIN_SEED",
    "VALIDATION_SEED",
    "features_from_history",
    "generate_split",
    "generate_diagnostic_split",
    "metadata",
    "validate_features",
]
