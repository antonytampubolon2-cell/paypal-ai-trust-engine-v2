# Synthetic Model Evaluation — Evidence and Limits

**Status:** Existing offline benchmark documented; synthetic-only evidence, not production validation.
**Code review baseline:** `c95a1b5cac9b81dcc01408a5a3c0259360ff622c`.

## Scope

TrustGuard's active screening model is `SyntheticIsolationForestScorer` in `risk_scoring.py`. It uses the existing `sklearn.ensemble.IsolationForest` and fixed runtime threshold `0.65`. The screening path derives four features from authenticated request and ledger state: amount-to-grant ratio, cumulative spending ratio, recent velocity ratio, and new-payee indicator. Caller-provided risk features are not used. The model score is an **anomaly ranking**, not a calibrated fraud probability.

The separate `risk_evaluation.py` harness and `scripts/evaluate_risk_model.py` use the actual scorer but do not alter the runtime scorer, threshold, authentication path, ledger, or dispatch behavior. The harness defines training seed `20261104`, validation seed `20261105`, and evaluation seed `20261106`. It uses 768 synthetic routine-like training-reference vectors, 40 rows per scenario in validation, and 80 rows per scenario in evaluation across six predefined scenarios. Exact feature-vector overlap between splits is rejected. Validation is not used for training or threshold selection by this baseline harness.

Labels are assigned by deterministic synthetic scenario rules—not observed payment outcomes, fraud investigations, chargebacks, or independent human adjudication. The generated report explicitly identifies the dataset/model, split seeds, counts, fingerprints, threshold, synthetic labels, and limitations.

## Metrics and what is not measured

`risk_evaluation.compute_metrics()` currently reports confusion-matrix counts, precision, recall, F1, false-positive rate, ROC-AUC, and average precision. The report includes per-scenario metrics and individual synthetic sample results. Undefined metrics are represented as `null` with a reason.

The current v1 report **does not** include an explicit false-negative rate field or average/p95 inference latency. Although false-negative counts are present in the confusion matrix, no FNR value should be quoted as though the report emitted one. Latency has not been measured by this harness; do not infer production latency from a unit test or one local run. The benchmark does not establish calibration, operational error costs, fraud prevalence, or performance on real transactions. No real-world baseline is available for comparison.

No fresh numeric benchmark report is included in this readiness package. Existing repository v2/v3 research reports and comparisons remain explicitly synthetic and offline; they are not independent evidence of fraud detection efficacy.

## Existing verification evidence

The repository has automated checks in `tests/test_risk_evaluation.py`, including:

- `test_scorer_fit_uses_exact_training_reference_vectors`;
- `test_copied_training_vector_is_rejected_as_dataset_leak`;
- `test_actual_model_ranks_extreme_features_above_low_features_without_threshold_drift`;
- `test_evaluation_report_is_reproducible_and_contains_model_dataset_threshold_timestamp`.

Additional v3 data/model tests compare generated features with ledger semantics and test repeatability. These establish implementation consistency, deterministic generation, split-overlap checks, and metric/report behavior. They do **not** validate real-world fraud detection.

The offline judge demo is a separate control-flow demonstration: `scripts/run_judge_demo.py --mode offline` delegates to `scripts/run_local_demo.py`, uses generated local test credentials and synthetic claims, temporary SQLite, and provider/network-call guards. Its two scored cases are not an independent model-evaluation set.

## Evidence decision

**Supported claim:** TrustGuard includes a reproducible offline benchmark of its current IsolationForest against explicitly defined synthetic scenarios, with separate deterministic seeds and leakage checks. The results characterize only that synthetic generator and fixed model configuration.

**Unsupported claims:** real-world fraud accuracy, fraud reduction, calibrated probabilities, deployment suitability, or representative operational false-positive/false-negative rates.

A stronger efficacy evaluation requires appropriately governed, representative, independently labeled outcomes and a predeclared holdout protocol that is not used for fitting, threshold selection, or tuning. No real transaction data is included in this repository or this review. Production model and threshold remain unchanged.
