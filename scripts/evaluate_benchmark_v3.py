#!/usr/bin/env python3
"""Run Synthetic Benchmark v3 offline; never activate any production model."""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark_v3_evaluation import build_report


def write_json(path: Path, value: dict) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
            temporary = f.name
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-validation-fpr", type=float, default=0.01)
    parser.add_argument("--timestamp", default=None, help="Fixed UTC timestamp for same-environment reproducibility.")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "synthetic_v3_research_report.json")
    parser.add_argument("--metadata-output", type=Path, default=ROOT / "evaluation" / "synthetic_v3_research_freeze.json")
    args = parser.parse_args(argv)
    if not math.isfinite(args.max_validation_fpr) or not 0.0 <= args.max_validation_fpr <= 1.0:
        parser.error("--max-validation-fpr must be finite and between 0 and 1")
    if args.output.resolve() == args.metadata_output.resolve():
        parser.error("report and metadata paths must be distinct")
    for destination in (args.output, args.metadata_output):
        if destination.suffix.lower() != ".json":
            parser.error("research artifact outputs must be JSON files")
        resolved = destination.resolve()
        if resolved.is_relative_to(ROOT.resolve()) and resolved.exists() and not resolved.name.startswith("synthetic_v3_"):
            parser.error("existing non-v3 repository artifacts cannot be overwritten")
    protected = {p.resolve() for p in (ROOT / "evaluation").glob("*.json")
                 if not p.name.startswith("synthetic_v3_")}
    if args.output.resolve() in protected or args.metadata_output.resolve() in protected:
        parser.error("v1/v2 historical evaluation artifacts cannot be overwritten")
    frozen = []

    def persist_freeze(record: dict) -> None:
        if frozen:
            raise RuntimeError("candidate is already frozen for this run")
        write_json(args.metadata_output, record)
        frozen.append(record)

    report = build_report(timestamp=args.timestamp, max_validation_fpr=args.max_validation_fpr,
                          freeze_callback=persist_freeze)
    if len(frozen) != 1:
        raise RuntimeError("exactly one pre-holdout freeze artifact is required")
    write_json(args.output, report)
    print("SYNTHETIC RESEARCH ONLY — error rates/intervals are not real-world population guarantees; production v1 stays at 0.65.")
    summary = {key: report[key] for key in ("status", "selected_representation", "selected_candidate_threshold",
               "feature_version", "counts", "timestamp") if key in report}
    metric_keys = ("confusion_matrix", "precision", "recall", "f1", "false_positive_rate", "roc_auc", "average_precision")
    metrics = report.get("holdout_metrics")
    summary["holdout_metrics"] = None if metrics is None else {key: metrics.get(key) for key in metric_keys}
    summary["confidence_intervals"] = report.get("confidence_intervals")
    summary["validation_metrics"] = {name: values.get("selection", {}).get("selected_validation_metrics")
        for name, values in report.get("validation_comparison", {}).items()}
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"Pre-holdout freeze: {args.metadata_output.resolve()}")
    print(f"V3 research report: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
