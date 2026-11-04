#!/usr/bin/env python3
"""Evaluate an offline IsolationForest v2 candidate; production remains unchanged."""
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

from risk_candidate_evaluation import build_candidate_report


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
    parser.add_argument("--timestamp", default=None, help="Fixed UTC timestamp for reproducibility in the same dependency environment.")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "synthetic_v2_candidate_report.json")
    parser.add_argument("--metadata-output", type=Path, default=ROOT / "evaluation" / "synthetic_v2_candidate_metadata.json")
    args = parser.parse_args(argv)
    if not math.isfinite(args.max_validation_fpr) or not 0.0 <= args.max_validation_fpr <= 1.0:
        parser.error("--max-validation-fpr must be finite and between 0 and 1")
    if args.output.resolve() == args.metadata_output.resolve():
        parser.error("report and metadata output paths must be distinct")
    report = build_candidate_report(timestamp=args.timestamp, max_fpr=args.max_validation_fpr)
    write_json(args.metadata_output, report["candidate_model_metadata"])
    write_json(args.output, report)
    print("SYNTHETIC BENCHMARK ONLY — not real-world fraud evidence; v2 is not active; production remains v1 at 0.65.")
    print(json.dumps({key: value for key, value in report.items() if key in {
        "status", "selected_candidate_threshold", "baseline_threshold", "validation_comparison",
        "fresh_holdout_comparison", "timestamp", "selection_reason"}}, indent=2, sort_keys=True))
    print(f"Candidate metadata: {args.metadata_output.resolve()}")
    print(f"Evaluation report: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
