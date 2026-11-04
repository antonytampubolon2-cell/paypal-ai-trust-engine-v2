#!/usr/bin/env python3
"""Offline validation-only synthetic threshold calibration; never activates a threshold."""
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

from risk_calibration import build_calibration_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-validation-fpr", type=float, default=0.01,
                        help="Empirical validation false-positive fraction ceiling (default 0.01 = 1%%).")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "calibration_report.json")
    parser.add_argument("--timestamp", default=None, help="Fixed UTC ISO timestamp for reproducibility in the same environment.")
    args = parser.parse_args(argv)
    if not math.isfinite(args.max_validation_fpr) or not 0.0 <= args.max_validation_fpr <= 1.0:
        parser.error("--max-validation-fpr must be finite and between 0 and 1")
    report = build_calibration_report(max_fpr=args.max_validation_fpr, timestamp=args.timestamp)
    payload = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=args.output.parent, delete=False) as f:
            temporary = f.name
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, args.output)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)
    print("SYNTHETIC CALIBRATION ONLY — candidate is not active; production threshold remains 0.65.")
    print(json.dumps({key: value for key, value in report.items()
                      if key in {"status", "selected_candidate_threshold", "baseline_threshold", "max_validation_fpr", "validation_comparison", "holdout_comparison", "timestamp"}},
                     indent=2, sort_keys=True))
    print(f"JSON report: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
