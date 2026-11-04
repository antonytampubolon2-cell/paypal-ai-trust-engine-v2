#!/usr/bin/env python3
"""Offline synthetic benchmark only: no provider calls or transaction creation."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from risk_evaluation import build_evaluation_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "synthetic_report.json")
    parser.add_argument("--timestamp", default=None,
                        help="Optional fixed UTC ISO timestamp for byte-reproducible reports; otherwise current UTC run time.")
    args = parser.parse_args(argv)
    report = build_evaluation_report(timestamp=args.timestamp)
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
    print("SYNTHETIC BENCHMARK ONLY — not real-world fraud detection performance or calibrated fraud probability.")
    print(json.dumps({key: report[key] for key in ("dataset_id", "model_version", "sample_counts", "threshold", "metrics", "timestamp")}, indent=2, sort_keys=True))
    print(f"JSON report: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
