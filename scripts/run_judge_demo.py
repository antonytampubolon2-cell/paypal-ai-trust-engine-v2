#!/usr/bin/env python3
"""Single entry point for the offline judge demo and separately gated local Sandbox flow."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the TrustGuard judge demonstration.")
    parser.add_argument(
        "--mode",
        choices=("offline", "sandbox"),
        default="offline",
        help="offline is simulated and provider-free (default); sandbox can create a real Sandbox order",
    )
    parser.add_argument(
        "--confirm-sandbox",
        action="store_true",
        help="required explicit acknowledgment before entering the operator-controlled Sandbox flow",
    )
    args = parser.parse_args(argv)

    if args.mode == "offline":
        if args.confirm_sandbox:
            parser.error("--confirm-sandbox is only valid with --mode sandbox")
        from scripts.run_local_demo import main as run_offline

        return run_offline()

    if not args.confirm_sandbox:
        print(
            "Sandbox mode can contact PayPal Sandbox and create an order. "
            "Re-run with --mode sandbox --confirm-sandbox only when you intend to do so.",
            file=sys.stderr,
        )
        return 2

    from scripts.run_paypal_sandbox_demo import main as run_sandbox

    return run_sandbox()


if __name__ == "__main__":
    raise SystemExit(main())
