# TrustGuard Agent — Hackathon Demo Guide

This is an offline synthetic demonstration. It makes no PayPal/OpenAI requests, creates/captures no orders, and does not verify a KYAPay issuer, merchant identity, or DPoP signature. Unknown verification is blocked. Dashboard is static, not live telemetry.

## Scenarios
- Structurally complete synthetic grant: simulated allow-shaped result, not issuer verified.
- Repeated synthetic token identifier: simulated block.
- Expired synthetic grant: simulated block.
- DPoP verification unavailable: UNKNOWN_BLOCKED / FAIL_CLOSED; no authorization attempted.

## Reproduce
Requires Python 3.10+ and no third-party packages.
    python main_public.py --output hasil.json
    python -m unittest -v demo_validation_tests
    python -m http.server 8000
Open http://127.0.0.1:8000/dashboard_v2.html. Regeneration changes local files only, not public Pages.

## Labels
SIMULATED = synthetic data; UNVERIFIED = no authoritative verification; UNKNOWN_BLOCKED = required check uncertain/unavailable and blocked; NOT_ATTEMPTED / NOT_EXECUTED = no provider authorization or payment.

## Limitations
KYAPay issuer trust, full DPoP cryptographic verification, live FRP scoring, PayPal provider integration/idempotency/reconciliation, and real OpenAI connectivity are not verified. PR #10 is a separate advisory FastAPI backend, not connected to the public dashboard. No production-readiness claim is made.
