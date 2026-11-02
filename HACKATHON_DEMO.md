# TrustGuard Agent — Hackathon Demo Guide

## Scope and truth in labeling
This is an offline, synthetic demonstration of authorization-boundary concepts. It does not call PayPal or OpenAI, create or capture orders, move money, or verify a KYAPay issuer, merchant identity, DPoP signature, or live fraud score. The dashboard is a static snapshot, not live telemetry. Its “allow-shaped” case is a simulated scenario, not authorization.

## Reproduce from the release-candidate checkout
The generator uses only the Python standard library. Full tests use Python 3.12, Playwright, and Chromium. From the repository root, set the commit identity used by the artifact tests:

    export GITHUB_SHA="$(git rev-parse HEAD)"

    python -m compileall -q .
    python build_pages.py
    python -m unittest -v demo_validation_tests demo_artifact_tests
    python -m unittest -v security_tests paypal_rest_tests spend_reservations_tests frontend_tests pages_artifact_tests release_pipeline_tests
    python -m unittest -v frontend_browser_tests demo_browser_tests
    cd _site
    python -m http.server 8000

Open http://127.0.0.1:8000/dashboard_demo.html. Build and tests operate on local files only. Do not dispatch the deploy workflow for judging.

## Scenario labels
- SIMULATED: synthetic data generated locally.
- UNVERIFIED: no authoritative issuer/merchant/DPoP verification has occurred.
- UNKNOWN_BLOCKED: a required check is unknown/unavailable; fail closed.
- NOT_ATTEMPTED: provider authorization was not attempted.
- NOT_EXECUTED: no real payment/order/capture occurred.
- UNVERIFIED_STATIC_FRONTEND: build provenance only; not transaction evidence.

## Architecture
The static demo generator is intentionally separate from main_public.py, which contains the security/dispatch logic exercised by mocked regression tests. Importing either module performs no provider request. The security pipeline validates token/DPoP/policy, freezes canonical transaction data, checks PayPal REST line-item totals against the approved amount, and requires spend reservation before provider dispatch. Provider outcomes can remain UNKNOWN; no capture is implemented in the dispatcher.

## Implemented / simulated / unverified / deferred
- Implemented and tested with mocks: backend validation primitives, replay checks, spend reservations, PayPal Orders v2 item normalization and approved-amount binding, fail-closed dashboard data validation, static artifact SHA identity checks, and manual deployment gate.
- Simulated only: four demo scenarios, including allow-shaped, repeated token, expired grant, and unavailable DPoP verification.
- Unverified: official KYAPay issuer/trust contract, real merchant mapping, official DPoP interoperability, distributed replay/spend reservations, live PayPal Sandbox/provider connectivity, OpenAI connectivity, and real fraud scoring.
- Deferred: FastAPI advisory backend integration from draft PR #10. It is not required for the offline demo, and connecting it would add configuration/authentication surface without proving external provider connectivity.

## Safety
No production deployment is authorized by this change. The Pages workflow remains manual, main-only, and requires the exact DEPLOY_TO_PRODUCTION input. Passing mocked tests is not production certification.
