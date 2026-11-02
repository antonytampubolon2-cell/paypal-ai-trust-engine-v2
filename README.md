# PayPal AI Trust Engine / TrustGuard Agent

TrustGuard is a security-focused hackathon prototype exploring authorization boundaries for AI-assisted commerce. Its core principle: **model output is advice, not authorization**.

## Fast, safe offline demo
The candidate includes a local-only synthetic dashboard. Set the commit identity before building and running artifact tests:

    export GITHUB_SHA="$(git rev-parse HEAD)" It makes no PayPal/OpenAI calls, creates/captures no orders, moves no money, and does not verify KYAPay issuer identity, merchant identity, DPoP signatures, or live fraud scores. The dashboard is not live telemetry.

    python -m compileall -q .
    python build_pages.py
    python -m unittest -v demo_validation_tests demo_artifact_tests
    python -m unittest -v security_tests paypal_rest_tests spend_reservations_tests frontend_tests pages_artifact_tests release_pipeline_tests
    python -m unittest -v frontend_browser_tests demo_browser_tests
    cd _site
    python -m http.server 8000

Open http://127.0.0.1:8000/dashboard_demo.html. The generator uses only the Python standard library; browser tests require Playwright and Chromium. Full test setup is documented in HACKATHON_DEMO.md.

## Architecture and security
- Token, DPoP, delegated policy, and replay checks fail closed.
- Canonical transaction data is carried through policy checks to prevent amount/merchant substitution.
- PayPal Orders v2 line-item totals use decimal arithmetic and must exactly match the approved amount and currency.
- Spend reservations are single-host SQLite-backed and are not a distributed atomicity guarantee.
- Ambiguous provider outcomes remain unknown; the pipeline does not capture payments.
- Static dashboards validate input and use safe DOM text rendering. A source/build SHA is provenance for the artifact, not proof of a real transaction.
- GitHub Pages deployment is manual-only, restricted to main, and requires exact confirmation; it was not dispatched for this candidate.

## Status truth table
| Label | Meaning |
|---|---|
| SIMULATED | Synthetic local scenario only |
| UNVERIFIED | No authoritative verification evidence |
| UNKNOWN_BLOCKED | Required evidence unavailable/unknown; fail closed |
| NOT_ATTEMPTED | Provider authorization not attempted |
| NOT_EXECUTED | No real payment/order/capture executed |
| UNVERIFIED_STATIC_FRONTEND | Build artifact status, not transaction evidence |

## Feature status
- **Implemented and mocked-tested:** security validation primitives, replay protections, spend reservation controls, PayPal REST schema and approved-amount binding, static dashboard contract/fail-closed handling, artifact SHA checks, manual deployment gate.
- **Simulated:** four synthetic dashboard scenarios.
- **Unverified:** official KYAPay issuer/token/delegation contract and trust material; confirmed merchant mapping; official DPoP/provider interoperability; distributed replay/spend guarantees; live PayPal Sandbox and OpenAI connectivity; live fraud scoring.
- **Deferred:** FastAPI advisory backend from draft PR #10. It is intentionally not connected to this offline demo or public dashboard; the extra integration is not needed to demonstrate the safe offline flow.

## Project documents
- HACKATHON_DEMO.md
- DEVPOST_SUBMISSION.md
- SECURITY_STATUS.md

## Safety notice
This is not production-ready payment software. Never use the prototype to authorize real transactions. Passing mocked tests is not proof of provider connectivity or production security.
