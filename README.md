# PayPal AI Trust Engine / TrustGuard Agent

TrustGuard Agent is a hackathon prototype exploring safer authorization boundaries for AI-assisted commerce.

## Safe offline demo
The reproducible demo uses synthetic data only. It makes no PayPal/OpenAI calls, does not create/capture orders, and does not verify a KYAPay issuer, merchant identity, or DPoP signature. Dashboard is not live telemetry.

Requires Python 3.10+, no third-party packages:
    python main_public.py --output hasil.json
    python -m unittest -v demo_validation_tests
    python -m http.server 8000
Open http://127.0.0.1:8000/dashboard_v2.html. This updates local files only, not public Pages. Deployment requires owner approval.

See HACKATHON_DEMO.md and DEVPOST_SUBMISSION.md for scope, limitations, reproduction, and video outline.

## Demo labels
SIMULATED = synthetic fixture; UNVERIFIED = no authoritative verification; UNKNOWN_BLOCKED = required check uncertain and blocked; NOT_ATTEMPTED / NOT_EXECUTED = no provider authorization or real payment.

## Separate FastAPI backend
Draft PR #10 proposes an isolated advisory endpoint on a non-main integration branch. It is not merged into main or connected to the public dashboard. Mocked tests do not establish real OpenAI connectivity.

## Known limitations
KYAPay issuer trust, full DPoP cryptographic verification, complete live fraud scoring, PayPal provider integration/idempotency/reconciliation, and real OpenAI connectivity remain unverified. Stage 1 uses a shared bearer token and process-local rate limiting and is not production-ready. Passing tests is not production certification.
