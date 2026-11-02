# Devpost Submission Draft — TrustGuard Agent

## Project name
TrustGuard Agent — Safer Authorization Boundaries for AI-Driven Commerce

## Summary
A security-focused hackathon prototype exploring how AI-assisted commerce can separate advisory model output from explicit authorization and payment execution.

## Problem
A language model response is not proof an agent is authorized to act. Commerce systems need boundaries between AI advice, authorization evidence, replay protection, risk signals, and payment-provider actions.

## Solution
TrustGuard Agent explores authorization-oriented checks and fail-closed handling when required verification is unknown. The reproducible demo is offline and synthetic; it performs no real payments and claims no external identity verification.

## Implemented in the demo
- Static dashboard renders JSON snapshot using text nodes/textContent.
- Offline Python snapshot generator.
- Synthetic grant-shaped, repeated-token, expired-grant, and unavailable-DPoP scenarios.
- SIMULATED, UNVERIFIED, UNKNOWN_BLOCKED, NOT_ATTEMPTED, and NOT_EXECUTED labels.
- Fail-closed display when snapshot is invalid/unavailable.
- Separate advisory FastAPI backend proposed in draft PR #10; not merged into main or connected to the public dashboard.

## Reproduction
Python 3.10+, no third-party packages:
    python main_public.py --output hasil.json
    python -m unittest -v demo_validation_tests
    python -m http.server 8000
Open http://127.0.0.1:8000/dashboard_v2.html. This local demo does not connect to providers.

## Testing evidence
Run python -m unittest -v demo_validation_tests on this branch. Stage 1 PR #10 separately passed mocked API tests (18) and 101 regression tests in GitHub Actions run 41411197229 at commit d2f1b8f137f912ec03c3bf26ae0351bd1181aa8c; that does not validate this branch. Tests are not production certification.

## Security and limitations
KYAPay issuer identity/contracts, full DPoP verification, complete fraud-risk scoring, real PayPal authorization/idempotency/reconciliation, and real OpenAI connectivity are unverified. No provider request, order creation, capture, refund, or live payment is performed. Do not use this prototype to authorize real transactions.

## Demo video outline (90–120 seconds)
0:00–0:15 problem; 0:15–0:30 architecture; 0:30–1:05 four synthetic scenarios and fail-closed state; 1:05–1:25 run generator and tests, show zero real payments; 1:25–1:45 explain limitations; 1:45–2:00 next steps.

## Closing
When verification is missing or uncertain, the safe outcome is to block rather than invent successful external authorization.
