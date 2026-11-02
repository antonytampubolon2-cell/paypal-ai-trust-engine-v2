# Devpost Submission Draft — TrustGuard Agent

## Project
**TrustGuard Agent — Safer Authorization Boundaries for AI-Assisted Commerce**

## Summary
TrustGuard explores a simple security principle: model output is advice, not authorization. The prototype separates advisory reasoning from delegated authorization checks, replay protection, amount binding, and payment execution boundaries. The release-candidate demo is deliberately offline and synthetic so judges can reproduce the scenarios without credentials or financial risk.

## Problem
AI agents can generate convincing instructions, but a convincing response does not prove that the user authorized a transaction, that a token is valid, or that the requested amount is within the grant.

## What the prototype demonstrates
- Fail-closed treatment when verification is missing or ambiguous.
- Security primitives and mocked regression tests for token/DPoP/policy paths, replay claims, spend reservation, and PayPal Orders v2 line-item amount binding.
- Static dashboards that label data as unverified and validate input contracts before rendering.
- A reproducible local demo with four synthetic scenarios and explicit SIMULATED, UNVERIFIED, UNKNOWN_BLOCKED, NOT_ATTEMPTED, and NOT_EXECUTED states.
- Build artifact identity checks tied to the exact source commit and a manual-only deployment workflow.

## Reproduce
Use the instructions in HACKATHON_DEMO.md. The demo requires no provider credentials. It does not contact PayPal/OpenAI and does not create or capture orders.

## What is not claimed
The prototype does not establish live KYAPay issuer trust, merchant identity, official DPoP interoperability, distributed replay/spend safety, real PayPal Sandbox interoperability, live OpenAI connectivity, or real fraud scoring. Mocked tests are not proof of provider connectivity. No real payment was executed.

## Architecture
A local synthetic snapshot generator feeds a safe DOM-rendered dashboard. Separately, the backend security pipeline validates delegated claims and DPoP, enforces replay and spend controls, binds REST line items to the approved amount, and leaves ambiguous provider outcomes unknown. The demo page never calls that pipeline or a provider.

## 100–120 second video script
- **0:00–0:12 — Hook:** “An AI answer is not payment authorization.”
- **0:12–0:28 — Threat model:** show the boundary between model advice, delegated grant, DPoP/replay checks, amount policy, and provider dispatch.
- **0:28–0:58 — Demo:** open the local dashboard and walk through the simulated allow-shaped case, repeated token block, expired grant block, and unknown DPoP fail-closed case.
- **0:58–1:15 — Evidence:** run the snapshot/artifact tests and show the commit identity and zero real payments.
- **1:15–1:35 — Security:** explain approved-amount binding and why unknown provider outcomes stay unknown.
- **1:35–1:55 — Honest limits:** list issuer contract, official DPoP interoperability, live provider access, and distributed controls as unverified.
- **1:55–2:00 — Close:** “When authorization evidence is missing, block rather than guess.”

## Recording checklist
- [ ] Start from the exact release-candidate commit; show the full SHA.
- [ ] Run build and tests on screen; capture successful command output.
- [ ] Show SIMULATED and NO PAYMENT WAS EXECUTED disclosures.
- [ ] Show no credentials, tokens, merchant secrets, or account data.
- [ ] Avoid describing the demo as production-ready or claiming a real payment.
- [ ] Record a clean browser window and readable terminal; keep the video under two minutes.
- [ ] Recheck that displayed commit matches the tested branch head before recording.

## Submission status
Draft only. Before submitting, the owner should review claims, record the video, and confirm the final tested commit. Do not submit claims of live provider integration without independent evidence.
