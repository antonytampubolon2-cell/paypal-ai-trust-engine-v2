# PayPal AI Trust Engine

A multi-layered security gate for AI Agent transactions on PayPal.

## 🌐 Live Dashboard Demo
Experience the live, interactive dashboard directly in your browser:
👉 **[PayPal AI Trust Engine Dashboard](https://antonytampubolon2-cell.github.io/paypal-ai-trust-engine-v2/dashboard_v2.html)**

## Background & Problem Statement

As AI agents gain the ability to transact using user funds, critical security questions arise:
- How do we ensure the AI agent is truly authenticated?
- How do we prevent stolen tokens from being reused (replay attacks)?
- How do we enforce strict boundaries on the agent's spending authority?

The **PayPal AI Trust Engine** addresses these challenges through the **TrustGuard Agent** — a security gate that meticulously verifies every transaction request before it reaches PayPal.

## Security Architecture

| Layer | Component | Status |
| :--- | :--- | :--- |
| 1 | KYAPay Token Verifier | ✅ Operational (Claim-based verification) |
| 2 | JTI Anti-Replay Cache | ✅ Operational |
| 3 | DPoP Verifier (RFC 9449) | ⚠️ Partial (Claim verification, not signature) |
| 4 | TrustGuard Agent | ✅ Operational |

**Honest Note:** The current implementation focuses on claim-based verification. Full cryptographic signature verification (JWT) and native AI Agent integration are currently under development.

## End-to-End Transaction Proof

Three orders were successfully created in the PayPal Sandbox as proof of integration:

| Order ID | PayPal Status | Description |
| :--- | :--- | :--- |
| `7R3064957MB0759941` | PAYER_ACTION_REQUIRED | Order created, awaiting payer approval |
| `3HD92730V0626752B` | PAYER_ACTION_REQUIRED | Order created, awaiting payer approval |
| `8RJ05941XL2772705` | PAYER_ACTION_REQUIRED | Order created, awaiting payer approval |

*Note: The `PAYER_ACTION_REQUIRED` status indicates the order was successfully created, but the payment is pending buyer approval. The `capture_order` process is not yet implemented.*

## Getting Started

1. **Install dependencies:**
   ```bash
   pip install paypal-agent-toolkit openai-agents
