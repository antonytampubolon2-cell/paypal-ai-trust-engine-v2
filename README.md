# PayPal AI Trust Engine

### Secure Transactions for AI Agents — Trust, Verification, and Controlled Authorization

**PayPal AI Trust Engine** is a security-focused prototype designed to help protect PayPal transactions initiated by AI agents. It introduces a layered verification workflow that evaluates delegated authorization, detects token replay attempts, checks Demonstrating Proof of Possession (DPoP) binding, and forwards eligible requests to the PayPal Sandbox.

The project's core principle is simple: **an AI agent should not be trusted to initiate a financial transaction merely because it can access a payment API.** Its authorization and transaction request should be evaluated before the request proceeds.

Built for the **PayPal AI Hackathon 2026**, the project combines Python-based security logic, PayPal Agent Toolkit integration, and a browser-based monitoring dashboard.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Live Demo](#live-demo)
- [The Problem](#the-problem)
- [Our Solution](#our-solution)
- [Security Architecture](#security-architecture)
- [Transaction Evidence](#transaction-evidence)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [Judges' Testing Instructions](#judges-testing-instructions)
- [Expected Test Results](#expected-test-results)
- [Security Considerations and Prototype Scope](#security-considerations-and-prototype-scope)
- [Roadmap](#roadmap)
- [License](#license)

---

## Project Overview

AI agents are increasingly capable of initiating actions on behalf of users, including interactions with commerce and payment services. As these agents become more autonomous, payment integrations need controls that help prevent unauthorized actions, replayed credentials, and transactions that exceed delegated permissions.

PayPal AI Trust Engine explores a layered approach to this problem through **TrustGuard Agent**, a verification workflow designed to check authorization and proof-of-possession signals before a payment order is submitted to PayPal Sandbox.

### Project Information

| Item | Details |
|---|---|
| Project | PayPal AI Trust Engine |
| Security Workflow | TrustGuard Agent |
| Backend | Python |
| Frontend | HTML, CSS, and JavaScript |
| Payment Integration | PayPal Agent Toolkit |
| Test Environment | PayPal Sandbox |
| Dashboard Hosting | GitHub Pages |
| License | MIT |

## Dashboard Preview and Deployment Status

The dashboard source and build checks are available in this repository. The public GitHub Pages URL is provided as a navigation target, **not as a claim that the current deployed artifact has been verified**:

[Open the PayPal AI Trust Engine Dashboard](https://antonytampubolon2-cell.github.io/paypal-ai-trust-engine-v2/dashboard_v2.html)

The dashboard consumes static JSON and cannot establish authenticated backend telemetry or prove a live transaction. A public deployment is verified only after the release workflow confirms that the published manifest, index, dashboards, and data all match the intended commit.

**Source Code:** [GitHub Repository](https://github.com/antonytampubolon2-cell/paypal-ai-trust-engine-v2)

## The Problem

AI-powered commerce introduces security challenges that are different from those of traditional user-initiated payments.

An AI agent may have access to payment tools, but tool access alone does not establish that a particular transaction is authorized.

Important threats include:

- **Token misuse:** A token may be expired, malformed, or inconsistent with the intended authorization.
- **Replay attacks:** A previously accepted token or proof may be submitted again.
- **Credential theft and proof-of-possession failures:** A stolen bearer credential may be abused if the system does not adequately bind authorization to the intended client.
- **Excessive delegated permissions:** An agent may attempt to act beyond its permitted merchant, spending limit, or authorization period.
- **Insufficient transaction visibility:** Developers and reviewers need a clear way to inspect verification outcomes and transaction-related activity.

The project explores how these risks can be addressed through layered checks before a payment request reaches the PayPal Sandbox.

## Our Solution

PayPal AI Trust Engine introduces **TrustGuard Agent**, a security-oriented workflow that evaluates a request before deciding whether it should proceed to PayPal's order-creation interface.

The original prototype used synthetic authorization payloads and process-local caches. The `codex/security-hardening` branch replaces that executable demonstration with a fail-closed JWT/DPoP verification boundary and atomic SQLite replay claims. Official KYAPay issuer and delegation contracts remain blockers.

Its intended workflow is:

1. Receive an AI-agent payment request and its associated authorization data.
2. Validate required authorization claims and delegation constraints.
3. Reject expired grants or previously used token identifiers.
4. Evaluate the supplied DPoP-related proof fields and key binding.
5. Block the request if a verification check fails.
6. If the checks pass, attempt to create a PayPal Sandbox order.
7. Display relevant project and transaction information through the monitoring dashboard.

The new regression tests use explicitly synthetic, ephemeral signing keys and a mocked PayPal adapter. They verify code paths only; they do not establish a real KYAPay trust relationship or prove production readiness.

---

## Security Architecture

TrustGuard Agent organizes the prototype into the following security layers.

### 1. KYAPay Token Verifier

The new JWT adapter requires a compact signed token and verifies its signature plus configured issuer, audience, expiration, and required claims. It fails closed unless official issuer configuration is supplied. The repository does not contain the authoritative KYAPay token contract.

- Issuer (`iss`)
- Subject (`sub`)
- Audience (`aud`)
- Expiration (`exp`)
- Token identifier (`jti`)
- Delegation grant (`delegation_grant`)

The delegation policy adapter checks the allowlisted merchant, amount, currency, grant validity, and token expiry. Its expected field names must be confirmed against the actual issuer schema before deployment.

These checks are intended to help establish whether the submitted authorization data contains the required information and remains within the configured constraints.

**Blocker:** Signature verification is configurable, but no authoritative KYAPay issuer, signing algorithm, public key/JWKS policy, or delegation schema is supplied by this repository. Do not configure invented values.

### 2. JTI Anti-Replay Cache

The JTI Anti-Replay Cache records accepted token identifiers and rejects an identifier that has already been used while it remains in the cache.

The new `SQLiteReplayStore` uses an atomic transaction and unique key to reject duplicate identifiers. It is suitable only for a persistent single-host deployment; multi-host production requires a shared atomic replay store.

This demonstrates the basic anti-replay control:

**Accept a valid token identifier once; reject a repeated identifier.**

SQLite is persistent and atomic on a single host, but is not a distributed replay store. A shared replay service remains a deployment blocker for multi-host operation.

### 3. DPoP Verifier — RFC 9449

The prototype includes a DPoP-oriented verifier referencing [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html).

The new DPoP verifier validates a signed compact JWT, public JWK, signature, `typ`, `htm`, canonical HTTPS `htu`, `iat`, `jti`, `ath`, token key binding, and replay protection. Full interoperability and deployment-specific protocol review remain required.

- `htm` — expected HTTP method
- `htu` — expected HTTP URI
- `jti` — unique proof identifier
- `jwk` — public-key information

It computes the RFC 7638 thumbprint and compares it with `cnf.jkt`, verifies the `ath` hash against the presented access token, and uses the atomic replay store for proof identifiers.

These checks demonstrate selected binding and replay-detection concepts.

**Important limitation:** The implementation adds cryptographic proof verification but has not passed a full RFC 9449 interoperability suite. The actual issuer/client protocol and any required nonce policy must be confirmed before deployment.

### 4. Fraud Risk Engine (FRP)

The Live Dashboard includes a Fraud Risk Engine (FRP) monitoring panel intended to provide visibility into suspicious transaction activity and anomaly-related status.

The dashboard is a monitoring interface, not a standalone guarantee that a transaction is safe. The currently published `main_public.py` does not provide a complete, independently verifiable FRP scoring pipeline.

### 5. PayPal Agent Toolkit Integration

The hardened entry point does not initialize the PayPal toolkit on import and does not enable capture actions. Order creation is possible only through an explicitly injected adapter after authentication and policy checks.

No live or Sandbox API call is performed by the test suite. A mocked adapter verifies that the outbound order payload uses the same checked merchant, amount, and currency. The real merchant-ID mapping remains unconfirmed.

Requests rejected by authentication or policy checks are blocked before the adapter is called. An order-created result is not treated as proof that a payment was completed or captured.

This integration is intended for controlled testing in the PayPal Sandbox, not for processing real payments.

---

## Transaction Evidence

No independently verified PayPal order identifiers are published as evidence in this repository. Backend regression tests use a mocked adapter and synthetic identifiers; those fixtures are not PayPal transaction evidence. No real or Sandbox order/capture was performed as part of this hardening work.

A genuine Sandbox order should be claimed only when it can be retrieved from the intended Sandbox account and its response is reviewed. Even then, order creation does not prove payment capture or settlement.

For Sandbox concepts, consult the official [PayPal Sandbox Testing Guide](https://developer.paypal.com/sandbox-testing/overview/).

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend logic and security-verification workflow |
| PayPal Agent Toolkit | PayPal API and order-related integration |
| HTML | Dashboard structure |
| CSS | Dashboard presentation |
| JavaScript | Dashboard behavior and data rendering |
| PayPal Sandbox | Isolated payment-order testing |
| GitHub | Source-code hosting and version control |
| GitHub Pages | Public dashboard deployment |
| JTI-based replay detection | Demonstration of token replay prevention |
| DPoP concepts | Demonstration of proof-of-possession binding checks |
| RFC 9449 | DPoP protocol reference |

---

## Getting Started

### Prerequisites

Before running the Python demonstration, install:

- Python 3
- `pip`
- Git
- A PayPal Developer account with Sandbox application credentials

You can manage Sandbox application credentials through the [PayPal Developer Dashboard](https://developer.paypal.com/dashboard/).

### 1. Clone the Repository

```bash
git clone https://github.com/antonytampubolon2-cell/paypal-ai-trust-engine-v2.git
cd paypal-ai-trust-engine-v2
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements-security.txt
```

The hardened verification path does not initialize PayPal Agent Toolkit on import. Do not install or configure a real payment adapter merely to run the local security tests.

---

## Security Hardening Branch — Safe Verification

The hardened entry point no longer creates a PayPal order when imported or run directly. It does not capture payments. The KYAPay issuer contract and merchant/delegation schema are not available in this repository, so the backend fails closed until official issuer documentation and trust material are supplied.

### Run local security tests

Install the dedicated verifier dependencies and run the automated tests:

```bash
python -m pip install -r requirements-security.txt
python -m unittest -v security_tests
```

The tests use ephemeral synthetic cryptographic fixtures and a mocked PayPal adapter. They do not prove that a real KYAPay issuer is trusted, and they must never be used as production credentials.

### Required official KYAPay configuration

The JWT adapter requires `KYAPAY_ISSUER`, `KYAPAY_AUDIENCE`, `KYAPAY_PUBLIC_KEY_PEM`, and `KYAPAY_JWT_ALGORITHM`. Do not invent these values. Obtain the authoritative token format, signing algorithm, issuer, audience, key-discovery/rotation rules, and delegation schema from the real KYAPay issuer before configuring them.

### PayPal integration status

No PayPal API call is made by the test suite or by importing `main_public.py`. The payment dispatcher accepts an injected adapter so integration tests can use a mock. Before connecting a real adapter, confirm the merchant identifier mapping and Orders API payload with official PayPal documentation. An order-creation result is reported as `ORDER_CREATED`, not as a completed or captured payment.

See [SECURITY_STATUS.md](SECURITY_STATUS.md) for critical blockers and deployment limitations. Do not merge this branch or represent the project as production-ready while those blockers remain unresolved.

---

## Security Considerations and Prototype Scope

PayPal AI Trust Engine is a security-focused hackathon prototype.

The current implementation demonstrates several useful concepts, but it should not be deployed as a production payment-security gateway without further engineering and validation.

Known limitations include:

- The JWT verifier requires authoritative KYAPay issuer, audience, algorithm, public-key/JWKS and delegation-schema details that are not supplied by this repository.
- SQLite replay protection is atomic and persistent only when configured on a persistent single host; it is not a distributed multi-instance replay service.
- Spending limits are enforced per transaction; there is no atomic cumulative-spend reservation/ledger across concurrent transactions.
- Provider idempotency and reconciliation for ambiguous order responses are not implemented. The dispatcher reports ambiguous outcomes as UNKNOWN and must not automatically retry.
- DPoP has core signature and binding checks but has not passed a full RFC 9449 interoperability suite; issuer/client nonce and canonicalization requirements remain to be confirmed.
- The FRP dashboard panel is not evidence of a complete backend fraud-scoring system.
- The static dashboard is untrusted presentation data, not authenticated backend telemetry.
- No official provider interoperability test has been performed. Regression tests use synthetic keys and a mocked adapter.

These limitations define the current prototype scope and block any production-readiness claim.

## Roadmap

Potential next steps include:

- Obtain and validate the official KYAPay issuer/token/delegation contract and key-rotation policy.
- Confirm the official mapping between delegated merchant identities and PayPal merchant IDs.
- Deploy a shared atomic replay store and implement cumulative-spend reservation with concurrency-safe accounting.
- Confirm PayPal Orders v2 payload and idempotency/reconciliation behavior against official documentation and an authorized Sandbox integration.
- Run a full RFC 9449 interoperability suite with the real issuer/client protocol, including nonce policy where applicable.
- Connect the FRP panel to a fully implemented and validated risk-scoring backend.
- Add authenticated backend telemetry and signed/otherwise trusted audit evidence for dashboard consumption.
- Verify GitHub Pages source, environment reviewers, branch restrictions, and rollback procedures before any authorized deployment.

---

## License

This project is released under the **MIT License**. See the [`LICENSE`](LICENSE) file for the complete license terms.

---

## Acknowledgments and References

- [PayPal Developer Platform](https://developer.paypal.com/)
- [PayPal Sandbox Testing Guide](https://developer.paypal.com/sandbox-testing/overview/)
- [PayPal Agent Toolkit — GitHub](https://github.com/paypal/agent-toolkit)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)
- [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)

**PayPal AI Trust Engine — Building a safer foundation for AI-driven commerce.**
