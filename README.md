# PayPal AI Trust Engine

### Secure Transactions for AI Agents — Trust, Verification, and Controlled Authorization

**PayPal AI Trust Engine** is a security-focused prototype for evaluating delegated authorization and proof-of-possession signals before an optional PayPal Orders request. The current code uses an injected provider adapter; automated tests use mocks and do not call PayPal. Official KYAPay trust material and provider interoperability remain unverified.

The project's core principle is simple: **an AI agent should not be trusted to initiate a financial transaction merely because it can access a payment API.** Its authorization and transaction request should be evaluated before the request proceeds.

Built for the **PayPal AI Hackathon 2026**, the project combines Python-based security logic, PayPal Agent Toolkit integration, and a browser-based monitoring dashboard.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Dashboard Preview and Deployment Status](#dashboard-preview-and-deployment-status)
- [The Problem](#the-problem)
- [Our Solution](#our-solution)
- [Security Architecture](#security-architecture)
- [Transaction Evidence](#transaction-evidence)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [Judges' Testing Instructions](#judges-testing-instructions)
- [Security Considerations and Prototype Scope](#security-considerations-and-prototype-scope)
- [Roadmap](#roadmap)
- [License](#license)

---

## Project Overview

AI agents are increasingly capable of initiating actions on behalf of users, including interactions with commerce and payment services. As these agents become more autonomous, payment integrations need controls that help prevent unauthorized actions, replayed credentials, and transactions that exceed delegated permissions.

PayPal AI Trust Engine explores a layered approach to this problem through **TrustGuard Agent**, a verification workflow designed to check authorization and proof-of-possession signals before an optional order-creation request is sent through an injected provider adapter.

### Project Information

| Item | Details |
|---|---|
| Project | PayPal AI Trust Engine |
| Security Workflow | TrustGuard Agent |
| Backend | Python |
| Frontend | HTML, CSS, and JavaScript |
| Payment Integration | Injected PayPal Orders v2 adapter boundary (mocked in tests) |
| Intended Test Environment | PayPal Sandbox; interoperability not verified |
| Dashboard Hosting | GitHub Pages source; public deployment not verified |
| License | MIT |

## Dashboard Preview and Deployment Status

[Open the dashboard URL](https://antonytampubolon2-cell.github.io/paypal-ai-trust-engine-v2/dashboard_v2.html) as a navigation target only. **The current public Pages deployment has not been verified by this audit.**

The dashboard reads a static, unsigned `hasil.json` file. Build SHA/manifest checks identify the frontend build but do not authenticate transaction data or prove that backend security checks ran. The page therefore labels source data UNVERIFIED and authentication/policy status UNKNOWN unless an authenticated telemetry contract is implemented.

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

The static dashboard describes the intended Fraud Risk Engine (FRP) layer, but the page is not connected to authenticated telemetry and does not establish that live scoring ran.

The dashboard is a presentation interface, not a standalone guarantee that a transaction is safe. The backend does not provide a complete, independently verifiable FRP scoring pipeline.

### 5. PayPal Orders Adapter Boundary

The hardened entry point does not initialize the PayPal toolkit on import and does not enable capture actions. Order creation is possible only through an explicitly injected adapter after authentication and policy checks.

No live or Sandbox API call is performed by the test suite. A mocked adapter verifies that the outbound order payload uses the same checked merchant, amount, and currency. The real merchant-ID mapping remains unconfirmed.

Requests rejected by authentication or policy checks are blocked before the adapter is called. An order-created result is not treated as proof that a payment was completed or captured.

This integration is intended for controlled testing in the PayPal Sandbox, not for processing real payments.

---

## Transaction Evidence

**No PayPal order IDs are asserted as verified transaction evidence by the current implementation.** Legacy demo identifiers have been removed from this README because their provenance and current availability are not established by the checked-in backend or test results.

The automated tests use a mocked adapter and synthetic fixtures only. They do not call PayPal, create a Sandbox order, capture a payment, or prove real-provider interoperability.

For official Sandbox concepts, consult the [PayPal Sandbox Testing Guide](https://developer.paypal.com/sandbox-testing/overview/).

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
python -m pip install -r requirements-security.txt pyyaml playwright
python -m playwright install chromium
```

The hardened backend uses an injected PayPal adapter and the test suite uses mocks; these commands do not configure credentials or call PayPal. Browser tests require Playwright and Chromium.

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

- The JWT adapter fails closed unless the real KYAPay issuer, audience, public key, and algorithm are configured from authoritative issuer documentation. Synthetic test keys do not establish an external trust relationship.
- SQLite replay claims are atomic on a single host only; multi-instance deployment needs a shared atomic store.
- DPoP signature and binding checks are implemented, but full RFC 9449 interoperability and any issuer-specific nonce policy remain unverified.
- The delegation schema and merchant mapping are not confirmed by official contracts.
- Cumulative-spend reservation, provider idempotency, and reconciliation of ambiguous order-creation outcomes are not implemented.
- The FRP dashboard panel is descriptive only; the repository does not provide a complete, independently verifiable fraud-scoring pipeline.
- The dashboard consumes unsigned static JSON; manifest/SHA consistency is not transaction authenticity or backend telemetry.
- No PayPal API call, order creation, capture, refund, or money transfer was performed in the test runs.
- The manual Pages workflow has not been dispatched; public deployment, environment protections, and Pages source configuration remain unverified.

These limitations define the current prototype scope and provide a foundation for further development.

## Roadmap

Potential next steps include:

- Implementing complete cryptographic DPoP proof validation and applicable RFC 9449 checks.
- Integrating a persistent, shared anti-replay store with defined expiration and concurrency behavior.
- Strengthening authorization-policy evaluation for issuer, audience, merchant permissions, spending limits, and delegation rules.
- Connecting the FRP monitoring panel to a fully implemented and validated risk-scoring backend.
- Expanding automated tests for replay, expired grants, mismatched keys, unauthorized merchants, and spending-limit violations.
- Improving auditability and operational monitoring.
- Adding deployment and credential-management guidance suitable for a production environment.

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


## Cumulative spending reservations (prototype boundary)

The integrated dispatcher now requires an injected persistent `SQLiteSpendReservationStore`, an authoritative stable `grant_id`, and a caller-generated stable `reservation_idempotency_key` before it will call the PayPal adapter. Missing reservation configuration fails closed before outbound provider I/O.

The reservation ledger in `spend_reservations.py` uses SQLite `BEGIN IMMEDIATE` transactions, unique grant/idempotency keys, Decimal arithmetic, and a durable lifecycle:

- `RESERVED`: amount is held against the grant's cumulative limit.
- `SETTLED`: verified settlement evidence was recorded; amount remains consumed.
- `RELEASED`: only permitted with explicit confirmed-non-payment evidence.
- `EXPIRED`: only a reservation that never began provider dispatch may expire and release its hold.
- `RECONCILIATION_REQUIRED`: provider dispatch began but the outcome is ambiguous; the amount remains consumed.

Provider I/O occurs outside the database transaction. The dispatcher records dispatch-started before calling the adapter, persists a returned order ID as reconciliation evidence, and leaves the reservation held because order creation is not payment settlement. Ambiguous responses are not retried automatically.

**Deployment limit:** SQLite is supported only for processes on one host sharing the same persistent local database and correct filesystem locking. It is not a multi-host/distributed spend ledger. Do not run this configuration across multiple hosts. A shared atomic store and deployment-specific integration must be implemented and tested before multi-instance operation.

**External contract limit:** the code deliberately requires the caller to supply a stable authoritative grant ID rather than guessing a KYAPay claim name. The issuer's grant schema and PayPal merchant mapping remain unconfirmed. No real payment, authorization, capture, or deployment was performed by the regression tests.
