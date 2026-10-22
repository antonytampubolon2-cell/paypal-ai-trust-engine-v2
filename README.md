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

## Live Demo

**Explore the deployed monitoring dashboard:**

[Open the PayPal AI Trust Engine Live Dashboard](https://antonytampubolon2-cell.github.io/paypal-ai-trust-engine-v2/dashboard_v2.html)

The dashboard provides a visual overview of the security modules, transaction-related information, statistics, and audit-oriented monitoring data exposed by the project.

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

The prototype brings together authorization-claim validation, an in-memory anti-replay cache, selected DPoP binding checks, and PayPal Sandbox integration.

Its intended workflow is:

1. Receive an AI-agent payment request and its associated authorization data.
2. Validate required authorization claims and delegation constraints.
3. Reject expired grants or previously used token identifiers.
4. Evaluate the supplied DPoP-related proof fields and key binding.
5. Block the request if a verification check fails.
6. If the checks pass, attempt to create a PayPal Sandbox order.
7. Display relevant project and transaction information through the monitoring dashboard.

The repository currently uses synthetic authorization payloads and mock DPoP data in its verification demonstrations. These tests demonstrate the intended control flow; they should not be interpreted as proof of a complete production-grade identity or DPoP implementation.

---

## Security Architecture

TrustGuard Agent organizes the prototype into the following security layers.

### 1. KYAPay Token Verifier

The KYAPay verification module checks for required authorization claims, including:

- Issuer (`iss`)
- Subject (`sub`)
- Audience (`aud`)
- Expiration (`exp`)
- Token identifier (`jti`)
- Delegation grant (`delegation_grant`)

It also checks token expiration and selected delegation constraints, including the grant's validity period and spending limit.

These checks are intended to help establish whether the submitted authorization data contains the required information and remains within the configured constraints.

**Implementation note:** The current demonstration performs structural and selected claim checks against synthetic payloads. It does not establish an external identity or independently validate every issuer and audience claim against a trusted policy.

### 2. JTI Anti-Replay Cache

The JTI Anti-Replay Cache records accepted token identifiers and rejects an identifier that has already been used while it remains in the cache.

The implementation uses an in-memory Python data structure and removes expired entries.

This demonstrates the basic anti-replay control:

**Accept a valid token identifier once; reject a repeated identifier.**

The current cache is process-local and is not a persistent or distributed production cache.

### 3. DPoP Verifier — RFC 9449

The prototype includes a DPoP-oriented verifier referencing [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html).

The current implementation checks selected proof fields, including:

- `htm` — expected HTTP method
- `htu` — expected HTTP URI
- `jti` — unique proof identifier
- `jwk` — public-key information

It also computes a JWK thumbprint and compares it with the token's `cnf.jkt` value. A separate in-memory cache is used to reject a repeated DPoP proof identifier.

These checks demonstrate selected binding and replay-detection concepts.

**Important limitation:** The published prototype does not perform full cryptographic signature verification of a DPoP proof. Complete RFC 9449 enforcement requires additional validation, including proof-signature verification and the applicable protocol checks.

### 4. Fraud Risk Engine (FRP)

The Live Dashboard includes a Fraud Risk Engine (FRP) monitoring panel intended to provide visibility into suspicious transaction activity and anomaly-related status.

The dashboard is a monitoring interface, not a standalone guarantee that a transaction is safe. The currently published `main_public.py` does not provide a complete, independently verifiable FRP scoring pipeline.

### 5. PayPal Agent Toolkit Integration

The project initializes PayPal Agent Toolkit with Sandbox context and enables selected order-related actions.

In the end-to-end demonstration, a payment request that passes the TrustGuard checks proceeds to a PayPal Sandbox order-creation attempt.

Requests rejected by the TrustGuard verification workflow are blocked before that order-creation call.

This integration is intended for controlled testing in the PayPal Sandbox, not for processing real payments.

---

## Transaction Evidence

The following PayPal Sandbox Order IDs are provided as references for judging and review.

| # | PayPal Sandbox Order ID |
|---|---|
| 1 | `7R3064957MB0759941` |
| 2 | `3HD92730V0626752B` |
| 3 | `8RJ05941XL2772705` |

These identifiers are references supplied for the project demonstration. Their availability and associated transaction details may depend on the Sandbox account and credentials used during review.

PayPal Sandbox is a simulated testing environment. Orders created there are test resources and are separate from live payment activity.

For additional information, consult the official [PayPal Sandbox Testing Guide](https://developer.paypal.com/sandbox-testing/overview/).

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
pip install paypal-agent-toolkit openai-agents
```

Use a compatible Python environment and resolve any dependency errors before proceeding.

---

## Judges' Testing Instructions

This section is intended to help judges run the public Python demonstration using PayPal Sandbox credentials.

**Sandbox credentials must be provided through a private, secure channel or supplied by the judge. Do not publish a Client Secret in this README, a GitHub issue, a commit, or a public project submission.**

### Step 1 — Obtain Sandbox Credentials

Obtain the Sandbox application's:

- **Client ID**
- **Client Secret**

Use credentials associated with a PayPal Developer Sandbox application, not live-production credentials.

Official resource: [PayPal Developer Dashboard](https://developer.paypal.com/dashboard/).

### Step 2 — Prepare the Public Script for Environment Variables

The currently published `main_public.py` contains placeholder assignments that overwrite environment variables.

Open `main_public.py` in a text editor and locate these lines:

```python
os.environ["PAYPAL_CLIENT_ID"] = "MASUKKAN_CLIENT_ID_ANDA_DI_SINI"
os.environ["PAYPAL_CLIENT_SECRET"] = "MASUKKAN_SECRET_ANDA_DI_SINI"
```

**Delete those two assignment lines from the local copy of the script.** Do not replace them with actual credentials.

The script already reads `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET` when it initializes the PayPal Toolkit. Removing the hard-coded placeholder assignments allows those values to be supplied by the environment.

This is a local testing preparation step; it does not change the published GitHub source unless you separately commit a code change.

### Step 3 — Configure Credentials

#### Windows PowerShell

In the same PowerShell session, from the repository directory, run:

```powershell
$env:PAYPAL_CLIENT_ID = "YOUR_SANDBOX_CLIENT_ID"
$env:PAYPAL_CLIENT_SECRET = "YOUR_SANDBOX_CLIENT_SECRET"
```

Replace the example values locally with the actual Sandbox credentials supplied for the test.

#### macOS or Linux

In the same terminal session, run:

```bash
export PAYPAL_CLIENT_ID="YOUR_SANDBOX_CLIENT_ID"
export PAYPAL_CLIENT_SECRET="YOUR_SANDBOX_CLIENT_SECRET"
```

Replace the example values locally with the actual Sandbox credentials supplied for the test.

Avoid sharing terminal screenshots or logs that expose the Secret.

### Step 4 — Run the Verification and Sandbox Demonstration

With the virtual environment activated and the environment variables set, execute:

```bash
python main_public.py
```

The script runs the security demonstrations and then attempts a PayPal Sandbox order-creation request if the verification workflow permits it.

**Important:** The current demonstration is configured to attempt a Sandbox order for **USD 50.00**. Running it can create a test order in the configured Sandbox account. It does not represent a live payment.

### Step 5 — Review the Console Output

Inspect the console output for:

- PayPal Agent Toolkit initialization and available tools
- KYAPay token validation results
- Replayed-token rejection
- Expired-token rejection
- DPoP field, binding, and replay-check results
- TrustGuard allow-or-block decisions
- The PayPal Sandbox order-creation response
- The final status reported by the demonstration

The exact response and any generated order identifiers depend on successful authentication, the Sandbox environment, and the PayPal API response.

### Step 6 — Review the Live Dashboard

Open:

[PayPal AI Trust Engine — Live Dashboard](https://antonytampubolon2-cell.github.io/paypal-ai-trust-engine-v2/dashboard_v2.html)

Use the dashboard to review its security-module status panels and the transaction-related information available from its published data source.

The dashboard is a separate, browser-based monitoring surface. Running `main_public.py` locally does not by itself guarantee that local console results will automatically appear in the deployed dashboard.

### Testing Notes

- Use Sandbox credentials only.
- Do not commit secrets to GitHub.
- Use the provided order IDs as review references rather than assuming they will be retrievable by every Sandbox application.
- If authentication fails, verify that the credentials belong to the Sandbox application and that both environment variables are available in the same shell session.
- If a Python dependency fails to install, verify the Python environment and the package's current installation requirements.

---

## Expected Test Results

A successful demonstration should show the verification workflow evaluating its synthetic test cases, including valid authorization data, a repeated token identifier, and expired authorization data.

The DPoP test cases are designed to demonstrate acceptance of a matching proof, rejection of a repeated proof identifier, and rejection of an HTTP URI mismatch.

For the end-to-end path, a request that passes the configured TrustGuard checks should proceed to the PayPal Sandbox order-creation attempt. The script reports the resulting API response or an error.

An authorization-check success is **not equivalent to a guarantee that PayPal will successfully create an order**. The external request can still fail due to invalid credentials, API errors, dependency problems, or other environment-related issues.

---

## Security Considerations and Prototype Scope

PayPal AI Trust Engine is a security-focused hackathon prototype.

The current implementation demonstrates several useful concepts, but it should not be deployed as a production payment-security gateway without further engineering and validation.

Known limitations include:

- KYAPay verification is performed against synthetic payloads and selected claims; it is not a complete external identity-verification service.
- Token and DPoP replay caches are in-memory and process-local.
- The DPoP demonstration checks selected fields and JWK binding but does not verify the full DPoP proof signature.
- The FRP dashboard panel is not evidence of a complete backend fraud-scoring system.
- The end-to-end workflow uses test authorization data and PayPal Sandbox.
- Production deployment would require comprehensive validation, persistent replay protection, secure key management, robust audit logging, monitoring, rate limiting, and additional testing.

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
