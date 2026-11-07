# Security Event Integration Specification — Design Only

**Status:** Future integration design. **No SIEM, SOAR, or EDR integration is implemented or active.**
**Review baseline:** `c95a1b5cac9b81dcc01408a5a3c0259360ff622c`.

## Current state

Repository inspection found no security-operations connector, webhook, event sink, syslog/CEF/LEEF/OCSF exporter, or Splunk, Sentinel, CrowdStrike, or other vendor adapter. Runtime Pydantic request/response models and SQLite transaction/review records are not an event integration. The dashboard's sample `audit_trail` display and offline-demo `audit_count` do not constitute a general event schema or exported stream. The `opentelemetry-api` dependency alone is not instrumentation or an exporter.

The envelope below is a proposal for a future separately authorized integration. It does not modify current logging, create events, or send data anywhere.

## Proposed versioned JSON envelope

```json
{
  "schema_version": "trustguard.security-event.v1",
  "event_id": "evt_local_demo_0001",
  "event_time": "2026-11-07T12:00:00Z",
  "event_type": "transaction.screened",
  "producer": {
    "service": "trustguard",
    "environment": "local-demo",
    "classification": "simulated"
  },
  "correlation_id": "corr_local_demo_0001",
  "subject": {
    "transaction_ref": "LOCAL-TEST-ONLY-HIGH"
  },
  "outcome": "held",
  "risk": {
    "decision": "HOLD",
    "score": 0.69845,
    "score_type": "synthetic_anomaly_ranking_not_probability",
    "model_version": "trustguard-isolation-forest-synthetic-v1"
  },
  "reason_codes": ["ANOMALY_THRESHOLD_EXCEEDED"],
  "transaction_state": "HOLD",
  "payment_dispatch_state": "NOT_DISPATCHED",
  "approval_required": true,
  "sensitive_data_classification": "no_raw_token_no_credentials_pseudonymized_reference"
}
```

All values above are illustrative synthetic values, not a captured operational event. `risk.score` is optional and must be omitted when no score exists. If present, `score_type` is mandatory; it must not imply calibrated fraud probability.

### Proposed field rules

- `schema_version`, unique `event_id`, UTC `event_time`, `event_type`, `producer`, `correlation_id`, `outcome`, `payment_dispatch_state`, and data-classification metadata are required.
- `producer.classification` is an explicit enum such as `simulated`, `test`, or `live`; producers may not upgrade a simulated event to live based on display/import alone.
- `subject.transaction_ref` should be pseudonymous or local-only. Do not place payment card data, personal details, raw tokens, JWT claims, DPoP proofs, private keys, passwords, client secrets, access tokens, raw provider payloads, or unnecessary account IDs in the event.
- `risk`, `reason_codes`, `transaction_state`, `approval_required`, and reviewer metadata are optional and reflect only observed state. A missing risk score is not zero. A reviewer event records only authorized reviewer identity/reference and decision; no credential.
- Provider evidence references may be included only if the corresponding provider observation was actually obtained and independently reconciled. A create response alone is not completion evidence.
- `simulated` and `NOT_DISPATCHED` must remain explicit in local demo events. An event schema is not proof that an event was exported, delivered, or acted upon.

## Suggested event types

A future producer could define versioned types such as `transaction.screened`, `transaction.held`, `review.recorded`, `dispatch.started`, `dispatch.unknown`, and `provider.outcome.reconciled`. Define valid state transitions and reason-code enums before production. Do not generate `dispatch.*` or provider-outcome events from a static dashboard or synthetic report unless labeled simulated.

## Future authorized transport and operations

Before implementation, authorize the receiving system, data fields, retention, environment, and event volume. Use authenticated TLS transport with certificate validation and least-privilege service identity (for example, mutually authenticated TLS or short-lived OAuth client credentials from an approved secret manager). Do not embed secrets in source, event payloads, or URLs.

Use at-least-once delivery with a stable `event_id` idempotency key, bounded exponential backoff with jitter, and receiver `Retry-After` handling. Persist delivery attempts/status separately from the canonical payment ledger; cap queues and define back-pressure, retention, dead-letter, replay, and operator-alert behavior. Authenticate and audit administrative replay. Never retry payment actions because an event-delivery attempt failed. Event-export failure must not convert a `HOLD`, `UNKNOWN`, or `NOT_DISPATCHED` payment state into success.

Record minimal delivery audit metadata (event ID, destination alias, attempt number, time, response class, result) without logging credentials or raw payloads. Protect logs and queues with access control and retention limits. Test duplicate delivery, replay, receiver outage, malformed responses, redaction, and schema-version compatibility before enabling any integration.

Any future mapping to OCSF, CEF, a vendor API, SIEM, SOAR, or EDR must be separately designed and tested. This document is a schema/integration **design**, not an active integration or enterprise-readiness claim.
