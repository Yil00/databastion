# ADR-0003: No raw sensitive value leaves the agent

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
If the console stores the sensitive data it detects, it becomes the most lucrative target in the information system. The initial scope planned AES-GCM encryption of payloads on top of TLS, but since the key lives on the console, this does not protect against its compromise.

## Decision
- The agent only sends: location, classifier, confidence, volume, **masked samples**, **HMAC-SHA256 fingerprints** computed with a key local to the agent that never leaves it.
- Database credentials stay on the agent's host.
- The protocol schema forbids additional fields (`additionalProperties: false`); the console rejects non-conforming batches.
- Application-level AES-GCM encryption of payloads is removed. TLS 1.3 is mandatory. Sensitive fields are encrypted at rest on the console side.

## Consequences
- The console cannot display the full value of a finding. This is intentional. A user who wants to see the data goes to the database, with their own permissions.
- Correlation between targets of the **same agent** is possible through the fingerprint. Across different agents, it is not (different keys). An optional shared key may be considered later.
- Mandatory automated test: seed known fake PII → verify that none of it appears in cleartext in the console's database.

## Rejected alternatives
- Storing samples in cleartext, encrypted with a console key: same risk in case of compromise.
