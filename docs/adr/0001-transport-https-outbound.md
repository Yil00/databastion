# ADR-0001: Outbound HTTPS transport with long-poll

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
Databases sit in sensitive network zones. Opening an inbound port to them is unacceptable for most security teams. Agents must also traverse corporate proxies.

## Decision
- The agent is always the client. Everything goes over HTTPS (TLS 1.3) on the console's port 443.
- Responsiveness is achieved through **long-poll** on `GET /api/agent/v1/jobs` (25 s).
- Versioned JSON, OpenAPI contract in `shared/protocol/`.

## Consequences
- Works behind any standard HTTP(S) proxy and reverse proxy.
- Console → agent command latency < 1 s in practice, without a persistent bidirectional connection.
- One HTTP request permanently open per agent: size the console accordingly (a few hundred agents for the MVP).

## Rejected alternatives
- **Bidirectional gRPC**: more efficient, but passes poorly through some proxies and adds complexity (end-to-end HTTP/2). To be reassessed in phase 2.
- **WebSocket**: marginal gain over long-poll, more complex reconnection handling.
- **Simple polling every 5-30 s**: more latency for as many requests.
