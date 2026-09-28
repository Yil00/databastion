# ADR-0004: Agent metrics reported through the console

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
The initial scope mentioned "Prometheus metrics exposed by each agent". Prometheus works in *pull* mode: it queries each target, which requires an inbound port to the agents. This contradicts the outbound-only principle.

## Decision
- Agents expose **no port** by default.
- Their metrics (counters, durations, spool size, target status) are sent in the **heartbeat**.
- The console re-exposes them, along with its own metrics, on **a single** `/metrics` endpoint in Prometheus format (labels `agent_id`, `target_id`). This endpoint is authenticated and restricted to the internal network.
- Option `metrics.local_listen` (disabled by default, `127.0.0.1` only) for on-host diagnostics.

## Consequences
- Prometheus scrapes only one target: the console.
- Agent metric granularity follows the heartbeat frequency (30 s), which is enough for this kind of tool.
- The "silent agent" state itself becomes a metric and an alert (`databastion_agent_last_seen_seconds`).

## Rejected alternatives
- **Pushgateway**: an extra component, not designed for this use case.
- **OTLP push to a collector**: relevant later for customers who already run an OpenTelemetry collector. May be added as an option (phase 2).
