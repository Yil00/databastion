# Agent API v1 (`/api/agent/v1/*`)

Server side of the agent ↔ console protocol. **Nothing is implemented yet**: the
catch-all route `[...path]/route.ts` answers `501 not_implemented` to every
request and never reads the request body.

Rules for the endpoints to come (see [docs/09-agent-protocol.md](../../../../../../docs/09-agent-protocol.md)):

- The contract is `shared/protocol/openapi.yaml` (invariant I6). Types and
  validators are **generated** into `src/generated/protocol/`; no hand-written
  protocol types.
- Every request is validated against the generated schema and rejected on
  unknown fields (`additionalProperties: false`).
- The console never initiates a connection to an agent (I1) and never stores
  target database credentials (I3).
- Agent secrets are stored hashed (argon2id).
- Each endpoint is a sibling route (e.g. `heartbeat/route.ts`), which takes
  precedence over the catch-all placeholder.
