# Agent API v1 (`/api/agent/v1/*`)

Server side of the agent ↔ console protocol. **Nothing is implemented yet**: the
catch-all route `[...path]/route.ts` answers `501 not_implemented` to every
request and never reads the request body.

Rules for the endpoints to come (see [docs/09-agent-protocol.md](../../../../../../docs/09-agent-protocol.md)):

- The contract is `shared/protocol/openapi.yaml` (invariant I6). Types and the
  JSON Schema bundle are **generated** into `src/generated/protocol/`; no hand-written
  protocol types.
- Every request body is validated with `src/lib/protocol/validate.ts`
  (`validateHeartbeatRequest(body)`…, Ajv 2020 on the generated schema bundle) and
  rejected on unknown fields (`additionalProperties: false`). On failure it returns
  `{pointer, keyword}` details (at most 20) built only from contract property names
  and array indices: they never echo a submitted value or an unknown field name, so
  they can be returned to the agent and logged. Pointers are truncated at the first
  segment that cannot be disclosed, so they always match the contract's `ErrorDetail`.
- `ok: true` from `validateSchema` is **schema-only**. Every endpoint (P1-A, P2-D…) must
  then call `checkSemantics(name, value)`, which enforces the rules JSON Schema cannot
  express: `x-databastion-max-bytes` (keyword `maxBytes`) and the 50 % `*` rule of
  `MaskedSample` (keyword `maskRatio`). Reserved metric names are ignored by the
  `/metrics` exporter, not rejected.
- The console never initiates a connection to an agent (I1) and never stores
  target database credentials (I3).
- Agent secrets are stored hashed (argon2id).
- Each endpoint is a sibling route (e.g. `heartbeat/route.ts`), which takes
  precedence over the catch-all placeholder.
