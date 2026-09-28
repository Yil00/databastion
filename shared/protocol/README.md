# shared/protocol – agent ↔ console contract

Single source of truth for the protocol between the DataBastion agent and the console (invariant I6).
The narrative design is in [docs/09-agent-protocol.md](../../docs/09-agent-protocol.md); when the two differ, `openapi.yaml` wins.

Owner: `agent-engineer`. **Every change requires a `security-reviewer` review.** A compatible change (e.g. an optional field) goes through a regular PR. An incompatible change needs a new ADR and a new version (`/api/agent/v2`).

## Layout
| Path | Content |
|------|---------|
| `openapi.yaml` | OpenAPI 3.1 contract: endpoints, headers, responses, and **all** JSON Schemas under `components/schemas` |
| `fixtures/valid/<Schema>.<case>.json` | Bodies that must be accepted by `<Schema>` |
| `fixtures/invalid/<Schema>.<case>.json` | Bodies that must be rejected by `<Schema>` |
| `fixtures/invalid-expectations.json` | For each invalid fixture, the JSON Schema keyword it must fail on (so it fails for the intended reason) |
| `scripts/validate-fixtures.mjs` | Bounds lint of the schemas + fixture validation + coverage check |
| `redocly.yaml` | Redocly ruleset for local linting (`recommended-strict`) |

`<Schema>` is a key of `components/schemas` in `openapi.yaml` (e.g. `FindingsBatch`, `HeartbeatRequest`). Fixture data is fake: `example.com` domains, documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`), secrets made of `EXAMPLE`.

### Why the schemas live in `openapi.yaml`
The schemas sit in `components/schemas` rather than in separate `schemas/*.json` files:
- one self-contained file: no cross-file `$ref` resolution for Redocly, for code generators or for the console's runtime validator;
- OpenAPI 3.1 schemas are plain JSON Schema 2020-12, so they are directly usable by Ajv (the validation script moves them to `$defs`, nothing else);
- a reviewer sees the endpoint and its payload in the same diff.

## Rules enforced by `validate-fixtures.mjs`
- Every object schema is closed with `additionalProperties: false` (invariant I2). The only exception is a map marked `x-databastion-numeric-map: true` (heartbeat metrics): keys restricted by pattern, values numbers only.
- Every string has `maxLength` (or `enum` / `const`), every array `maxItems`, every number `minimum` and `maximum`.
- Every fixture in `valid/` passes, every fixture in `invalid/` fails with its expected keyword.
- Every request and response body schema has at least one valid and one invalid fixture.

## Commands
Run from `shared/protocol/`:

```sh
npm ci                 # installs the pinned devDependencies (ajv, ajv-formats, yaml)
npm run validate       # bounds lint + fixtures + coverage
npm run lint           # Redocly, recommended-strict ruleset
npm test               # both
```

CI (from the repository root) runs `npx --yes @redocly/cli@2.54.3 lint shared/protocol/openapi.yaml`.

## Consumers
- **Console**: validates every agent API input against these schemas (unknown fields rejected), and tests its agent API with `fixtures/`.
- **Agent**: serializes only through the generated types; masked samples and fingerprints come from `classifiers::masking`.
- TypeScript and Rust types are **generated** from `openapi.yaml`, never written by hand (ROADMAP P0-B, item 3).
