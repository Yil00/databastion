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
| `scripts/schema-lint.mjs` | Closure / bounds lint of every schema (used by `validate-fixtures.mjs`) |
| `scripts/schema-lint.test.mjs` | Self-test: the contract passes the lint, and known mutations (`{}`, `true`, nullable unbounded types, open objects…) are caught |
| `scripts/validate-fixtures.mjs` | Schema lint + fixture validation + coverage check + `x-databastion-max-bytes` check |
| `redocly.yaml` | Redocly ruleset for local linting (`recommended-strict`) |

`<Schema>` is a key of `components/schemas` in `openapi.yaml` (e.g. `FindingsBatch`, `HeartbeatRequest`). Fixture data is fake: `example.com` domains, documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`), secrets made of `EXAMPLE`.

Fixture secrets and tokens (`dbs_EXAMPLE…`, `dbe_EXAMPLE…`) are deliberately low-entropy so that secret scanners ignore them. They are valid for the **schema** only: the console's low-entropy check (see `AgentSecret`) rejects them, so console tests of `/rotate` must generate a real secret.

### Why the schemas live in `openapi.yaml`
The schemas sit in `components/schemas` rather than in separate `schemas/*.json` files:
- one self-contained file: no cross-file `$ref` resolution for Redocly, for code generators or for the console's runtime validator;
- OpenAPI 3.1 schemas are plain JSON Schema 2020-12, so they are directly usable by Ajv (the validation script moves them to `$defs`, nothing else);
- a reviewer sees the endpoint and its payload in the same diff.

## Rules enforced by the scripts
- Every object schema is closed with `additionalProperties: false` (invariant I2). The only exception is a map marked `x-databastion-numeric-map: true` (heartbeat metrics): keys restricted by pattern, values numbers only.
- No `true` or `{}` schema, except directly under `not` / `if` / `then` / `else`. Every value schema has a `type`, `$ref`, `enum`, `const` or composition.
- Every string has `maxLength` (or `enum` / `const`), every array `maxItems`, every number `minimum` and `maximum`, including each member of a `type` array such as `[string, "null"]`.
- Valid fixtures of a schema with `x-databastion-max-bytes` stay under that size.
- Every fixture in `valid/` passes, every fixture in `invalid/` fails with its expected keyword.
- Every request and response body schema has at least one valid and one invalid fixture.

## Commands
Run from `shared/protocol/`:

```sh
npm ci                 # installs the pinned devDependencies (ajv, ajv-formats, yaml)
npm test               # schema-lint self-test + validate (offline)
npm run validate       # schema lint + fixtures + coverage
npm run lint           # Redocly, recommended-strict ruleset (downloads the pinned CLI)
npm run check          # lint + test
```

Validators must use Ajv 2020 with `ajv-formats`, `strict: true` and `strictRequired: false` (the contract uses `oneOf: [{required: [a]}, {required: [b]}]` for "exactly one of"), and declare the annotation keywords `discriminator`, `x-databastion-numeric-map`, `x-databastion-normalized-name` and `x-databastion-max-bytes`, as `validate-fixtures.mjs` does. Patterns use Unicode property escapes (`\p{L}`, `\p{Cc}`…): they require the `u` flag in JavaScript (Ajv's default) and are compatible with the Rust `regex` crate.

## Contract extensions (`x-databastion-*`)
| Extension | Meaning |
|-----------|---------|
| `x-databastion-numeric-map` | The only allowed open object: numeric values, restricted key pattern, `maxProperties` |
| `x-databastion-normalized-name` | The agent normalizes the name before the uplink (indices -> `[]`, dynamic or classifier-matching segments -> `*`, LDAP entry DN -> parent container); see `Identifier` |
| `x-databastion-max-bytes` | Maximum serialized size of a batch, enforced by the agent (the console limit is 4 MiB) |

CI (from the repository root) runs `npx --yes @redocly/cli@2.54.3 lint shared/protocol/openapi.yaml`.

## Consumers
- **Console**: validates every agent API input against these schemas (unknown fields rejected), and tests its agent API with `fixtures/`.
- **Agent**: serializes only through the generated types; masked samples and fingerprints come from `classifiers::masking`; each item is validated and sanitized before spooling (see the `openapi.yaml` description).
- TypeScript and Rust types are **generated** from `openapi.yaml`, never written by hand (ROADMAP P0-B, item 3).
