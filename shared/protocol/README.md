# shared/protocol – agent ↔ console contract

Single source of truth for the protocol between the DataBastion agent and the console (invariant I6).
The narrative design is in [docs/09-agent-protocol.md](../../docs/09-agent-protocol.md); when the two differ, `openapi.yaml` wins.

Owner: `agent-engineer`. **Every change requires a `security-reviewer` review.** A compatible change (e.g. an optional field) goes through a regular PR. An incompatible change needs a new ADR and a new version (`/api/agent/v2`).

## Layout
| Path | Content |
|------|---------|
| `openapi.yaml` | OpenAPI 3.1 contract: endpoints, headers, responses, and **all** JSON Schemas under `components/schemas` |
| `classifiers.json` | Classifier registry: the valid classifier ids of each `classifiers_version` |
| `classifiers.schema.json` | JSON Schema of the registry (keys `ClassifiersVersion`, ids `ClassifierId`, from `openapi.yaml`) |
| `fixtures/valid/<Schema>.<case>.json` | Bodies that must be accepted by `<Schema>` |
| `fixtures/invalid/<Schema>.<case>.json` | Bodies that must be rejected by `<Schema>` |
| `fixtures/invalid-expectations.json` | For each invalid fixture, the JSON Schema keyword it must fail on (so it fails for the intended reason) |
| `scripts/schema-lint.mjs` | Closure / bounds lint of every schema (used by `validate-fixtures.mjs`) |
| `scripts/schema-lint.test.mjs` | Self-test: the contract passes the lint, and known mutations (`{}`, `true`, nullable unbounded types, open objects…) are caught |
| `scripts/validate-fixtures.mjs` | Schema lint + fixture validation + coverage check + `x-databastion-max-bytes` check + registry check |
| `scripts/contract-ajv.mjs` | Builds the Ajv instance (contract schemas as `$defs`, registry schema) shared by the scripts |
| `scripts/classifier-registry.mjs` | Registry checks: schema, ids sorted, valid fixtures only use ids registered for their `classifiers_version` |
| `scripts/classifier-registry.test.mjs` | Self-test: the registry passes, known mutations (bad id, duplicate, empty list, unsorted…) are caught |
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
- `classifiers.json` conforms to `classifiers.schema.json`, its ids are sorted, and every valid fixture that carries a `classifiers_version` only uses classifier ids registered for it.

## Classifier registry (`classifiers.json`)
A map `classifiers_version -> [classifier ids]`, e.g. `{"2026.09.1": ["pii.birth_date", …]}`. The console rejects findings whose `classifiers_version` is not a key (`400`, `/classifiers_version`, `enum`) or whose `classifier` is not listed for that version (`400`, `/findings/<i>/classifier`, `enum`), and only issues `discovery.scan` jobs with a registered version. Rules:
- a published version is **never modified** (ids are frozen, see `agent/crates/classifiers/README.md`); a new or changed classifier is a new version, added by a compatible change (regular PR + `security-reviewer` review);
- ids sorted ascending, at most 200 per version (the `DiscoveryScanParams.classifiers` bound);
- the agent's compiled classifier set must equal the entry of its `CLASSIFIERS_VERSION` (contract test `agent/crates/classifiers/tests/contract_registry.rs`).

## Commands
Run from `shared/protocol/`:

```sh
npm ci                 # installs the pinned devDependencies (ajv, ajv-formats, yaml)
npm test               # schema-lint self-test + validate (offline)
npm run validate       # schema lint + fixtures + coverage
npm run lint           # Redocly, recommended-strict ruleset (downloads the pinned CLI)
npm run check          # lint + test
```

Validators must use Ajv 2020 with `ajv-formats`, `strict: true` and `strictRequired: false` (the contract uses `oneOf: [{required: [a]}, {required: [b]}]` for "exactly one of"), and declare the annotation keywords `discriminator`, `x-databastion-numeric-map`, `x-databastion-normalized-name` and `x-databastion-max-bytes`, as `scripts/contract-ajv.mjs` does. Patterns use Unicode property escapes (`\p{L}`, `\p{Cc}`…): they require the `u` flag in JavaScript (Ajv's default) and are compatible with the Rust `regex` crate.

## Contract extensions (`x-databastion-*`)
| Extension | Meaning |
|-----------|---------|
| `x-databastion-numeric-map` | The only allowed open object: numeric values, restricted key pattern, `maxProperties` |
| `x-databastion-normalized-name` | The agent normalizes the name before the uplink (indices -> `[]`, dynamic or classifier-matching segments -> `*`, LDAP entry DN -> parent container); see `Identifier` |
| `x-databastion-max-bytes` | Maximum serialized size of a batch, enforced by the agent (the console limit is 4 MiB) |

CI (from the repository root) runs `npx --yes @redocly/cli@2.54.3 lint shared/protocol/openapi.yaml`.

## Consumers
TypeScript and Rust types are **generated** from `openapi.yaml`, never written by hand (invariant I6). Each side commits its generated output, and a drift test fails when it no longer matches the contract: after any change here, run both generators and commit the result.

| Side | Regenerate | Output | Drift test |
|------|------------|--------|------------|
| Console | `pnpm protocol:generate` (from `console/`) | `console/src/generated/protocol/types.gen.ts`, `schemas.gen.json`, `classifiers.gen.ts` (registry as a `const`) | `console/src/lib/protocol/generated.test.ts` (`pnpm test`) |
| Agent | `cargo run -p databastion-protocol-codegen` (from `agent/`) | `agent/crates/protocol/src/generated.rs` | `agent/crates/protocol/tests/drift.rs` (`cargo test`); registry: `agent/crates/classifiers/tests/contract_registry.rs` (`include_str!`, no generated file) |

- **Console**: validates every agent API input against these schemas with Ajv (unknown fields rejected), and tests its agent API with `fixtures/` (every valid fixture accepted, every invalid one rejected). For **agent -> console** bodies (findings, events, heartbeat…), Ajv is the enforcement point for keywords the Rust types cannot express. The console must also validate every **outgoing** `JobList` (and any console -> agent body) against its schema before serving it (ROADMAP P1-A `/jobs`, P2-D scan launching), as defense in depth. Besides the JSON Schema keywords, an `ErrorDetail.keyword` sent by the console can be one of its own:
  - `maxBytes`: the body exceeds the schema's `x-databastion-max-bytes`;
  - `maskRatio`: a `MaskedSample` has fewer than 50 % `*`;
  - `falseSchema`: Ajv's `false schema` error (e.g. `JobStatusUpdate`'s `error` on a non-failed status);
  - `invalid`: fallback when an Ajv keyword does not match the `ErrorDetail.keyword` pattern, or when no detail is available;
  - `notFound`: unknown job or target, or one not assigned to the calling agent (`404`).

  Console-side cross-field checks also reuse JSON Schema keywords: `const` (value must equal the job's or the target's), `maximum` (`matched > sampled`, `sampled > sample_rows`), `enum` (classifier registry), `maxItems` (per-job findings cap), `formatMaximum` (timestamp in the future). The list, pointers and order of the checks are in `openapi.yaml` ("Console-side checks").
- **Agent**: serializes only through the generated types; masked samples and fingerprints come from `classifiers::masking`; each item is validated and sanitized before spooling (see the `openapi.yaml` description). The Rust generator (typify) replaces a few schemas with **hand-written** types in `databastion-protocol`: credentials `AgentSecret` and `EnrollmentToken` (`src/secret.rs`: redacted `Debug`, zeroized) and `Uuid` / `UuidV7` (`src/ids.rs`: canonical lowercase, version 7 checked). The header of `generated.rs` lists the keywords removed or rewritten before generation (`if` / `then` / `else`, `not`, `const`); typify also ignores most `minItems` / `maxItems` / `maxProperties` and number bounds. The invalid fixtures serde therefore accepts are listed with a reason in `agent/crates/protocol/tests/fixtures.rs` (`NOT_ENFORCED_BY_SERDE`, exact list).
- **Optional filter arrays** (`DiscoveryScanParams.databases`, `schemas`, `include_objects`, `classifiers`): absent means "all", so an empty list is rejected (`minItems: 1`) rather than read as "none" or "all". The Rust generator emits them as `Option<Vec<_>>` so that `[]` stays distinguishable from absent; for these console -> agent payloads, the **agent's** job mapping (`TryFrom`, ROADMAP P2-B / P2-C) is the enforcement point and must reject `Some([])`; the console's outgoing validation is a second layer, not a substitute. The Rust generator fails closed if `minItems >= 1` appears anywhere it cannot rewrite (a `$ref` to an array schema, a `type` list, a nested object, a composition).
