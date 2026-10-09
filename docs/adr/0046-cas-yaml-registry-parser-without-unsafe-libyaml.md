# ADR-0046: CAS YAML service definitions read by an own parser of the pre-scanned subset, without `unsafe-libyaml`

- **Status**: Accepted (2026-10-09; the maintainer accepted the recommended answers to the five open questions)
- **Date**: 2026-10-09
- **Refines**: [ADR-0041](0041-cas-connector.md) (which stays Accepted): decision 4 ("Parser": "the workspace `serde_json` (and the workspace `serde_yaml_ng` for YAML)", and its refinement of 2026-10-08, YAML service registry) and decision 13 ("Its dependencies are workspace crates only (`serde`, `serde_json`, `serde_yaml_ng`, …)"). The accepted YAML subset, the refusals, the bounds and the visitor are unchanged.
- **Context references**: review of #169 (YAML service registries), finding L5; ROADMAP [phase 8 follow-ups](../ROADMAP.md#phase-8-follow-ups); `agent/crates/connector-cas/src/parse/yaml.rs` (pre-scanner), `src/parse/definition.rs` (`parse_yaml_definition`, `parse_with`, the closed visitor), `src/proptests.rs`, `fixtures/registry/` (JSON / YAML pairs); `agent/fuzz/fuzz_targets/cas_registry_yaml.rs` and the nightly AddressSanitizer campaign (`.github/workflows/fuzz-nightly.yml`, #179); `agent/deny.toml`, `.github/workflows/advisories.yml`; [08-engine-capabilities.md](../08-engine-capabilities.md#apereo-cas)

## Why an ADR and not a design note
The change replaces the parser that ADR-0041 decisions 4 and 13 name, at a security boundary: the CAS service definitions are files that CAS administrators write, not the agent's operator. It also removes a dependency from the attacker-reachable path of the agent binary. An accepted ADR names the current parser, so changing it needs a refinement.

## Context

### The path today
`parse_yaml_definition` runs in two stages. First, `yaml::prescan` scans the raw bytes. It follows libyaml's tokenizer (indentation stack, simple-key candidates, flow levels, block scalars) and refuses anything outside a small subset. The refusals:

- anchors, aliases, tags other than Java class hints, merge keys, directives and second documents;
- explicit or complex keys, tabs outside quoted scalars, and indentation indicators;
- flow nesting beyond 4, nesting beyond 32, more than 32 768 lines or 196 608 tokens;
- anything its model of libyaml does not follow.

It blanks the class hints and the single-line credential values, and returns a `Zeroizing<Vec<u8>>` copy. Second, that copy goes to `serde_yaml_ng::Deserializer::from_slice` and through the closed visitor that JSON definitions also use (`parse_with`, generic over any `serde::Deserializer`).

`serde_yaml_ng` 0.10.0 (last release 2024-05-26, MIT) is a fork of the deprecated `serde_yaml`. It is built on `unsafe-libyaml` 0.2.11 (last release 2024-03-17, MIT): a machine translation of libyaml's C into `unsafe` Rust, which its author has archived (per the review of #169; not re-checked here, because GitHub was not reachable from this environment). Every scalar goes through libyaml's buffers and then into a plain `String` that is freed unwiped: ADR-0041's refinement records that "the YAML parser's internal copies of scalars are not wiped".

### What the advisory databases say (RustSec `advisory-db` at 2026-10-09)
- `unsafe-libyaml`: one advisory, RUSTSEC-2023-0075 (unsound unaligned write on 32-bit targets, patched in 0.2.10; 0.2.11 is not affected). **There is no "unmaintained" advisory**, so the agent's advisories job (`cargo deny check advisories`, which fails on unmaintained crates by default when an advisory exists) has nothing to flag today.
- `serde_yaml` (0.9.34+deprecated): RUSTSEC-2018-0005 only (old); no unmaintained advisory either.
- `serde_yaml_ng`: no advisory.
- `yaml-rust`: RUSTSEC-2024-0320, unmaintained (points to `yaml-rust2`).

### Other users of `serde_yaml_ng` in the workspace
- `databastion-core` parses `agent.yaml` (`config.rs`, `config/cas.rs`) with derived types, `serde_yaml_ng::Value` (`metrics.local_listen`) and the library's error paths. `agent.yaml` is written by root, is mode `0600` / `0640`, and is read at start and on reload. Whoever can write it already controls the agent: it is a different trust level from the CAS registry.
- `databastion-protocol-codegen` reads `shared/protocol/openapi.yaml`. It is a dev-dependency only, never linked into the binary.

So `unsafe-libyaml` stays in the shipped graph as long as the core keeps `serde_yaml_ng`, whatever happens to the CAS path.

## Options

### (a) An own parser for the subset the pre-scanner accepts
The pre-scanner becomes the tokenizer. It already decides, for every byte, which token it belongs to (it keeps libyaml's indentation stack, simple-key candidates, flow levels and block-scalar extents), so it emits tokens instead of only checking them. A small parser builds events from the tokens: block mappings and sequences (indentless sequences included), flow mappings and sequences up to depth 4, and plain, single-quoted, double-quoted, literal and folded scalars. A `serde::Deserializer` over those events (`deserialize_any`, `MapAccess`, `SeqAccess`) feeds the existing visitor unchanged.

- **Size.**
  - Tokenizer changes over the pre-scanner (about 1 000 production lines today): about 300 lines.
  - Scalar values: line folding of plain and quoted scalars, the double-quoted escapes libyaml accepts (the pre-scanner already validates them, `escapes_valid`), and block scalars with chomping (indentation indicators stay refused): about 350 lines.
  - Event builder: about 350 lines.
  - Deserializer with scalar resolution: about 300 lines. Resolution follows `serde_yaml_ng`'s rules (YAML 1.2 core schema: `null` / `~` / empty, booleans, decimal / `0x` / `0o` integers, floats with `.inf` / `.nan`), so findings do not change.
  - In all, about 1 300 production lines under `#![forbid(unsafe_code)]`, with `clippy::indexing_slicing` and `clippy::string_slice` denied as in the rest of the crate.
- **Risk.** A new parser can be wrong. Memory safety is not at stake (no `unsafe`). The concern is semantics: a misread structure gives wrong findings or locations. The worst case is a value read under a key other than its own. Credential keys are protected in two places that do not depend on the parser's structure: the pre-scanner's blanking by position, and the visitor's key rule. The project already ships its own parsers for hostile inputs (the MySQL protocol, BSON, LDAP BER: [ADR-0018](0018-mysql-mariadb-grants-and-connector.md), [ADR-0026](0026-mongodb-connector.md), [ADR-0029](0029-openldap-connector.md)).
- **One tokenizer.** Today the pre-scanner models libyaml, and "wherever its model could differ from libyaml's it refuses". A divergence that it does not see means that blanking and parsing disagree on where a value is. With (a), the scanner that refuses, the scanner that blanks and the scanner that parses are the same code, so they cannot disagree.
- **Fuzzability.** The subset is a pure function from bytes to visitor output. `serde_yaml_ng` can stay a **dev-dependency** (test and fuzz only; `deny.toml` excludes dev-dependencies from the shipped graph) and serve as a differential oracle: on every input the pre-scanner accepts, both parsers must give the same `Definition`, or both must refuse. That differential target is stronger than today's "never panics nor hangs" target.
- **Zeroization.** Every buffer is ours. Scalars without escapes or folding are borrowed from the `Zeroizing` file copy (`visit_borrowed_str`: no copy at all). Unescaped or folded scalars are built in `Zeroizing<String>`. The residual "the YAML parser's internal copies of scalars are not wiped" goes away.

### (b) A maintained safe-Rust YAML crate
The offline cargo registry of this environment holds only `serde_yaml` 0.9.34, `serde_yaml_ng` 0.10.0 and `unsafe-libyaml` 0.2.11. The candidates below were checked on crates.io (index and API) and in their published sources, on 2026-10-09:

| Crate | Latest | Maintenance | `unsafe` in its own source | Licence | MSRV | serde | Fit |
|---|---|---|---|---|---|---|---|
| `saphyr-parser` | 0.1.0 (2026-09-19) | active, 0.x: 12 releases in 2026 | none (no `forbid`); dependency `arraydeque` 0.5.1 (last release 2023-02, has `unsafe`, used by its buffered input only) | MIT OR Apache-2.0 | 1.85 | no: an event parser (`Event::Scalar(Cow<'input, str>, …)`, borrowed for `&str` input), anchors as ids, tags as values | an own `Deserializer` over its events (about 400 lines) could feed the visitor |
| `saphyr` | 0.1.0 (2026-09-19) | active, 0.x | none; `hashlink` (has `unsafe`), `ordered-float`, `encoding_rs` | MIT OR Apache-2.0 | 1.85 | no: a document tree (`Yaml`), whole document in owned strings | the tree copies every scalar unwiped; adds nothing over `saphyr-parser` |
| `yaml-rust2` | 0.13.0 (2026-09-11) | active (same author as `saphyr`) | none; `arraydeque`, `hashlink` (both have `unsafe`) | MIT OR Apache-2.0 | 1.85 | no: tree loader, event parser underneath | as `saphyr`; `saphyr` is its successor |
| `serde_yaml2` | 0.1.3 (2025-05-12) | quiet: no release in 17 months | none; on `yaml-rust2` | MIT OR Apache-2.0 | not declared | yes, but over a `yaml-rust2` tree (whole document first, unwiped) | weak |
| `serde-saphyr` | 1.3.0 (2026-09-16) | active; 1.0 on 2026-07-31 | `#![forbid(unsafe_code)]`; parser `granit-parser` 1.3.0 (a `saphyr-parser` fork, `forbid(unsafe_code)`, MSRV 1.81); with `deserialize` only: `num-traits`, `annotate-snippets`, `smallvec`, `encoding_rs_io` | MIT OR Apache-2.0 | **1.89** (the agent's MSRV is 1.88) | yes: `with_deserializer_from_slice` hands out a `Deserializer` that can drive the visitor; a `Budget` (aliases, anchors, depth, nodes, events) and a merge-key policy | the closest drop-in, but about 38 000 lines of source (many optional features: includes with a file resolver, figment, validators), 14 months old, and over the MSRV |
| `serde_yaml_bw` | 2.5.8 (2026-09-07) | active | 51 lines with `unsafe`; still depends on `unsafe-libyaml-norway` | MIT OR Apache-2.0 | not declared | yes | does not remove the C translation |
| `unsafe-libyaml-norway` | 0.2.15 (2024-12-21) | a fork of `unsafe-libyaml`, quiet since | the same translated C | MIT | 1.71.1 | (backend) | same code, another owner |

None has a RustSec advisory. All licences are on the `deny.toml` allow-list.

Common to every crate in (b): **the pre-scanner models libyaml's tokenizer, not theirs.** Its safety argument ("refuse wherever the model could differ") would have to be redone against a different tokenizer, here YAML 1.2 in the `yaml-rust` lineage, whose handling of tabs and of some simple-key and flow edge cases is not libyaml's. A differential fuzz target between the pre-scanner and the new parser would then be needed to find those divergences, and blanking would stay a second model of someone else's parser. `serde-saphyr` would also need an MSRV bump to 1.89 (a release decision since #129) and brings a large surface for a subset of a few hundred grammar rules.

### (c) Keep `serde_yaml_ng`
Rely on the pre-scanner (the parser never sees an anchor, alias, tag, merge key or second document, and the token bound caps its memory), the property tests, the 10-second fuzz smoke in CI and the nightly 600-second ASan run of `cas_registry_yaml`, which instruments `unsafe-libyaml` because it is Rust. Watch the advisories. The C translation stays reachable by any CAS administrator who can write a registry file. Nobody fixes it upstream if the campaign finds a bug. The unwiped scalar copies stay.

## Decision
Option (a), for the CAS path only:

1. **Own parser.** `connector-cas` gains `parse/yaml/` with three modules: the scanner (today's pre-scanner, now also emitting tokens), the event builder and a `serde::Deserializer`. `parse_yaml_definition` runs scan, refusals and blanking, then events, then the existing `parse_with` visitor. The accepted subset is **exactly** today's: every input refused today is refused, and every input accepted today gives the same `Definition`. Widening the subset (anchors, values on the next line, …) is a later decision.
2. **Scalar resolution** matches `serde_yaml_ng` 0.10 on the accepted subset, so the JSON / YAML pair equivalence and the findings do not change. Integers keep being classified as their decimal text (ADR-0041 refinement of 2026-10-08).
3. **Buffers.** Scalars are borrowed from the `Zeroizing` file copy when they need no transformation. Otherwise they are built in `Zeroizing<String>`. No other copy is made. The event builder holds at most one document's events, under the same token bound as today (196 608), and resolves nothing it does not hand to the visitor.
4. **Dependencies.** `serde_yaml_ng` moves from `[dependencies]` to `[dev-dependencies]` of `connector-cas` (the differential oracle). The fuzz workspace keeps it for the differential target. `connector-cas`'s new code adds no crate.
5. **`agent.yaml` keeps `serde_yaml_ng`** in `databastion-core` (open question 3). Its input is root-owned configuration, it needs serde's whole data model (enums, `Value`, error paths) that the CAS subset parser does not offer, and swapping it would change the operator-facing error messages. The binary therefore still links `unsafe-libyaml`, but only for a file that only root can write. A later ADR moves `agent.yaml` once a safe serde YAML crate meets the criteria of open question 3.
6. **Advisories.** The advisories job keeps scanning the shipped graph. When RustSec publishes an unmaintained advisory for `unsafe-libyaml` or `serde_yaml_ng` (open question 4), the job fails as designed. The fix is then a reasoned `ignore` in `agent/deny.toml` that names this ADR and limits the scope to `agent.yaml`, with a `security-reviewer` review, until `agent.yaml` moves.

## Consequences
- **Code** (`agent-engineer`, `security-reviewer` review: a parser at a security boundary):
  - `connector-cas` `parse/yaml.rs` splits into `parse/yaml/{scan,events,de}.rs`;
  - `parse/definition.rs` calls the new deserializer;
  - `Cargo.toml` moves `serde_yaml_ng` to the dev-dependencies;
  - `fuzz.rs` gains the differential entry point.

  No protocol, configuration or documented-behaviour change. ADR-0041's YAML residual ("internal copies of scalars are not wiped") is removed from [08-engine-capabilities.md](../08-engine-capabilities.md#apereo-cas) by `docs-keeper` after the implementation.
- **Tests** (all kept, plus the differential ones):
  - the JSON / YAML pair equivalence tests on `fixtures/registry/`;
  - the property tests of `proptests.rs`: the rendered-document generator, anchor / alias / tag injection, blanking, and the "no input byte survives except closed facts" property, now also run against the new parser;
  - the pre-scanner's unit tests (each refusal, block-scalar ends, encodings, bounds);
  - the hostile files (billion laughs, merge keys, `!!python/…` tags, deep nesting, oversized token counts);
  - the `cas_registry_yaml` fuzz target and its nightly ASan run.

  New:
  - a differential property test: for every generated document, the new parser and `serde_yaml_ng` (dev-dependency) give the same `Definition`, or both refuse;
  - a differential fuzz target `cas_registry_yaml_diff` with the same rule, added to the CI smoke and to the nightly campaign (600 s), seeded with the fixtures and the hostile files;
  - a zeroization test: no scalar of a credential key is ever allocated outside a `Zeroizing` buffer, checked with a counting allocator in test.
- **Estimated size**: about 1 300 production lines (of which about 1 000 are the existing scanner, reworked), 800 lines of tests and a fuzz target. 4 to 6 days with one review round.
- **Residual risks.**
  - A semantic bug in the new parser on an input the pre-scanner accepts. The differential tests against `serde_yaml_ng` bound it on the generated and fuzzed space, and the visitor's key rules and the positional blanking still protect credential values.
  - `unsafe-libyaml` stays in the binary for `agent.yaml` (root-owned input).
  - What CAS itself (Jackson / SnakeYAML) reads may still differ from the agent's reading on unusual inputs, as today. That affects findings, never the refusals.

## Rejected alternatives
- **Option (b), `serde-saphyr`**: the closest drop-in, but over the MSRV (1.89), very large for a few hundred grammar rules, and modelled on another tokenizer than the pre-scanner's, so the pre-scanner's safety argument would have to be redone. It stays the first candidate for `agent.yaml` (open question 3).
- **Option (b), `saphyr-parser` with an own deserializer**: about the same code to write as (a) for the deserializer, plus a pre-scanner that models a third-party tokenizer still in 0.x (12 releases this year). Option (a) writes slightly more and depends on nothing.
- **Option (b), `yaml-rust2`, `saphyr`, `serde_yaml2`**: tree loaders that copy the whole document into unwiped strings before any visitor runs.
- **Option (b), `serde_yaml_bw` and `unsafe-libyaml-norway`**: still the translated C.
- **Option (c)**: keeps archived, unsafe, translated C on a path any CAS administrator can feed, with nobody to fix what the ASan campaign finds, and keeps the unwiped copies.
- **Moving `agent.yaml` to the CAS subset parser**: the subset does not cover the configuration's needs (enums, `Value`, error paths), and widening it for a root-owned file would grow the attack surface of the CAS path.

## Open questions (answered)
Each answer is the recommendation of this ADR, accepted by the maintainer on 2026-10-09.
1. Option (a), an own parser for the pre-scanned subset, as proposed, or (b) `serde-saphyr` with an MSRV bump to 1.89, or (c) keep `serde_yaml_ng` with the ASan campaign?
   **Answer (decided by the maintainer on 2026-10-09)**: (a). It removes `unsafe` code and unwiped copies from the only YAML path hostile input reaches, keeps one tokenizer for refusing, blanking and parsing, and adds no dependency.
2. Keep `serde_yaml_ng` as a dev-dependency of `connector-cas` and in the fuzz workspace, as the differential oracle?
   **Answer (decided by the maintainer on 2026-10-09)**: yes. It is never linked into the binary (`deny.toml` excludes dev-dependencies), and it is the only independent reference for the subset's semantics.
3. `agent.yaml`: keep `serde_yaml_ng` in the core for now, as proposed, and with which criteria to move it later?
   **Answer (decided by the maintainer on 2026-10-09)**: keep it for now (root-owned input). Move it, by a later ADR, to a safe serde YAML crate once one has `forbid(unsafe_code)`, an MSRV no higher than the agent's, 12 months of releases since its 1.0 and no open advisory. `serde-saphyr` is the current candidate (1.0 on 2026-07-31, MSRV 1.89).
4. RustSec has no unmaintained advisory for `unsafe-libyaml`. Should the maintainer, after confirming the archive, submit one (`informational = "unmaintained"`), knowing that the agent's own advisories job will then fail until a scoped `ignore` is reviewed (decision 6)?
   **Answer (decided by the maintainer on 2026-10-09)**: yes. It warns every user of the crate, and the scoped `ignore` records that the agent keeps it for root-owned configuration only.
5. Keep the pre-scanner's positional blanking of credential values once the parser is ours and never copies them?
   **Answer (decided by the maintainer on 2026-10-09)**: yes, as defence in depth: it costs one pass, and it keeps credential values out of the event builder even if a later change makes the parser copy scalars.

## Implementation note (2026-10-09)
Recorded with the implementation (#187), after its security review.

- **Two passes of one scanner.** The same scanner code runs twice: in pre-scan mode over the raw bytes (refusals, blanking), then in parse mode over the blanked copy (libyaml's tokens). The two passes therefore read different texts, and "they cannot disagree" (option (a), "One tokenizer") holds only because anything that blanking could change structurally is refused in the pre-scan. Blanked credential values are single-line scalars right after their key's `:`, so blanking removes no token that moves the indentation or a simple key. Class hints are tags: a tag is accepted only on the line of the `:`, `-`, `[` or `,` it follows, as Jackson writes it. A tag alone on a later line moved the block indentation on the raw bytes but not on the blanked copy (security review of #187, M1). That could swap the form of the top-level `clientSecret`, a residual since #169, and gave a differential false positive. libyaml refused such files anyway. They are now refused, with refusal tests and hostile fuzz seeds. A refusal in parse mode, which would mean the passes disagree, fails closed (the file is refused).
- **Zeroization test.** Decision "Tests" planned a counting allocator. It needs `unsafe impl GlobalAlloc`, which the workspace lint `unsafe_code = "forbid"` rules out in every target, tests included. It is replaced by a memory scan:
  - The test parses a definition whose credential values hold a run-time marker in every form that reaches the parser, including a top-level `clientSecret` over 1 KiB with escapes.
  - It drops everything, then searches the process's writable memory through `/proc/self/maps` and `/proc/self/mem` (Linux only). The search buffers are allocated before parsing, so the search allocates nothing.
  - It finds no copy, and a control per block size shows that an unwiped copy is found. The former `serde_yaml_ng` path left dozens of copies.
  - Keys (field names) are still copied into ordinary strings by the visitor; only value scalars are covered.
