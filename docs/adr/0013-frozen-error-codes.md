# ADR-0013: Error codes are frozen within a protocol major version

- **Status**: Accepted
- **Date**: 2026-09-28
- **Context references**: #38 (classifier registry and console-side checks, compatible contract change) and its `security-reviewer` review

## Context
Every non-2xx answer of the agent API carries an `Error` body whose `code` is a closed enum in `shared/protocol/openapi.yaml`. The Rust types are generated from the contract, and the v1 agent decodes the body with serde into the generated `ErrorCode` enum, with no fallback variant (`agent/crates/core/src/uplink.rs`, `classify`). An unknown `code` therefore makes the **whole** error body fail to decode: the agent loses `details[]` (so a `400` with item pointers turns into a whole-batch drop instead of dropping only the offending items) and `min_protocol` on `426`, and only logs "error without a valid error body".

While closing the contract gaps of phase 2 (#38), several new situations needed an answer: `501` for endpoints not implemented yet (`POST /events` before phase 4), the per-job findings cap, the job window, and the classifier registry checks. Adding codes such as `not_implemented` or `limit_exceeded` would have broken every deployed v1 agent in the way described above. #38 reused existing codes instead, and its security review asked for the rule to be recorded.

## Decision
- **The `Error.code` values of a protocol major version are frozen.** For v1: `invalid_request`, `unauthorized`, `not_found`, `conflict`, `batch_conflict`, `rotation_conflict`, `invalid_secret`, `payload_too_large`, `protocol_unsupported`, `rate_limited`, `unavailable`, `internal`.
- **New situations reuse an existing code** and are told apart by the HTTP status, `details[].pointer` and `details[].keyword`. Examples from #38: `501` + `unavailable` for an unimplemented endpoint; `400` + `/findings` + `maxItems` for the per-job cap; `404` + `/job_id` + `notFound` for a job outside its findings window; `400` + `enum` for the classifier registry. Console-side checks reuse JSON Schema keyword names where one fits (`const`, `maximum`, `enum`, `maxItems`, `formatMaximum`) and add console keywords (`notFound`, `maxBytes`, `maskRatio`, `falseSchema`, `invalid`) only within the existing `keyword` pattern, which v1 agents decode as a plain string.
- **Adding, removing or renaming a code is an incompatible change**: it needs a new ADR and a new protocol version (`/api/agent/v2`).
- **Agent behavior is driven by the status first**, then by pointers and keywords; the code is used for logs and metrics. This is already the v1 agent's behavior (docs/09, "Agent handling") and stays the rule.
- **Lenient decoding from v2 (recommendation, to be applied when v2 is designed):** v2 agents decode `ErrorCode` with an `Unknown` fallback (e.g. `#[serde(other)]`), so an unknown code still yields the rest of the body (`details`, `min_protocol`) and is handled by status. With that in place, adding a code can become a compatible change within v2. The console must keep emitting only codes that the oldest supported agent of the major version knows, until that version's agents are all lenient.
- **v1 cannot adopt lenient decoding retroactively**: v1 agents already deployed decode strictly, and the console cannot know whether a given v1 agent is lenient. Any new code sent to v1 agents would break the strict ones, so v1 stays frozen for its whole lifetime even if later v1 agent builds decode leniently.

## Consequences
- New console behaviors never need a new code within v1; reviewers reject a contract diff that changes the `Error.code` enum under `/api/agent/v1`.
- Error details become the main discriminator: pointers and keywords must stay documented (`openapi.yaml`, `ErrorDetail.keyword`; overview in [09-agent-protocol.md](../09-agent-protocol.md#errors)).
- Some codes carry broad meanings (`unavailable` covers both `503` and `501`); logs and metrics must record the status next to the code.
- The v2 design must include the `Unknown` fallback in the generated agent types (the typify output or a hand-written wrapper, as for the other hand-written protocol types).

## Rejected alternatives
- **Adding `not_implemented` (and similar) codes to v1**: breaks decoding of the whole error body on every deployed v1 agent.
- **Making `code` an open string in v1**: an incompatible change of the schema for the same reason, and it removes the closed set that keeps error bodies free of arbitrary text.
- **Lenient decoding in v1 agents only**: does not help, because the console cannot tell strict from lenient v1 agents and must remain compatible with both.
