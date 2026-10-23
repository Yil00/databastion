# ADR-0022: Protocol capability negotiation for optional fields

- **Status**: Accepted
- **Date**: 2026-09-29
- **Refines**: [ADR-0013](0013-frozen-error-codes.md) (which stays Accepted), its rule that a compatible change is an optional field: optional fields added after protocol 0.1.0 are sent only once the receiver announced it accepts them
- **Refined by**: [ADR-0042](0042-hold-items-of-unlisted-engines.md) (decision 9 for engine values gated by ADR-0039 decision 8: items of an unlisted engine are held, not stripped)
- **Context references**: ROADMAP P4-D (protocol follow-up to the P4-A and P4-C security reviews), its security review (M1: an agent upgraded before the console loses every heartbeat), `shared/protocol/openapi.yaml` ("Compatibility and capability negotiation", `Capability`, `HeartbeatResponse.accepts`, `HeartbeatRequest.accepts`)

## Context
Every object schema of the agent protocol is closed (`additionalProperties: false`, invariant I2). The console rejects any request body with an unknown field with `400`, at any depth, and stores nothing. The v1 agent decodes every response and job with generated types that deny unknown fields. [ADR-0013](0013-frozen-error-codes.md) and the protocol README say a compatible change is "an optional field". Until now, that held only if the receiver was upgraded first:
- **Agent upgraded before the console.** An optional request field unknown to the console gets the whole body rejected. For a heartbeat, every heartbeat fails. The agent treats the `400` as a non-retryable rejection and keeps going, so no heartbeat is accepted until the console is upgraded. The console then:
  - shows the agent silent after 90 s and raises `agent.silent` after 10 intervals by default;
  - keeps target status frozen;
  - answers `404` to results for targets declared after the upgrade.
  For findings and events, every item carrying the field is dropped and an agent-integrity alert is raised.
- **Console upgraded before the agents.** An optional response or job field unknown to the agent makes the agent fail to decode the reply. For a heartbeat response, the heartbeat counts as failed; for a job, the job is lost.

The P4-D protocol change adds the first optional request fields meant for later use: `TargetStatus.notes`, `AccessEvent.bytes`, and the `JobProgress` coverage counters. Deployments do not upgrade the console and the agents atomically, and one console serves agents of several versions. A rule that depends on upgrade order is a runtime trap. The decision has to be made before 0.1.0, because every released agent must already carry the mechanism.

## Decision
1. **Capability tokens.** A `Capability` is a snake-case token `<object>.<field>`, e.g. `access_event.bytes`, with up to two more segments for a revision, e.g. `target_status.note_labels.2026_10`. The contract pattern checks the form only, and a party ignores tokens it does not know. A `CapabilityList` holds at most 64 unique tokens.
2. **Request fields (agent -> console).** `HeartbeatResponse.accepts` lists the optional request fields and features the console accepts. The agent keeps the list from its latest heartbeat response and sends an optional request field introduced after protocol 0.1.0 only when that list names it:
   - never before its first heartbeat response, nor when the list is absent;
   - after a heartbeat rejected with `400` (for example a console rolled back), the agent forgets the list, so its next heartbeat carries none of these fields.
   The fields added by P4-D are gated this way: `target_status.notes`, `access_event.bytes`, `job_progress.coverage`. For 0.1.0 the console lists every such field it accepts, in a tested constant (`console/src/server/agent-api/capabilities.ts`). A token is added to that constant in the same change that makes the console accept the field.
3. **Response and job fields (console -> agent).** `HeartbeatRequest.accepts` lists the optional console -> agent fields and features the agent build accepts. The console sends a console -> agent field introduced after protocol 0.1.0 (in any response or job) only when the agent's latest heartbeat named it. None exists yet, so the agent omits the list. "Upgrade the console first" therefore holds for request fields only: a new response field must be negotiated.
4. **New enum values** in a request field (e.g. a new `TargetNoteLabel`) are negotiated like a field, with a revision token. Until the console lists it, the agent sends the fallback value (`other`).
5. **Form-only registries need no negotiation.** For ids whose schema checks the form only (`Signal` with `signals.json`, `TargetNoteCode` with `target-notes.json`), an older console accepts a well-formed id it does not know. It stores the id and shows it raw. Such registries are append-only; CI compares them with `dev`, `main` and, on push, the previous tip.
6. **Still incompatible** (unchanged from ADR-0013): removing or renaming a field, making a field required, narrowing a pattern or an enum, and adding an `Error.code` value. These need a new ADR and `/api/agent/v2`.
7. **Agent implementation.** The agent's `ConsoleCapabilities` holds the set, keeping at most the first 64 tokens (`CapabilityList.maxItems`). `console_accepts(token)` is the only way a producer may decide to send a gated field.
8. **Multi-replica consoles.** A console running several replicas (web processes behind a load balancer) lists a token only once **every** replica accepts the field. Otherwise an agent told by one replica could send the field to another replica that rejects it. During a rolling upgrade:
   - first roll out the build that accepts the field without listing its token;
   - once no replica runs an older build, roll out (or switch on) the listing.

   The single-process MVP console lists its constant directly.
9. **Obligations of the first gated producer.** No producer exists yet. The first change that makes the agent send a gated field must also:
   - **Clear the capabilities on any `400` whose body carried a gated field**, not only on a heartbeat. This covers `POST /events`, `POST /findings` and `POST /jobs/{id}/status`: the console that rejected it may be an older replica or a rolled-back build.
   - **Resend the items pointed at with the gated fields stripped**, rather than dropping them. A `400` on an item that carried a gated field is more likely an old console than a bad item, so dropping it would lose data that an older console accepts without the field.
   - **Hold target-note codes as a closed Rust enum** (`NoteCode`, with `NoteCode::ALL` and `as_str`). A contract test against `target-notes.json` checks both directions, as `contract_signals.rs` does for signals. A code is never built with `format!` or from engine text.

## Consequences
- Agents and consoles can be upgraded in either order without losing heartbeats. A new optional request field simply stays unsent until the console announces it.
- Adding `accepts` to `HeartbeatResponse` is itself a response field unknown to agents built before this change. It is introduced before 0.1.0, so every released agent knows it. Pre-release agent builds must be upgraded together with the console.
- Each new optional field now needs a token, a console constant entry and a producer gate. Reviewers check all three.
- `accepts` is informational and bounded. It cannot widen what the agent collects (I2, I4): it only allows the agent to send fields that the contract already defines.
- The console may accept a field before it uses it: `access_event.bytes` is accepted but not stored yet. "Accepts" means "does not reject".
- The form-only id patterns (`Signal`, `TargetNoteCode`) are narrowed before 0.1.0 to letters and `_` only: 1 to 6 words of 1 to 16 letters, no digits, so an id cannot carry a number such as an account, card or phone number. After 0.1.0, narrowing them further would be an incompatible change.

## Rejected alternatives
- **Upgrade the console first, as a documented procedure only**: an operator mistake loses every heartbeat of the upgraded agents, and nothing detects it early.
- **Open schemas (`additionalProperties: true`) for new fields**: breaks I2. An unknown field could carry a raw value, and the console could not reject it.
- **Negotiating on the protocol version (`X-DataBastion-Protocol`) or on `agent_version`**: too coarse. Features land independently between versions, and a version number does not tell which optional fields a given console build accepts.
- **Agent fallback that retries a rejected heartbeat without its optional fields**: every heartbeat would cost two requests against an old console. It would also have to guess which field caused the `400`, because pointers name the object, never the unknown property.
- **Lenient decoding of unknown response fields in the agent** (serde without `deny_unknown_fields`): weakens the closed-schema defense in the console -> agent direction (jobs must never carry unexpected content), and v1 agents already deployed decode strictly.

## Implementation note (2026-10-21): the first agent capability token

Records #280 (not released yet). The decisions are unchanged; decision 3's "None exists yet, so the agent omits the list" described the state at the time it was written and no longer holds.

- **The first console -> agent value form.** Since #280, `SensitiveObject.object` in `audit.configure` jobs is an `ObjectName`: an `Identifier`, or, on a `redis` or `valkey` target only, a `KeyPattern`. An agent built before #280 decodes the field as an `Identifier` and cannot decode a job carrying a key pattern that is not one, so it would lose the whole job. A value form that a console -> agent field accepts only after protocol 0.1.0 is therefore negotiated like a new field, under decision 3, with the token `sensitive_object.key_pattern` (contract: "Compatibility and capability negotiation", `HeartbeatRequest.accepts`, `SensitiveObject`).
- **Agent.** The agent lists `sensitive_object.key_pattern` in `HeartbeatRequest.accepts` (`AGENT_ACCEPTS` in `agent/crates/core/src/capabilities.rs`, the only token of this build). It checks every received key pattern against the whole `KeyPattern` schema and refuses an `audit.configure` job whose key pattern names a target of another engine (`invalid_params`).
- **Console.** The console stores, per agent, the tokens of its own list (`AGENT_TOKENS` in `console/src/server/agent-api/capabilities.ts`) that the agent's latest heartbeat named (`agents.accepts`, migration `0041`), and ignores the others. It sends a key pattern that is not an `Identifier` only to an agent that lists the token, checks again at delivery, and otherwise leaves the object out and counts it (the counter and page note of #235 stay for older agents). Settings are queued again when a heartbeat changes the agent's tokens (#280 review M2).
- **What decision 3 implies, now applied.** "Upgrade the console first" still holds for request fields only. For this value form the order does not matter: an older agent never lists the token and gets no key pattern; an older console never sends one.

## Implementation note (2026-10-23): the token hold for multi-replica rollouts

Records the console switch for decision 8, decided by the maintainer on 2026-10-23 after the end-of-phase-9 security review finding L1 (the console listed every token it accepts, statically, so decision 8's two-step rollout could not be followed). The decisions are unchanged.

- **The switch.** `DATABASTION_AGENT_TOKENS_HOLD`, set to a console release line (`X.Y`), makes the heartbeat answer list only the tokens that release line listed (`RELEASE_ACCEPTS` in `console/src/server/agent-api/capabilities.ts`, through `listedAccepts`). It changes the listing only: request validation, the engine gate (`unlistedEngineDetails`) and storage keep using the full `CONSOLE_ACCEPTS`, so a held console accepts and stores every field it knows, as decision 8's first step requires ("the build that accepts the field without listing its token"). Removing the variable is the second step ("switch on the listing").
- **Values.** Unset or empty: no hold, every token listed. `0.8`: the list shipped by 0.8.0, 0.8.1 and 0.8.2 (identical), which holds back the tokens added since: `access_event.objects_overflowed` (ADR-0053), `target_status.name_case` (ADR-0055), `location.altered` and `object_ref.altered` (ADR-0056) and `target_status.note_labels.2026_10_c` (#280, the `on_failure_probe` label, which a 0.8 replica rejects). The engine tokens and every earlier token are in that list. Any other value is a configuration error: the web and worker processes refuse to start (fail closed). A release line is added when its successor lists a new token; its entry is the list it shipped, never edited.
- **Procedure.** Set the hold to the running release line on every web replica before rolling out the new build (an older build ignores the variable), roll out, then remove it once no older replica remains: [deploy/README.md](../../deploy/README.md#rolling-upgrade-of-several-console-replicas). A rollout from a release older than 0.8.0 is not covered by `0.8`.
