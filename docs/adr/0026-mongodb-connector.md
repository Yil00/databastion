# ADR-0026: MongoDB connector: client, grants, sampling and field paths

- **Status**: Proposed
- **Date**: 2026-09-29
- **Context references**: P5-A, branch `feat/p5-a-mongodb-discovery` (`agent/crates/connector-mongodb`, `agent/crates/core/src/config.rs`, `dev/mongo/initdb/`); the MongoDB counterpart of [ADR-0012](0012-postgresql-agent-grants.md) / [ADR-0015](0015-postgresql-connector-decisions.md) (PostgreSQL) and [ADR-0018](0018-mysql-mariadb-grants-and-connector.md) / [ADR-0020](0020-mysql-mariadb-connector-as-merged.md) (MySQL / MariaDB). Audit (P5-B, P5-C) is out of scope.

## Context
Phase 5 starts with MongoDB Discovery: sample documents, walk nested fields and arrays, classify the values, and report findings per database, collection and normalized field path (contract `Location`). The other connectors fixed the rules this one must follow: read-only and bounded (I4), declared targets only (I5), credentials local (I3), masking before the uplink (I2), rustls only, honest `check()`, closed notes ([ADR-0022](0022-protocol-capability-negotiation.md)), no database resource held across `FindingSink::submit().await` ([05-security.md](../05-security.md#connector-obligations)).

MongoDB raises questions the SQL connectors did not:

- **The client.** [03-tech-stack.md](../03-tech-stack.md) planned the official `mongodb` crate. Checked on version 3.9.1 with `default-features = false, features = ["rustls-tls"]`: it builds without OpenSSL, but
  - `rustls-tls` always pulls `webpki-roots` 1.0 (license `CDLA-Permissive-2.0`, not in the `agent/deny.toml` allow-list), and the driver uses that bundled Mozilla list as its only trust store when no CA file is given: the system store (`rustls-native-certs`, used by the uplink and the other connectors) cannot be used, and the driver takes no caller-built rustls configuration;
  - its `rust-version` is 1.88, above the workspace MSRV (1.85);
  - it enables tokio's `process` and `fs` features (the `mongocryptd` spawning code is compiled in) and depends on `socket2` directly;
  - it runs server discovery and monitoring: from a replica-set member it learns the other members from `hello` and connects to them, and keeps monitoring connections open in background tasks. A host named by the server is not a declared target (I5, [ADR-0006](0006-target-discovery.md)); a hostile server could name any address;
  - authentication negotiates the mechanism from the server's list (SCRAM-SHA-1 included), reply messages are read up to 48 MiB, rustls buffering is unbounded, and errors carry the server's message text.
- **Grants.** [05-security.md](../05-security.md#recommended-database-accounts-read-only) recommends `read` on the targeted databases plus `clusterMonitor`. `read` includes `changeStream` (every future write of the database, values included), `dbHash` and `find` on `system.js`; `clusterMonitor` includes `inprog` (other sessions' operations with their literals), `find` on `system.profile` of every database (other users' profiled queries) and `getCmdLineOpts`. Discovery needs none of these.
- **No schema.** Field names are data-driven: map keys can be e-mail addresses, phone numbers or ids (dynamic keys, contract `Identifier` note, [ADR-0009](0009-name-normalization-and-item-sanitization.md)); arrays nest; a value can be a string, a number, a `Decimal128`, a date, a binary.
- **Read-only has no server-side switch.** There is no read-only session or transaction mode: what the connector sends and what the role allows are the only controls.
- **Sampling cost.** `$sample` uses a random cursor only when the sample is under 5 % of the collection (WiredTiger, first stage); otherwise it scans and sorts the whole collection.

## Decision
1. **Own client for a closed subset of the wire protocol, no driver crate** (as [ADR-0018](0018-mysql-mariadb-grants-and-connector.md) decision 3 did for MySQL).
   - `OP_MSG` only (opcode 2013), one body section, no compression negotiated, no exhaust (`moreToCome` in a reply is refused), no checksum sent (a reply checksum is skipped; TLS protects integrity). Replies other than `OP_MSG`, or answering another request, end the connection.
   - The reply length is checked on the 16-byte header **before** the body is read: at most 16 MiB + 64 KiB (the server's largest reply document plus framing). BSON is parsed by the connector's own bounded reader (lengths checked against the enclosing document, nesting depth bounded, fail closed on anything malformed).
   - Closed command set, built in code: `hello`, `saslStart`, `saslContinue`, `buildInfo`, `connectionStatus`, `listDatabases`, `listCollections`, `count`, `find`, `aggregate` (one pipeline, see decision 6), `killCursors`. No write command, no `getMore`, no user-supplied filter or pipeline; database and collection names only ever appear as string values (`$db`, the command's collection argument), never as field names or operators.
   - Minimum server: wire version 13 (MongoDB 5.0). An older server, or one without `hello`, is reported `unsupported`.
   - Dependencies: the workspace TLS crates (`rustls`, `tokio-rustls`, `rustls-native-certs`), `hmac` / `sha2` (SCRAM, PBKDF2 written on `hmac`), `stringprep` (SASLprep; already in the lock through tokio-postgres), `getrandom` and `base64` (already used by the core). No new license, no MSRV change.
2. **One declared host, direct connection.** The target is one `host`/`port` or a Unix `socket`: a standalone, one replica-set member, or a `mongos`. The connector never connects to a host named by the server (no replica-set discovery), does not support `mongodb+srv` (no DNS SRV / TXT lookups that could inject hosts or options), and keeps no pool or monitoring connection: one connection per scan (replaced after an error that leaves it unusable, or when idle for 60 s), one per `check()`. Every read carries `$readPreference: {mode: "secondaryPreferred"}`: through a `mongos` reads go to secondaries when there are some; on a directly addressed secondary the read is allowed. Scanning a whole replica set means declaring the member to read from.
3. **Authentication: SCRAM-SHA-256 only.**
   - `authSource` from `targets[].mongodb.auth_source` (default `admin`). The password is read from its `agent.yaml` reference into zeroized memory, SASLprepped (a password that SASLprep refuses fails authentication), salted with the server's salt; the derived keys are zeroized.
   - The server's iteration count must be at least 4096, its nonce must extend the client's (24 random bytes), and its signature (`v=`) is verified before any other command runs (mutual authentication). A failure is `authentication_failed`.
   - Refused or not implemented: SCRAM-SHA-1 (its stored key derives from an MD5 of the password, and a mechanism downgrade from the server's list is not followed: the mechanism is fixed by the client), `PLAIN` (LDAP proxy authentication sends the password in clear), X.509, GSSAPI, `MONGODB-AWS`, `MONGODB-OIDC`, speculative authentication.
   - The `hello` handshake names the client (`application.name: databastion-agent`), so the agent's own operations can be told apart in the server logs and profiler (P5-C).
4. **TLS**, following [ADR-0015](0015-postgresql-connector-decisions.md) decision 1 (`targets[].mongodb.tls`):
   - `verify_full` (default): TLS 1.2 or 1.3 from the first byte (MongoDB has no in-protocol upgrade), certificate verified against a pinned CA file (`mongodb.ca_file`, then the only trusted root) or the system store, host name (DNS name or IP SAN) checked. No "encrypt without verifying" mode, no client certificate.
   - `disable`: a Unix socket or a loopback IP literal only (never `localhost`); a Unix socket requires it.
   - `disable_insecure`: explicit opt-in on a network; a warning at every connection and the `security.tls_disabled` note (samples travel in clear; an attacker on the path can relay the SCRAM exchange, which has no channel binding in MongoDB, and then send its own commands: read-only is not guaranteed).
5. **Least-privilege account: a custom role with `find` and `listCollections` per monitored database.**

   ```js
   // In the admin database. One privilege per monitored database; nothing cluster-wide.
   db.getSiblingDB("admin").createRole({
     role: "databastionDiscovery",
     privileges: [
       { resource: { db: "app", collection: "" }, actions: ["find", "listCollections"] }
     ],
     roles: []
   });
   db.getSiblingDB("admin").createUser({
     user: "databastion",
     pwd: passwordPrompt(),
     mechanisms: ["SCRAM-SHA-256"],
     roles: [{ role: "databastionDiscovery", db: "admin" }],
     // The agent's address(es): the account cannot log in from elsewhere.
     authenticationRestrictions: [{ clientSource: ["10.0.0.15"] }]
   });
   ```

   - `collection: ""` covers every collection of the database **except** `system.*` ones (`system.profile`, `system.js`, `system.views`).
   - **Time-series collections (optional grant).** A time-series collection is a view over its bucket collection (`system.buckets.<name>`), and MongoDB authorizes reads of it on the bucket collection, which `collection: ""` does not cover. Found by the first CI run against MongoDB 8.0: the minimal role gets `Unauthorized` (13). To cover them, add `{ resource: { db: "app", system_buckets: "" }, actions: ["find"] }` to the role: it reads the time-series collections' own documents and nothing else, so `check()` does not count it as over-privilege. Without it, the scan counts those collections as `skipped_not_readable` and `check()` reports them with `coverage.timeseries_not_readable` (a count, computed from the resolved privileges).
   - Not needed, so not granted: `listDatabases` (the connector asks with `authorizedDatabases: true`, which lists the databases the account holds privileges on), `collStats` / `dbStats` (the collection size comes from `count`, which needs `find`), `killCursors` (a user can always kill its own cursors), `killop`, `changeStream`, `dbHash`, `listIndexes`.
   - Never granted for Discovery: `readAnyDatabase`, `read` (see Context), `clusterMonitor`, any privilege on `admin`, `local` or `config`, any write or administration action. The Audit grants (profiler, logs) are decided with P5-B / P5-C.
   - `check()` evaluates the account's resolved privileges from `connectionStatus` with `showPrivileges: true` (privileges of every role, inherited ones included, so no role is left unevaluated) and reports, as closed notes with counts (decision 9): write or administration actions, read actions beyond `find` / `listCollections`, cluster-wide actions, privileges on every database, and access to system collections or to the `admin`, `local` and `config` databases. A resource the connector cannot parse is counted as a privilege on every database (fail closed).
6. **Read-only and bounded (I4).**
   - `maxTimeMS` from the job's clamped statement timeout (never `0`) on every command that reads data or metadata (`listDatabases`, `listCollections`, `count`, `find`, `aggregate`, `connectionStatus`); `hello`, `saslStart`, `saslContinue` and `buildInfo` are bounded client-side. Every exchange also has a client-side deadline (`maxTimeMS` + 2 s); `check()` uses 3 s per command and 9 s in total.
   - Aggregation: the only pipeline is `[{$sample: {size: n}}]`, with `allowDiskUse: false`. No `$out`, `$merge`, `$lookup`, `$unionWith`, `$function`, `$where` or JavaScript, ever.
   - **No cursor is left open.** `find` uses `singleBatch: true` (the server closes the cursor with the reply); `aggregate` asks for a batch of `n + 1` so the pipeline is exhausted in the first reply; `listCollections` asks for its bound in one batch. A reply with a non-zero cursor id (a batch cut by the 16 MiB reply limit, a truncated listing) is followed at once by `killCursors` on that cursor, and the connector never sends `getMore`. No logical session id is sent, so no server session or transaction exists either. Each collection is read by one command whose reply is fully parsed before any finding is submitted: nothing is held on the server across `submit()`.
   - A dropped future (job deadline, cancellation, shutdown) closes the connection: the server interrupts an operation whose client disconnected at its next interrupt check, and `maxTimeMS` bounds it in any case.
7. **Sampling.**
   - Databases: `listDatabases` with `nameOnly` and `authorizedDatabases` (at most 1024; beyond, one `skipped_limit`), filtered by the job's `databases`; `admin`, `local` and `config` are never read.
   - Collections: `listCollections` with `nameOnly` and `authorizedCollections` (at most 4096 per database; beyond, one `skipped_limit`), filtered by the job's object filters. `nameOnly` returns names and types without the view definitions (which can hold literals). Type `collection` and `timeseries` are sampled; `view` is never read (a view runs its pipeline, possibly over other collections or with server-side JavaScript: `skipped_unsupported`, and the `coverage.views_not_sampled` note); any other type is skipped as unsupported (fail closed). `system.*` collections and the queryable-encryption state collections (`enxcol_.*`) are out of scope and never read.
   - Size: `count` without a filter (collection metadata, no scan), reported as `estimated_rows`; plain collections only (on a time-series collection `count` would unpack every bucket, so these are read with `find` and carry no estimate).
   - Method: when the estimate is above 20 × `n` (and above 100 documents), `aggregate` with `$sample` (random cursor, no collection scan); otherwise `find` with `limit: n` in natural order (the collection is small, so the first `n` documents are a large share of it). `n` is the job's `sample_rows` (at most `limits.max_sample_rows`).
   - Bounds: one reply per collection (at most 16 MiB + 64 KiB, so a batch cut by the server gives a smaller sample, never a second read); per document at most 20 levels of nesting (deeper values skipped), the first 16 elements of each array, 512 values and 4096 elements visited; per collection at most 4096 distinct raw paths (each normalized once), 1024 distinct normalized field paths and `n` values per path; values cut to 4096 bytes on a character boundary.
   - A failure on one collection (permission, `maxTimeMS`, a reply over the limit, a malformed document) skips that collection only; a connection left unusable is replaced for the next one, and a target that is gone fails the scan when reconnecting.
8. **Field paths.** The connector walks each document: an embedded document adds a key, an array adds an index level (`[]`, arrays of arrays included). The raw path is normalized with `names::normalize_field_path` ([ADR-0009](0009-name-normalization-and-item-sanitization.md)): digit-only keys, keys containing a dot and keys that look like values become `*`, and a value split across nested keys is masked. The values of every raw path with the same normalized path are pooled before classification (every `contacts.<address>.phone` is `contacts.*.phone`); the normalized path is also the column name given to the classifiers (name hints). Database names are one key (`normalize_field_path`); collection names go through `names::normalize_path`, which reads dots as separators (`fs.files`). Raw keys and paths stay in memory for one collection, are never logged and never sent. Locations carry `database`, `object` (collection) and `field`, no `schema`. `_id` is a field like any other.
9. **BSON values to the classifiers.** Only through `RawValue`, then `ScanJob::classify` and `classifiers::masking` (I2):
   - string and the deprecated symbol type: as they are (valid UTF-8 only);
   - `int32`, `int64`: decimal digits; `double`: integral values below 2^53 only, as digits (a phone or card number stored as a number); `Decimal128`: finite values as a decimal string;
   - date: `YYYY-MM-DD` in UTC (birth dates; years 1 to 9999);
   - binary subtypes 0 (generic), 2 (old binary) and 0x80-0xFF (user defined): read as text only when valid UTF-8 without control characters; subtypes 3 and 4 (UUID), 5 (MD5), 6 (client-side / queryable encryption), 7 (compressed column), 8 (sensitive) and 9 (vector) are never read;
   - ObjectId, boolean, null, regular expression, JavaScript code (with or without scope), timestamp, min / max key, DBPointer, undefined: skipped.
10. **Honest `check()`**: reachability (TLS, `hello`, authentication), version and edition from `buildInfo` (agent logs only), the privilege evaluation of decision 5, views not sampled, `disable_insecure`. **The audit level is `None`** in this build, with the note `audit.stream_not_available`: the connector has no Audit stream yet (P5-B, P5-C), and the Discovery account cannot even read the profiler level nor the audit settings. Reporting the level a server could give before the agent reads anything would let an absent audit pass for a working one (docs/08). The privilege and coverage report is recomputed at most every 10 minutes per target, like the MySQL connector's.
11. **Closed notes.** New codes in `shared/protocol/target-notes.json` (engines `mongodb`, counts only, no label): `audit.stream_not_available`, `coverage.timeseries_not_readable`, `privilege.write_actions`, `privilege.read_beyond_discovery`, `privilege.cluster_actions`, `privilege.any_database`, `privilege.system_collections`. `mongodb` is added to the engines of `check.stage_failed`, `check.timed_out`, `security.tls_disabled` and `coverage.views_not_sampled`. The registry is append-only; no new `TargetNoteLabel` value, so no capability token is needed ([ADR-0022](0022-protocol-capability-negotiation.md) decision 4).
12. **Errors** are reduced to a closed failure code, the server's numeric error code (contract `EngineCode`) and a closed stage; `errmsg`, `codeName` and any other server text are never kept, logged or sent. Coverage counters: `objects_sampled`; `skipped_not_readable` (error 13, `Unauthorized`); `skipped_unsupported` (views, unknown types); `skipped_limit` (truncated listings); `skipped_error` (any other non-fatal error on one collection, such as a collection dropped since it was listed or a `maxTimeMS` expiry).

## Consequences
- `agent.yaml` gains a `targets[].mongodb` block: `tls`, `ca_file`, `auth_source`.
- `docs/05-security.md` must replace its MongoDB account line (`read` + `clusterMonitor`) with the grant of decision 5 for Discovery; `docs/03-tech-stack.md` must say that the MongoDB connector has its own client instead of the official crate; `docs/08-engine-capabilities.md` should state that MongoDB targets report `None` until P5-B / P5-C. These are `docs-keeper` files.
- The dev environment (`dev/mongo/initdb/`) creates the account of decision 5 on the `app` database; its container healthcheck can no longer use that account for `getCmdLineOpts` and uses the administrator instead. The Audit work (P5-B, P5-C) will need its own grants.
- The console shows the new note codes from the generated phrase catalog (`console/src/generated/protocol/target-notes.gen.ts`, regenerated from the registry).
- Accounts created with `mechanisms: ["SCRAM-SHA-1"]` only, or authenticated through LDAP, Kerberos, X.509, AWS or OIDC, cannot be used by the agent.
- Servers older than MongoDB 5.0, `mongodb+srv` URIs and scans spanning a replica set without declaring a member are not supported.

### Residual risks
- **Own parser.** The connector parses BSON and `OP_MSG` from a possibly hostile server. Lengths are checked before reading, parsing is bounded and fails closed, and property tests exercise the reader; the robustness still rests on this code.
- **Reply peak.** One reply (up to 16 MiB + 64 KiB) is received whole before its documents are walked: that is the memory peak per collection, like one row for the SQL connectors.
- **Server-side interruption on disconnect** is the server's behavior, not something the connector can force; `maxTimeMS` remains the bound. No `killOp` is sent (the operation id is not known without `currentOp`, a privilege the account does not have).
- **Sampling bias.** Natural order on small collections reads the first documents in storage order; `$sample` is random but a batch cut at 16 MiB samples fewer documents. Documents with more than 512 values, arrays beyond their first 16 elements and nesting beyond 20 levels are not fully read.
- **Coverage blind spots.** With `authorizedCollections`, collections the account holds no privilege on are not listed at all, so they cannot be reported as not covered (the MySQL `information_schema` open question of ADR-0018). Data reachable only through a view is not covered. On a sharded cluster `count` may include orphaned documents (the estimate only).
- **Name normalization** has the gaps listed in [05-security.md](../05-security.md#masking-and-fingerprints); dynamic keys that do not look like values (a surname used as a key) pass.
- **Binary as text.** A generic binary that is valid UTF-8 is classified as text; one that is not is skipped, even if it holds sensitive data in another encoding.
- **Time-series collections** are read through their unpacking view: the cost is bounded by `limit: n` and `maxTimeMS`, but it is higher than for a plain collection.
- **No SCRAM channel binding** (MongoDB offers no `-PLUS` mechanism): with `disable_insecure`, an attacker on the path can relay the exchange and act as the agent's account.

## Rejected alternatives
- **The official `mongodb` crate**: see Context. Allowing `CDLA-Permissive-2.0`, raising the MSRV and accepting topology discovery would have been needed, and the crate still could not use the system trust store, pin the authentication mechanism against the server's list without extra code, bound the reply size, or keep server text out of errors.
- **The `bson` crate for BSON only**: brings `serde`, `indexmap`, `time`, `uuid`, `rand` and more for a format the connector must walk with its own bounds anyway.
- **`read` + `clusterMonitor`** (the previous recommendation): change streams, other sessions' operations and profiled queries, cluster settings; none needed for Discovery.
- **`readAnyDatabase`**: every database, present and future, including ones never meant to be monitored.
- **Following the replica-set topology from `hello`**: connects to addresses the server chooses (I5).
- **`$sample` on every collection**: on a collection smaller than 20 × `n` it scans and sorts the whole collection; natural order is cheaper and reads a large share of it anyway.
- **Reporting the audit level the server could provide** (as ADR-0015 decision 4 and ADR-0018 decision 5 did before their Audit streams): without a stream and without the privileges to read the profiler settings, the level would be a guess.
- **Hashing or dropping dynamic keys**: `*` keeps the rest of the path readable, and hashing would make findings unreadable (ADR-0009).
