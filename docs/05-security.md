# Security & best practices – DataBastion

A security tool that reads sensitive data is itself a target. These rules are non-negotiable.

## Security invariants
1. **Outbound-only**: no inbound port to the agents or to the databases.
2. **No raw sensitive value leaves the agent.** Only: location, detected type, confidence, volume, masked sample, HMAC fingerprint ([ADR-0003](adr/0003-data-minimization-at-source.md)).
3. **Database credentials never leave the agent host.** The console neither stores nor receives them.
4. **Least privilege**: the agent connects with a dedicated **read-only** account.
5. **No secrets in images or in the repository**: environment variables, Docker secrets, mounted files.
6. **Console audit log**: every user action (login, policy change, incident acknowledgment, agent enrollment or revocation) is logged.

## Threat model (summary)
| Compromise | What the attacker gets | What they do not get |
|---------------|----------------------------|------------------------|
| Console | The map of sensitive locations, masked samples, notification channel secrets (webhook URLs and signing secrets, SMTP passwords, with the server key) | The data itself, database credentials, network access to the databases |
| An agent | Its own secret, the read-only account of its targets, its local HMAC key (so it can confirm guesses of low-entropy fingerprinted values, see below) | The other agents, the console secrets |
| Network between agent and console | Nothing (TLS 1.3) | |

The map remains sensitive information: the console must be protected (HTTPS, authentication, public exposure not recommended).

## Masking and fingerprints
*Implemented in the `classifiers` crate (#34); details in `agent/crates/classifiers/README.md`.*

- **Masked sample**: `jane.doe@example.com` → `j***@e***.com`; IBAN → `FR** **** **** **** **** ***0 189`; card → `**** **** **** 1111`; birth date → `****-**-**`. Every sample is checked against the contract `MaskedSample` rules (at least one `*`, no run of more than 4 letters or digits, at least 50 % `*`) and keeps **at most 4 digits in total**; a sample that fails the checks falls back to `***`.
- **Sample selection**: masked samples are not the first rows and are not row-aligned. Each column keeps the 5 distinct samples with the smallest `HMAC(agent key, "sample-order" 0x00 column_name 0x00 value)`: a keyed order, deterministic for an agent but independent from one column to the next, so the console cannot line up the samples of several columns into partial records.
- **Fingerprint**: `hmac-sha256:` + hex of `HMAC-SHA256(agent_local_key, "databastion/fp/v1" 0x00 domain 0x00 normalized_value)`, where `domain` is the classifier id, or `db_user` for an account-name fingerprint. The domain separation keeps the same string under two classifiers, or as an account name, from correlating. Fingerprints allow deduplication and equality checks without revealing the value. The key (`<state_dir>/hmac.key`, 32 bytes) is generated at enrollment and **never leaves the agent**; the value normalization is agent-local and not part of the contract, so the console treats fingerprints as opaque. Phone numbers written without `+` are only normalized to international form when the target declares `phone_region` in `agent.yaml` (`fr` today); otherwise their digits are fingerprinted as they are, so the national and international forms of one number do not match.
- **Low-entropy values**: an HMAC does not protect a value with few possible inputs against someone who **holds the key**. Phone numbers, birth dates and NIRs can be enumerated, so a holder of the agent key can recover them from their fingerprints by brute force. Without the key (the console, the network) this is not possible. The agent state directory and **all its backups** are therefore sensitive: protect them like the target credentials, and exclude `hmac.key` from backups that leave the agent host where possible.
- **Names** (tables, fields, LDAP containers) can embed values: the agent normalizes them before the uplink and sanitizes each item rather than dropping the batch ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)).
- Masking is implemented in a single crate (`classifiers`/`masking`) and covered by unit and property tests (contract conformance, no raw value or 5-digit run survives, keyed and domain-separated fingerprints, no raw value in `Debug`).

**Residual risks of name normalization.** Normalization (`agent/crates/classifiers/src/names.rs`, #39) replaces segments with more than 6 digits, UUIDs and long hex keys, e-mail addresses, percent-encoded bytes, segments matched by a classifier (including values split across dots) and words from a list of common first names. Since #42, `%uXXXX` escapes are treated as values like `%XX` (`%u0040` read as `@`); CJK numerals count as digits in the digit bounds and in the final `NormalizedName` check: the ideographic digits `零〇一二三四五六七八九`, the financial forms `壹贰叁肆伍陆柒捌玖` and `貳參陸`, `两` / `兩` and `拾` (short CJK words such as `一月` are kept; Hangul numerals are deliberately not counted, as they are ordinary syllables); and a document-path key that cannot be folded (NFKC) within the input bound makes the whole path `*`. Normalization cannot recognize every value written as a name. Known gaps, confirmed against the current code:
- **E-mail local part in the previous key.** With the real keys of a document path, a key that contains a dot and an `@` (`x@example.com`) becomes `*` on its own, and the keys before it are kept: `contacts` / `pdupont` / `x@example.com` / `phone` gives `contacts.pdupont.*.phone`. The previous key is only masked when it is itself recognized (e.g. a listed first name).
- **Spelled-out e-mails.** An address written without `@` (`pdupont_at_example_com`) matches no detector and passes unchanged.
- **Encoded names.** A base64-encoded value without padding (`cGR1cG9udEBleGFtcGxlLmNvbQ`) passes unchanged; with `=` padding the segment becomes `*` only because `=` is a forbidden character. Other encodings are not decoded either.
- **Person names.** A surname alone (`archive_dupont`) or a first name missing from the list passes; no detector recognizes arbitrary person names in identifiers, and such a name also passes the contract's `Identifier` pattern.

Name-based leaks are the subject of the P2-E invariant test.

**Invariant I2 test (P2-E).** An automated end-to-end test that runs a Discovery scan of a seeded PostgreSQL target and checks that no seeded sensitive value, including values embedded in object and field names, is stored in clear by the console. It runs in the E2E workflow (#50, `e2e/i2_check.py`), which is not yet a required check; extending it to MySQL / MariaDB and making it required are phase 2 sign-off follow-ups (ROADMAP P2-G). It scans the whole console database dump, every console and agent log and the rendered findings page (the only place masked samples are decrypted); no rendered masked sample may keep more than 4 digits. Matching is case-, accent- and normalization-form-insensitive, also after JSON / URL / HTML / SQL unescaping, with digit-only and national / international forms for numbers; values under 4 characters are excluded and counted. The agent must report an empty spool before the check, so no batch is still in flight. Known blind spots: base64 / hex encodings, camelCase-embedded names, values split across columns. It complements the masking property tests of the `classifiers` crate, per-item sanitization in the agent and strict schema validation in the console.

## Classifiers
*Implemented in the `classifiers` crate (#34, #48); semantics of classifier set `2026.09.1` in [ADR-0016](adr/0016-classifier-semantics-2026-09-1.md); detection and decision rules in `agent/crates/classifiers/README.md`.*

- **Values decide, names only lower thresholds.** A column is reported on the evidence found in its sampled values; a column-name hint lowers the thresholds. A name of something other than a person (`pet_name`, `hostname`, `company.name`) turns `pii.person_name` off, and an order / tracking / IMEI / barcode name turns `pii.card_number` off.
- **Unicode**: values are put in NFC before detection; tokens, masked samples and fingerprints are taken from the NFC value (fingerprint label `databastion/fp/v1` unchanged). NFKC applies to names only.
- **Detection temporaries** holding a value or part of it (the NFC copy of a value, digit and alphanumeric extractions, lowercased e-mail parts) are zeroized on drop, like `RawValue`, `HmacKey` and the normalized values used for fingerprints.
- **Held-out gate**: the phase 2 exit criterion (recall ≥ 90 %, precision ≥ 85 % per classifier, Wilson 95 % lower bound on `dev/holdout/`) is a blocking CI step since #48. Classifiers are never tuned against the holdout (independence rule, `dev/holdout/README.md`).

**Residual recall and precision limits**, known and accepted for this classifier set:
- **Placeholders**: values on a fixed list (`N/A`, `na`, `null`, `-`, `unknown`, `x`, `xx`, `0`, `0000-00-00`…) are not informative; a real value equal to one of them (a person called `Na`) is ignored.
- **Single address repeated**: a column holding one e-mail address repeated is not reported as personal e-mail, even if that address is a person's.
- **Checksum columns**: IBAN, card and NIR columns are reported only if at least half of their checksum-shaped candidates are valid. A column mixing many invalid numbers with a few real ones is missed.
- **Children's birth dates** without a column-name hint are missed (the age distribution needs a median birth year of 2002 or earlier).
- **Reference year drift**: the age heuristic uses the fixed reference year 2026 of the set. As time passes, real populations include more recent birth dates, and recall without a hint decreases until a later set moves the reference year.
- **Person names without a hint** rely on a lexicon of given names, surnames and surname endings: names from cultures poorly covered by it, or rare names, are missed without a hint.
- **Person names under a non-person hint** (`pet_name`, `product_name`, `team_name`…) are never reported, even when the column holds real person names.
- The dev ground truth and the synthetic evaluation are in-sample (the detectors were written with them in view); only the held-out corpus measures generalization.

## Encryption
- **In transit**: TLS 1.3 mandatory. No additional application-level AES-GCM encryption on top: without a key held outside the console, it adds nothing to TLS.
- **At rest (console)**: sensitive columns are encrypted with the console server key `DATABASTION_ENCRYPTION_KEY(_FILE)`, provided via Docker secret. The key derives independent HKDF-SHA256 subkeys: agent known-good fingerprints (`agent-known-good.v1`), login device cookies (`login-device.v1`) masked samples (`masked-samples.v1`) and notification channel secrets (`notification-channels.v1`, see [Alerting](#alerting)).
- **Masked samples** (#36) are stored only encrypted: AES-256-GCM under the `masked-samples.v1` subkey, a random 96-bit nonce per encryption, and AAD = label ‖ format version ‖ finding id, so a ciphertext copied onto another finding row, or relabelled with another format version, does not decrypt. Decryption happens server side for the findings view; a wrong key or a tampered row shows no sample rather than an error. Without a usable key, samples are neither stored nor shown (fail closed). **Changing the key** makes the stored samples unreadable (they are not re-encrypted); they come back with the next scan of each target, which replaces them. It also invalidates the known-good fingerprints and device cookies.
- **`DATABASTION_ENCRYPTION_KEY` is required in production** (#37). Without a usable key (unset, shorter than 32 characters or unreadable), the web and worker processes **refuse to start** in production (fatal log, exit code 1). `DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY=1` overrides this (not recommended): the processes then start, known-good fingerprints, device cookies and masked samples are disabled (fail closed), and an **error** naming the disabled protections is logged at startup.
- Agent secrets are stored **hashed** (argon2id) on the console side.

## Agent secret management
Normative details: [`shared/protocol/openapi.yaml`](../shared/protocol/openapi.yaml) (`/enroll`, `/rotate`, `agentSecret` security scheme); overview in [09-agent-protocol.md](09-agent-protocol.md#secret-rotation).

- **Enrollment token**: single use, valid 24 h, generated in the console. The console stores only its SHA-256 hash and consumes it **atomically** (one conditional update: unused and not expired → used), so two concurrent enrollments with the same token cannot both succeed. `/enroll` is rate limited per source IP, and hashes the new secret in its own argon2id pool of 2 concurrent operations: when it is full, the console answers `503` + `Retry-After` and the token is not consumed.
- At enrollment, the agent receives `agent_id` + a 256-bit secret; it stores them in a `0600` file, then generates its local HMAC key (never transmitted).
- **Secret storage**: argon2id hash on the console side. The bodies of `/enroll` and `/rotate` are excluded from every request, APM and error log, on both sides.
- **Authentication**: failed authentications are rate limited per agent id **and** per source IP (when known, see [Authentication rate limits](#authentication-rate-limits)) **before** the argon2id verification runs, so the hash cost cannot be used for denial of service. A cache of verified secrets, if any, keeps entries less than 30 s and is purged on revocation and on rotation.
- **Rotation** ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)): the **agent generates** the new secret, persists it as pending before any network call, and registers it with `POST /rotate`, authenticated with the current secret. Retries resend the same secret and are idempotent. The console rejects a new secret equal to the current one or obviously low-entropy (`invalid_secret`). A different new secret while one is pending, or use of the old secret after a **60 s tolerance window** following promotion, is a `rotation_conflict`: the console locks the agent, revokes all its secrets and raises a security incident; the agent stops and must be re-enrolled. [ADR-0010](adr/0010-rotation-conflict-window.md) makes the window precise: only a `/rotate` authenticated with the previous secret and carrying a different new secret can be a conflict inside the window (the same new secret is an idempotent `duplicate`), and a `/rotate` authenticated with the current secret always starts a new rotation while no secret is pending. [ADR-0011](adr/0011-late-rotation-retry.md) adds the late retry: a `/rotate` authenticated with the previous secret whose new secret matches the current (promoted) one is an idempotent `duplicate` at any time, bounded to 10 per agent per 5 min; any other `/rotate` outcome with the previous secret after the window locks the agent. When the outcome of a `/rotate` is unknown, the agent first probes its pending secret with a heartbeat before re-sending `/rotate` with the previous one (#20).
- **Security events** (#21): a `rotation_conflict` lock writes a `critical` row to the `security_events` table (console-computed kind, severity and scalar details, never a secret or hash) in addition to the console audit log. Since P3-C (#49), security events are notified to the channels flagged `system_alerts` (see [Alerting](#alerting)); they are not incidents, which only policies raise ([ADR-0014](adr/0014-policy-and-incident-model.md), [ADR-0017](adr/0017-alerting.md)). The table is insert-only for the runtime role, except the acknowledgement columns (`acknowledged_at`, `acknowledged_by`): migration `0010` revokes `UPDATE`, `DELETE` and `TRUNCATE`, so a compromised console process cannot erase or rewrite an integrity alert.
- **Revocation** invalidates the current and the pending secret and closes the agent's held long-polls. It is effective in **less than 60 s**.
- **Suspected compromise** of an agent secret is not handled by rotation (whoever holds the secret could rotate it too): the administrator revokes the agent and re-enrolls it.
- Vault integration: later

## Console internal database
*Introduced by P1-A (#17); details in `console/README.md` ("Database roles").*

### Database roles
The console uses three PostgreSQL roles, so that a compromised console process can neither remove the append-only trigger on `audit_log` nor plant code that migrations would run:
- a bootstrap superuser, used only by the init script that creates the two roles below;
- an **owner** role (not superuser, no `CREATEROLE`) used only for migrations: it owns the database, the `public` and `pgboss` schemas and every console table and trigger; its `search_path` is pinned to `public`;
- a **runtime** role used by the web and worker processes: DML only on the console tables, only `SELECT` and `INSERT` on `audit_log`, only `SELECT`, `INSERT` and `UPDATE (acknowledged_at, acknowledged_by)` on `security_events` (migration `0010`), `USAGE` and `CREATE` on schema `pgboss` for the pg-boss tables, and no `CREATE` on the database or on `public`.

The owner role never runs SQL against objects inside `pgboss`: they are created by the runtime role, so a trigger or function planted there would run with the owner's rights. Migration `0009` refuses to migrate when schema `pgboss` exists and is owned by a role other than the migration role; the whole run is rolled back, and a superuser must fix the ownership (after checking the schema for planted objects) before `migrate` runs again. Since #37, `migrate` also repeats the check as a pre-flight on every run, before any migration SQL. In a single-role setup (development), the audit log is append-only against the application code only.

### Metrics endpoint (#21)
`GET /metrics` requires `Authorization: Bearer <DATABASTION_METRICS_TOKEN>` (at least 32 characters, constant-time comparison, `401` otherwise). When the token is unset or too short, the endpoint answers `404`. It is meant for the internal network only. Since #27, setting `DATABASTION_METRICS_PORT` serves it on a dedicated listener of the web process, bound to `DATABASTION_METRICS_HOST` (an IP address, `127.0.0.1` by default), and the main port then answers `404` on `/metrics`. Without a dedicated port, `/metrics` stays on the main port: block the path on the public reverse proxy (a production start warns about it).

### Web UI headers (#21)
UI pages get a `Content-Security-Policy` with a per-request nonce: `script-src 'self' 'nonce-…' 'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`. It is not applied to `/api/*` and `/metrics`, which serve no HTML.

### Authentication rate limits
Every login or agent authentication that needs an argon2id verification is counted **before** the verification runs and refunded on success, so concurrent requests cannot exceed the limits. Logins, agent authentications and enrollments use separate, bounded argon2id pools (4, 8 and 2 concurrent operations per process; `503` + `Retry-After` when full), plus a pool of 4 reserved for agents presenting a known-good secret, so a login flood or a flood of wrong agent secrets cannot block a legitimate agent. Per-IP limits apply only when the client IP is known, that is behind a trusted reverse proxy explicitly configured (`DATABASTION_TRUST_PROXY` / `DATABASTION_TRUSTED_PROXY_HOPS`); otherwise only the per-user / per-agent limits and the pool caps apply. Limiters are in memory, per process (one web process in the MVP). Details: `console/README.md` ("Brute-force protection").

**Agent authentication** (all windows 5 min; #27, #32):
- **Per IP, argon2-backed only**: 50 failures per source IP, counting only failures that ran an argon2id verification.
- **Per IP, cheap failures**: a separate counter of 500 per source IP covers failures that need no argon2id work (missing or malformed headers or secret, unknown or inactive agent, `/rotate` body missing its read deadline). It only gates reaching the argon2id path.
- **Per agent**: 10 argon2-backed failures per (agent id, source IP), or per agent id alone when the IP is unknown.
- **Exemptions**: a secret verified less than 25 s ago (verified cache) or known good (current or pending) is held by none of these limits, so junk requests from a shared NAT or proxy IP, which need no secret, cannot block the agents behind it. The exemptions never authenticate: the secret is still checked against the hash-bound cache or a full argon2id verification.
- **Known-good fingerprints**: the console remembers which secrets it has verified for an agent as an HMAC-SHA256 fingerprint keyed with an HKDF-SHA256 subkey (`agent-known-good.v1`) of `DATABASTION_ENCRYPTION_KEY`, bound to the stored hash, valid 24 h and persisted across restarts. A known-good secret uses the reserved agent pool. Without a usable key, nothing is stored and nothing matches (fail closed); only the 25 s cache exemption remains.
- **Pending secret (`S1`)**: a pending secret registered by `/rotate` is recognized as known good in the same way, so the agent's `S1` probe is exempt too.
- **Previous secret (`S0`)**: attempts authenticated with the previous secret go through the same argon2id path and count against the per-agent and per-IP failure limits like a wrong secret. They are refunded only when `/rotate` answers an idempotent `duplicate`.
- **`/rotate` body**: a cheap precheck (protocol headers, secret format, failure limits) runs before the body is read. The body is capped at 64 KiB and must arrive within 10 s; a body that misses the deadline is answered `400` before any argon2id work, never causes a lock, and counts against the cheap per-IP counter only.
- **Known limitation (N4)**: the known-good exemption is checked first against an in-memory copy of the agent row, then against the row itself; that database read is skipped while the source IP is over the cheap limit. Right after a console restart (empty in-memory copy), a known-good agent behind an IP over the cheap limit can therefore wait up to 5 min, until the window expires, like the other clients of that IP.

**Logins** (all windows 15 min; #32):
- 20 failures per source IP (IPv6 addresses bucketed by /56 for logins, /64 elsewhere).
- 5 failures per (username, IP bucket): a failure flood from one IP answers `429` from that IP only and never locks the account out for other IPs.
- 100 failures per username across all IPs. Reaching this global cap never refuses the login: the username degrades to a slow-down (2 s before the verification) with one attempt in flight at a time; other concurrent attempts for that username get `503` + `Retry-After`. Wrong passwords still answer `401`.
- With an unknown client IP (no trusted proxy), the per-username counter is shared by every client: reaching it never answers `429`, the login degrades to the same slow-down path, and the slow-down grows with the username's failed degraded attempts: 2 s, doubling per failure, capped at 30 s (#37). With a known IP it stays at 2 s.
- Failures on unknown usernames share a process-wide budget of 30 per 5 min.
- **Device cookies** (OWASP "device cookies"): every successful login sets a 90-day `HttpOnly`, `SameSite=Strict` cookie (`__Host-` prefixed and `Secure` in production, unless `DATABASTION_INSECURE_COOKIES=1`) carrying the user id, the issue time and a random nonce, signed with HMAC-SHA256 under the HKDF subkey `login-device.v1` of `DATABASTION_ENCRYPTION_KEY`; nothing is stored server side. A valid cookie for the username being tried bypasses **only** the global per-username cap and the degraded slot, so a distributed guessing attack cannot keep the real user out. It never replaces the password and stays subject to the per-(username, IP) limit, the login argon2id pool and a per-cookie limit of 5 failures per 15 min (beyond, it gives no bypass). Failures made with a device cookie still count toward the global per-username cap (#37). Without the server key, no device cookie is issued or accepted.

## Findings ingestion
*Introduced by P2-D (#36, #37); normative checks in [`shared/protocol/openapi.yaml`](../shared/protocol/openapi.yaml) ("Console-side checks"), overview in [09-agent-protocol.md](09-agent-protocol.md#console-side-checks-on-findings).*

- **Rate bounds per agent** (in memory, per process): 60 **stored** findings batches per minute (duplicates and rejected batches give their slot back), and 300 `POST /findings` requests per minute whatever their outcome, which bounds the validation and database work of rejected batches. Beyond either: `429` + `Retry-After`.
- **Per-job cap**: at most 50 000 findings per scan job over all its batches, enforced atomically (one agent's batches are ingested one at a time).
- **Late window**: a scan job accepts findings while it runs, up to `delivered_at + max_duration_s + 1 h`, and for 24 h after it finished (counted from that deadline at the latest); later batches get `404`, so an agent cannot keep writing into old jobs.
- **Integrity events**: a rejected (`400`) findings batch, a `batch_conflict` and a finding for a target the agent does not own cannot come from a conforming agent. Each writes an audit-log entry and a `security_events` row (with a bounded write budget, so a hostile agent cannot flood the table); the body is never logged.
- **Classifier registry and console downgrades** (operator note, console registry checks, #41): the console serves a `discovery.scan` job only if its `classifiers_version` is in the console's classifier registry (`classifiers.json`) and its `params.classifiers` ids belong to that version. If the console is downgraded to a build whose registry no longer contains a version, pending scan jobs carrying that version fail closed: they are marked `failed` with `internal` when claimed and never sent to the agent. Launch the scans again once the agents report a version the console knows.
- **False positives**: only administrators can mark or unmark a finding as a false positive (CSRF-protected, audited). The mark records `matched` and `classifiers_version`; a later scan that matches more values or uses another classifier set clears it automatically (audited as a system action), so a mark cannot silently hide a growing exposure.

## Alerting
*Implemented in P3-C (#49); decisions in [ADR-0017](adr/0017-alerting.md); details in `console/README.md` ("Alerting").*

- **Payloads carry no sampled value**, masked or not (I2): identifiers, counts, normalized names and a console link only. The masked samples stay encrypted on the finding.
- **Webhook signature**: `X-DataBastion-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(signing secret, "<t>.<raw body>")>`; receivers compare in constant time, reject a `t` older than 5 minutes and deduplicate on `X-DataBastion-Delivery` (delivery is at least once).
- **Channel secrets**: the webhook signing secret is generated by the console (256 bits) and shown once; SMTP passwords are entered by an administrator. Both, and the full webhook URL, are encrypted with AES-256-GCM under the HKDF subkey `notification-channels.v1`, with the channel id and type in the AAD. They are never returned by the API, logged or written to the audit log. Changing an e-mail channel's host, port, TLS mode or user requires its password again.
- **SMTP**: implicit TLS or mandatory STARTTLS (no downgrade; bytes received in clear after the STARTTLS `220` abort the session), certificates always verified, AUTH only over TLS. Plain-text SMTP only towards a loopback relay, or with the development flag.
- **Outbound address policy (SSRF)**: only the worker connects out. Every resolved address is checked, the socket connects only to the checked addresses (in resolver order, falling back on a connection error), and IPv4 addresses embedded in IPv6 transition addresses are checked as IPv4. Link-local and metadata addresses, unspecified, multicast, broadcast and reserved ranges are always refused. Loopback, private, CGNAT, ULA, documentation and benchmarking ranges and the transition prefixes are refused for webhooks and allowed for SMTP relays. Webhooks require `https://`, redirects are never followed, and no HTTP proxy is used.
- **Development flag**: `DATABASTION_ALERTING_INSECURE_DEV=1` allows `http://` webhooks, internal webhook destinations and plain-text SMTP to a non-loopback relay (link-local and metadata stay refused). In production the web and worker processes refuse to start with it unless `DATABASTION_ALERTING_INSECURE_DEV_I_UNDERSTAND=1` is also set.
- **Silent agent**: an agent that was online and has sent no heartbeat for `DATABASTION_SILENT_AGENT_INTERVALS` × 30 s (default 5 minutes) raises one alert per silence episode, recorded in `security_events` (insert-only for the runtime role) and notified to the channels flagged `system_alerts`. Agent-integrity events are notified to the same channels, at most once per agent, kind and hour per channel.
- **Volume bounds**: at most `DATABASTION_NOTIFY_MAX_PER_HOUR` (default 30) incident notifications per channel and hour, then one digest; channel tests limited to 10 per administrator and 3 per channel per 10 minutes.

**Residual risks** ([ADR-0017](adr/0017-alerting.md#residual-risks)): only the well-known NAT64 prefix has its embedded IPv4 address checked (the local-use prefix `64:ff9b:1::/48` is internal as a whole, so allowed for SMTP; operator-chosen prefixes are not recognized); silent-agent alerts are not counted in the hourly budget (one per agent and episode); the test-send limits are in memory, per process; e-mails are plain text only.

## Agent local state and results path
*Introduced by P1-B (#16, #20); details in `agent/README.md`.*

- **State directory**: must be owned by the agent user and not group / world writable (`0700` expected, another mode warns). State files (`identity.json`, `hmac.key`, spool batches) are `0600`, written atomically, opened with `O_NOFOLLOW` and checked on the handle (regular file, owner, no group / other access).
- **Spool**: bounded by `spool.max_bytes` (default 256 MiB) and `spool.max_batches` (default 10000), oldest dropped first. A file that cannot be parsed or fails the state-file checks is moved to `spool/quarantine/` (32 kept), counted and never logged; it does not crash the agent. A response that is not a contract answer (e.g. an HTML page from a middlebox) keeps the batch, so an intermediary cannot empty the spool.
- **Name normalization** ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)): array indices of up to 6 digits become `[]`; any segment with more than 6 digits, UUIDs and e-mail addresses become `*`; an LDAP entry DN is reduced to its parent container. Since #39, segments matching a classifier (including values split across dots) and common first names also become `*`; see the residual risks under [Masking and fingerprints](#masking-and-fingerprints).
- **Per-item sanitization**: every finding or event is checked against the contract before spooling; an item still invalid is dropped and counted, not the whole batch. An account name that does not conform is replaced by its HMAC fingerprint (`db_user` domain, #39); an event is dropped and counted only if no conforming principal can be built.
- **Local engine detection** ([ADR-0006](adr/0006-target-discovery.md)): read-only and local, no network I/O. The agent checks a fixed list of Unix socket paths (never connects), `LISTEN` entries of `/proc/net/tcp{,6}` for the default engine ports (addresses not reported) and process names in `/proc/<pid>/comm` (never the command line); at most 16 entries. In a container without host networking, it sees only its own network namespace and processes, so detection finds little or nothing on the host.

## Connector obligations
Requirements for every connector (acceptance criteria of P2-B and P2-C, in addition to the PostgreSQL obligations of [ADR-0012](adr/0012-postgresql-agent-grants.md)):
- **No database resource held across `FindingSink::submit().await`.** `submit()` can block for a long time: the findings channel is bounded, and while `/findings` is parked after a `501` the scan worker holds its chunk and stops reading, possibly until the scan deadline ([09-agent-protocol.md](09-agent-protocol.md#agent-side-handling-of-job-parameters)). A connector collects the findings of one table or sample, closes the transaction and any server-side cursor, then submits; it never keeps a transaction or cursor open while awaiting `submit()`.
- **Idle timeouts on the server side** as a safety net for the same reason: `idle_in_transaction_session_timeout` on PostgreSQL (also set on the role, see below), and the equivalent idle-session and cursor timeouts on MySQL / MariaDB and MongoDB, so a paused connector cannot keep locks, snapshots or cursors open on the target.

## PostgreSQL connector
*Implemented in P2-B (#47), `agent/crates/connector-postgres`; decisions in [ADR-0015](adr/0015-postgresql-connector-decisions.md), obligations in [ADR-0012](adr/0012-postgresql-agent-grants.md); details in `agent/README.md`.*

- **TLS** (`targets[].postgres.tls`, rustls only): `verify_full` by default (certificate verified against a pinned CA file or the system store, host name checked). `disable` is accepted only for a Unix socket or a loopback IP literal. `disable_insecure` is an explicit opt-in for a network connection without TLS: the connector warns at every connection that samples and statements travel in clear and that read-only is not guaranteed.
- **Authentication without TLS**: the connector reads the server's authentication requests before the driver answers, and refuses cleartext and MD5 password requests and SCRAM with fewer than 4096 iterations. Only SCRAM, or password-less peer / trust authentication on a local socket, is accepted. The target password is read from its `agent.yaml` reference into zeroized memory and never logged (I3).
- **Read-only and bounded** (I4): every unit of work in `BEGIN TRANSACTION READ ONLY` with `SET LOCAL` `statement_timeout` (from the clamped job parameter, never `0`, at least 100 ms), `lock_timeout` (2 s) and `idle_in_transaction_session_timeout` (10 s); `search_path = ''`; no expression on sampled columns (values decoded in Rust). A statement whose future is dropped (job cancelled, deadline, shutdown) gets a server-side cancel request. Transactions are committed before `FindingSink::submit().await`.
- **Sampling bounds**: at most `sample_rows` rows per object (`TABLESAMPLE SYSTEM` on large relations, `LIMIT` otherwise), at most 32 MiB of values per relation (checked per row; the statement is then cancelled, not drained), values truncated to 4096 bytes, at most 64 leaves per partitioned root (reported under the root). Every relation is read `FROM ONLY`, a partitioned root is never read directly (its leaves are), and foreign tables and foreign leaves are never read (I5).
- **RLS policy allow-list**: a row-level security table is sampled only if its `SELECT` policy expressions, walked locally, use allow-listed node types, no relation other than the table itself, and only immutable `pg_catalog` functions outside a denylist (functions that run SQL text or resolve names at run time, and those with side effects) plus `current_setting`, `now`, `current_database` and `current_schema`. Otherwise the table is skipped and reported as not covered. The expression text is never logged or sent.
- **Honest `check()`**: audit level Limited with `pg_stat_statements` and `pg_read_all_stats`, None otherwise; Full is not reported before P4-A ([08-engine-capabilities.md](08-engine-capabilities.md)). Over-privilege (warned, not refused) and coverage (schemas without `USAGE`, relations without `SELECT`, skipped RLS relations) are logged by the agent. They do not reach the console yet: `TargetStatus` has no field for them (ROADMAP follow-up).
- **Server messages** are reduced to a SQLSTATE and a stage; notices are discarded.

**Residual risks** ([ADR-0015](adr/0015-postgresql-connector-decisions.md#residual-risks)):
- one row is received whole by the driver before the byte budget is checked, so a single row (a field can reach about 1 GiB) is the memory peak;
- the driver's copy of the password and its row buffers are not zeroized;
- no SCRAM channel binding: without TLS, an attacker on the path can relay the SCRAM exchange and act as the agent's role (hence the `disable_insecure` warning); with `verify_full`, server authentication rests on the certificate;
- no TCP keepalive on target connections: a silently dropped connection is only detected by the timeouts;
- RLS policy expressions (which may hold literals) are read into agent memory for the check.

## Recommended database accounts (read-only)
**PostgreSQL** ([ADR-0012](adr/0012-postgresql-agent-grants.md), minimal variant, recommended default). Discovery through explicit per-schema grants; Audit through `pg_read_all_stats` only.
```sql
-- Once per cluster. Set the password with psql's \password: it is hashed client-side and only
-- the SCRAM verifier reaches the server. Never use PASSWORD '...' with a cleartext value.
-- Requires password_encryption = 'scram-sha-256' (the default since PostgreSQL 14).
CREATE ROLE databastion_agent LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 4;
\password databastion_agent
-- Safety net for any session on this account; the connector sets its own values.
ALTER ROLE databastion_agent SET default_transaction_read_only = on;
ALTER ROLE databastion_agent SET statement_timeout = '30s';
ALTER ROLE databastion_agent SET lock_timeout = '2s';
ALTER ROLE databastion_agent SET idle_in_transaction_session_timeout = '60s';

-- Per monitored database
GRANT CONNECT ON DATABASE app TO databastion_agent;

-- Discovery: per application schema, and per role that creates tables in it
GRANT USAGE ON SCHEMA crm TO databastion_agent;
GRANT SELECT ON ALL TABLES IN SCHEMA crm TO databastion_agent;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA crm
  GRANT SELECT ON TABLES TO databastion_agent;

-- Audit (Full and Limited): other users' statements. Omit for a Discovery-only target.
GRANT pg_read_all_stats TO databastion_agent;
```
- Every new application schema, and every role that creates tables in it, needs the Discovery grants above. The connector's `check()` lists the schemas it cannot read as not covered (ADR-0012, obligation 6), in the agent's logs for now (see [PostgreSQL connector](#postgresql-connector)).
- Set the password of **every** role with psql's `\password`, not `PASSWORD '...'`: with `pg_read_all_stats`, statement text written by other users (including `ALTER ROLE ... PASSWORD` literals) is readable by the agent account, and the connector must drop it (ADR-0012, obligation 5).
- For clusters with many or dynamically created schemas, ADR-0012 also defines an opt-in **extended variant** (`pg_read_all_data`, `pg_read_all_settings`), which exposes credential-bearing catalogs to the account; read the ADR before choosing it. Never grant `pg_monitor`, `SUPERUSER`, `BYPASSRLS` or any write privilege (full list in the ADR).
- The dev environment (`dev/`, per-schema grants on `crm`, `billing`, `ops`) and the end-to-end harness (`e2e/`: `CONNECT` and `pg_read_all_stats` since #31, plus `USAGE` and `SELECT` on the seeded `crm`, `billing` and `ops` schemas with matching default privileges since #50) use the minimal variant. As a test-only deviation, they set the role password with a `PASSWORD` literal in a session that does not record it.

**MySQL / MariaDB** ([ADR-0018](adr/0018-mysql-mariadb-grants-and-connector.md), minimal variant, recommended default). Discovery through per-database `SELECT` only.
```sql
-- Restrict the host to the agent's address; require TLS; at least 3 connections
-- (a scan, a concurrent check() and the separate KILL QUERY connection), 4 recommended.
CREATE USER 'databastion'@'10.0.0.15' IDENTIFIED BY '...'
  REQUIRE SSL WITH MAX_USER_CONNECTIONS 4;
-- MariaDB only: a safety net, the connector sets its own statement timeout.
-- ALTER USER 'databastion'@'10.0.0.15' WITH MAX_STATEMENT_TIME 30;

-- Discovery: per application database
GRANT SELECT ON app.* TO 'databastion'@'10.0.0.15';

-- Audit (phase 4) only: statement history. Omit for a Discovery-only target.
-- GRANT SELECT ON performance_schema.* TO 'databastion'@'10.0.0.15';
```
- Never grant `SELECT ON *.*` in the minimal variant: it reads `mysql.user` / `mysql.global_priv` (password hashes; a `mysql_native_password` hash is enough to log in), `mysql.servers` (`FEDERATED` credentials) and the general and slow log tables. No `PROCESS` (other sessions' statement text) and no `SHOW VIEW` either. `check()` reports any global privilege, any privilege beyond `SELECT`, `WITH GRANT OPTION`, `SELECT` on `mysql` / `sys`, granted roles and `init_connect` as over-privilege.
- `performance_schema` statement text carries literals: once Audit reads it (phase 4), it goes through the query normalizer before leaving the agent, like PostgreSQL query text (ADR-0012, obligation 5).
- ADR-0018 also defines an **extended variant** (global `SELECT`) behind an explicit per-target opt-in, `extended_grants: true` in the `mysql` block of `agent.yaml` (default `false`, [ADR-0020](adr/0020-mysql-mariadb-connector-as-merged.md)). With it, `check()` reports the global `SELECT` as an expected warning instead of over-privilege; every other item above is still over-privilege, and the system schemas are never sampled. The account can still read the password hashes: read ADR-0018 before choosing it.
- The connector (P2-C, #52) samples base tables of local storage engines only (never `FEDERATED`, `CONNECT`, `SPIDER`, `S3`, `SPHINX`, NDB or `MERGE` tables, views or virtual generated columns), reads no statistics column during introspection and asks for a table's `TABLE_ROWS` only after reading its engine alone and finding a local one (computing `TABLE_ROWS` opens the table's handler, so a `FEDERATED` table would connect to its remote server; [ADR-0020](adr/0020-mysql-mariadb-connector-as-merged.md)), refuses cleartext, PAM, `sha256_password`, `client_ed25519` and RSA key retrieval, and does not support proxies (ProxySQL, MaxScale). Details and residual risks in ADR-0018.
- The dev accounts (`dev/mysql/`, `dev/mariadb/`) use the minimal variant (#52): `SELECT` on the seeded application database only, `REQUIRE SSL`, `MAX_USER_CONNECTIONS 4`, and `MAX_STATEMENT_TIME 30` on MariaDB. As a dev-only deviation, the host is `'%'` (the agent connects through a published port).

MongoDB: `read` roles on the targeted databases + `clusterMonitor`. OpenLDAP: a service DN with read rights on the tree and on `cn=accesslog`.

## Deployment recommendations
- Agents and console run as a **non-root** user, read-only file system, `cap_drop: ALL`, `no-new-privileges`
- Console behind a reverse proxy (Traefik / Nginx / Caddy) with HTTPS
- The reverse proxy must not log the `X-CSRF-Token`, `Authorization` or `Cookie` request headers. Caddy redacts only `Authorization`, `Cookie` and `Set-Cookie` by default; add a log filter for `X-CSRF-Token` (see [e2e/Caddyfile](../e2e/Caddyfile)). Check the equivalent settings on other proxies
- The console's internal database is never exposed outside the Docker network
- Enable the databases' native logs (pgaudit, MariaDB audit plugin, OpenLDAP `accesslog`…)

## Points of attention
- **Performance**: bounded sampling (N rows per column, `TABLESAMPLE` when possible), configurable off-peak execution, `statement_timeout` on every agent query
- **False positives**: per-finding marking by administrators, reset automatically when a rescan matches more values (see [Findings ingestion](#findings-ingestion)); policy exceptions per agent, target, classifier or location (#45, [ADR-0014](adr/0014-policy-and-incident-model.md))
- **Upgrades**: the agent stays compatible with protocol version N-1; the console advertises the minimum expected version
