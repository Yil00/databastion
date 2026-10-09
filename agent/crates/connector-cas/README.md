# databastion-connector-cas

Apereo CAS connector of the DataBastion agent (phase 8,
[ADR-0041](../../../docs/adr/0041-cas-connector.md)). It reads **local files
only** and opens no network connection of any kind: no HTTP client, no
database client, no actuator endpoint, no CAS credential. CAS stores held in
PostgreSQL, MySQL / MariaDB, MongoDB or OpenLDAP are read by that engine's
connector, with the CAS store guard (ADR-0041 decision 5, #141).

**Status**: wired into the agent (P8-B second part): `CasConnector` is the
`Connector` of the `cas` engine, compiled into the binary with the `cas` Cargo
feature (default). The `cas:` block of a target belongs to the core's schema
(`databastion_core::config::cas`, re-exported in `config`), validated and
resolved when `agent.yaml` is loaded. The crate's closed types
(`CasNoteCode`, `CasSignal`, `CasEvent`, `CasHealth`) are mapped exhaustively
to the core's `NoteCode` / `TargetHealth` and to the masked `MaskedEvent` /
`Signal` before they leave the crate. Its targets, findings and events reach
a console that lists `engine.cas` only (ADR-0042: held in the spool until
then).

## Target

```yaml
targets:
  - id: cas-prod
    engine: cas
    cas:
      service_registry:
        json_dir: /etc/cas/services        # or yaml_dir: YAML definitions (exclusive)
      audit_log:
        path: /var/log/cas/cas_audit.log   # audit-format: JSON, one record per line
        timezone: UTC                      # or a fixed offset ±HH:MM
      clear_principals: [svc-monitoring]   # at most 64; `*` and `unidentified` refused
      client_addr: truncated               # clear | truncated (default) | omitted
```

Absolute paths only, resolved when the configuration is loaded (or reloaded)
and refused under `/proc`, `/sys`, `/dev` and the agent's `state_dir`. No
`host`, `port`, `socket`, `account` or `secret` (refused by the core). Never
detected locally (I5).

## Permissions

The agent's account reads the files through a group without write access
(`0640`, owner the CAS user, group `databastion`; the registry directory
`0750`). Anything the agent could write is refused: a file or directory it
owns, a world-writable one, one group-writable for one of its groups, one
`faccessat(W_OK)` grants (ACLs), or one under an ancestor directory it can
write. **Never give the agent read access to the CAS configuration**
(`cas.properties`, `cas.yml`, `/etc/cas/config`): a registry directory holding
`cas.properties`, `cas.yml`, `application.yml` or `application.properties` is
refused as a whole, and those files are never opened.

## Service registry (Discovery)

- The directory is listed non-recursively; each `.json` entry (`json_dir`),
  or `.yml` / `.yaml` entry (`yaml_dir`) (at most 4096, each at most 1 MiB) is opened with `openat(…, O_NOFOLLOW | O_NONBLOCK)` and
  checked on the descriptor (`fstat`): regular file, one hard link, not
  writable by the agent. Other entries are ignored; refused ones are counted.
- A file is used only when its top-level object has an `@class` of a CAS
  registered service and a `serviceId`; anything else is skipped and none of
  its values is classified. JSON comments are not accepted.
- **YAML** (`yaml_dir`, `src/parse/yaml/`): CAS 8.0.2 loads a YAML file
  only when it starts with `--- !<class>` (`RegisteredServiceYamlSerializer`:
  Jackson writes class hints as verbatim tags) and reads one document. The
  agent requires the same start (after blank lines of spaces only, as CAS
  trims the content; `---` at column 0), takes the class from that root
  tag (a top-level `@class` next to it refuses the file), and **pre-scans
  the raw bytes before any YAML parsing**, following libyaml's tokenizer:
  the file is refused (skipped, counted) on an anchor (`&a`) or an alias
  (`*a`) starting a token; a tag other than a verbatim Java class name
  (`!<[A-Za-z_$][A-Za-z0-9_$.]*>`) placed after `:`, a block `-` or a flow
  sequence `[` / `,` and not on a key; a scalar starting with `<<` (merge
  key, quoted or not); a directive, a second `---` or a `...`; an explicit
  (`?`), empty, multi-line or collection key; `@` or a backquote starting a
  token; a tab outside quoted scalars, comments and block scalar content;
  an indentation indicator on a block scalar; `:` followed by a non-blank
  inside a flow collection; invalid UTF-8, control characters, a BOM, a
  lone CR or a Unicode line break (`U+0085`, `U+2028`, `U+2029`); flow
  collections nested deeper than 4, collections deeper than 32 (a lower
  bound: indentless sequences are not counted; the visitor's depth 32 and
  the deserializer's recursion limit 128 are the backstops), more than
  32 768 lines, or more than 196 608 tokens (scalars, flow collection
  starts, `-` entries and `:` values: three per node the visitor allows),
  since the event builder holds every event before the visitor's bounds
  apply (a 1 MiB `[a,a,…]` is refused before parsing). `&`, `*`, `!` and `#` inside quoted, plain and block
  scalars and comments are text. The class hints are then blanked (replaced
  by spaces, positions unchanged) in a zeroizing copy, which goes through
  the same closed visitor and bounds as JSON with the crate's own YAML
  parser: it never sees an anchor, an alias, a merge key nor a tag.
- **Unquoted numbers (YAML)**: YAML resolves `phone: 33612345678` or a card
  number to an integer; below the top level the visitor classifies it as
  its decimal text (a leading `+`, a `0x` / `0o` prefix and `_` are lost;
  a number with a leading zero stays a string). Floats are not classified.
  JSON numbers are not classified (unchanged).
- **YAML parser** ([ADR-0046](../../../docs/adr/0046-cas-yaml-registry-parser-without-unsafe-libyaml.md),
  refining ADR-0041 decisions 4 and 13): an own parser of the subset the
  pre-scan accepts, under `#![forbid(unsafe_code)]`, adding no crate. The
  scanner that refuses and blanks (`parse/yaml/scan.rs`) runs a second
  time, in parse mode, over the blanked copy and emits libyaml's tokens,
  with libyaml's own errors (a simple key at the indentation without its
  `:`, a key more than 1024 bytes before its `:`, a document marker inside
  a quoted scalar, a refused escape); `parse/yaml/events.rs` is libyaml's
  parser state machine over them, building the events of the one document
  before the visitor runs; `parse/yaml/de.rs` is the `serde::Deserializer`
  over the events. The accepted subset, the refusals and the values are
  those of the former `serde_yaml_ng` 0.10 path (plain scalars resolve as
  its untagged scalars: nulls, booleans, decimal / `0x` / `0o` / `0b`
  integers, floats; quoted and block scalars are strings; keys are read as
  strings), so findings do not change. `serde_yaml_ng` (on `unsafe-libyaml`,
  a machine translation of libyaml archived by its author) is a
  dev-dependency only: the oracle of differential property tests
  (`src/proptests.rs`) and of the `cas_registry_yaml_diff` fuzz target,
  which check that both read the same values and the same definition on
  every file the pre-scan accepts, or both fail. The core still links it
  for `agent.yaml` (root-owned configuration, ADR-0046 decision 5).
- **JSON without unwiped copies**: on the JSON path every key and value
  the visitor reads is a raw value borrowed from the zeroizing file buffer,
  and strings (the `clientSecret` whose form is taken, the classified
  values) are unescaped by `databastion_core::jtext` into zeroizing
  buffers sized once: `serde_json` never unescapes one into its scratch
  buffer, which is not wiped. Containers are walked by parsing their raw
  text again (at most 32 passes over a 1 MiB file). A definition whose
  bytes are not all UTF-8 is refused as malformed (before, bytes that are
  not UTF-8 in a skipped value were accepted); a lone surrogate escape or
  an out-of-range number in a skipped value is not examined, as before.
- **YAML without unwiped copies** (ADR-0046 decision 3): tokens and
  events hold byte positions only. A scalar is decoded only when the
  visitor reads it: a value the visitor skips (credential fields,
  structural keys) is never decoded nor copied. A scalar whose value is its
  own text (single-line plain, single-line quoted without escape nor `''`)
  is borrowed from the zeroizing copy of the file; any other (line folding,
  escapes, block scalars) is built once in a zeroizing buffer allocated at
  its final size, which never grows, and wiped when the visitor returns.
  Deserializer errors carry no text. A test parses a definition whose
  credential values hold a run-time marker in every form that reaches the
  parser, then searches the process's writable memory for it (none left;
  the former `serde_yaml_ng` path left dozens of copies).
- **Credential values blanked before YAML parsing** (review of #169, L2;
  kept as defence in depth by ADR-0046): the pre-scan also blanks (spaces, positions unchanged) the content of every
  single-line plain, single-quoted or double-quoted scalar that starts on
  the line of a credential key's `:` (a key matching the visitor's
  credential words): the parser never sees it, and the visitor skips the
  key's value as before. The `SecretForm` of the top-level `clientSecret`
  (a key of the root mapping, whatever the root block mapping's
  indentation) is computed by the pre-scan from the value before blanking
  (YAML's null spellings are absent); any other key spelled `clientSecret`
  is never blanked (fail safe, review of #180, M1). A double-quoted value
  with an escape libyaml refuses (`"\q"`, `"\uD800"`) is never blanked,
  so that blanking never turns an invalid document into a valid one
  (review of #180, L1). **Not blanked**: values on the next line,
  multi-line and block scalars, values after a tag, nested credential
  subtrees (`apiPassword:` then a mapping or a list), keys written with a
  double-quoted escape, a nested `clientSecret`, and a top-level
  `clientSecret` whose double-quoted value holds an escape are not
  blanked: the visitor skips them without decoding them (the top-level
  `clientSecret` is decoded into a zeroizing buffer for its form only).
- Credential fields are never sampled: `clientSecret`, and every key whose
  name contains (case-insensitively) `secret`, `password`, `passwd`, `pass`,
  `pwd`, `key`, `token`, `credential`, `jwk`, `private`, `keystore`,
  `authorization`, `auth`, `cookie`, `bearer`, `salt`, `cipher`, `signing` or
  `header`. This is stricter than the list of ADR-0041 decision 4 (security
  review of #138 M2): every HTTP header map or list (`headers`,
  `httpHeaders`) of the RESTful attribute release policy, the remote
  endpoint access strategy and the HTTP-based proxy and ticket policies is
  skipped whole, as are basic-authentication fields. For `clientSecret`,
  only its form is recorded (absent, reference, encrypted, clear): only a
  `{cipher}` value or a five-segment compact JWE counts as encrypted (a JWS
  is readable); services holding one in clear are counted
  (`security.client_secrets_in_clear`).
- URLs (`scheme://…`, protocol-relative `//…`, and the escaped `\/\/` and
  `%2F%2F` forms) lose everything up to the last `@` or `%40` of the URL (the
  userinfo, whatever characters the password holds), then their query
  string, fragment and `;` parameters (JDBC SQL Server `;password=…`, path
  parameters such as `;jsessionid=`), before classification. An `@` before
  the `//` (JDBC `thin:scott/tiger@//db`) drops everything before it;
  without a `//`, an `@` preceded by `:`, `%3A`, `/`, `;` or `|`
  (`user:pass@host`, JDBC `scott/tiger@db:1521:SID`) drops everything up to
  the last `@`, then the query string and fragment go, and the `;`
  parameters when a `:` precedes them (`jdbc:sqlserver:db;password=…`).
  Plain e-mail addresses are kept; a `;`-separated address list reads as a
  userinfo and loses all but its last domain (over-stripping, accepted).
  **Residual forms** (not stripped): a credential in a token without `//`,
  `@` nor `?`, `#`, `;` (`user:password` alone, `password=…` as plain
  text), one separated from its URL by a blank, a quote or a backquote (the
  token ends there), a password whose userinfo is not followed by an `@`
  (`https://host/?` with a custom header scheme, `sftp://user,pass:host`),
  and encodings other than the percent and JSON-escaped forms above
  (double percent-encoding, HTML entities, base64). Such a value is still
  only classified: what leaves is a masked sample (at most 4 characters of
  it kept) or a fingerprint, never the value.
- Besides the four names of ADR-0041 decision 3, a directory holding
  `application[-*]`, `cas[-*]` or `bootstrap[-*]` `.yml` / `.yaml` /
  `.properties` files, or key material (`thekeystore`, `*.jwks`, `*.jks`,
  `*.jwk`, `*.p12`, `*.pkcs12`, `*.p8`, `*.pem`, `*.der`, `*.key`, `*.pfx`,
  `*.jceks`, `*.keystore`, `*.bcfks`), is
  refused as a whole. An entry on another device than the
  directory (a mount point) is skipped.
- Per scan, at most 32 MiB of values are pooled, and at most 512 `serviceId`
  patterns are compiled (64 KiB each); a file beyond either budget counts as
  skipped for a limit, and a service ticket whose lookup reaches a service
  without a compiled pattern names no service (`*`). Registry files the agent could write are counted and
  reported as `privilege.registry_writable`.
- Locations: `service_registry` / service type / service name (or `*`) /
  field path (`contacts[].email`, `properties.*.values[]`).
- The `who` of `AUTHENTICATION_SUCCESS` records in the last 1 MiB of the audit
  log is classified as `audit_trail` / `audit_log` / `who`.

## Audit log

The core tailer opens the log with `O_NOFOLLOW` (first open and every reopen
after a rotation) and runs this crate's checks on its own handle after each
(re)open (`Tailer::with_open_check`): the declared path still resolves where
it did at load, a regular file with one hard link, not writable by the agent
(owner, mode, `faccessat`, ancestors), the path bound to the handle's
`(st_dev, st_ino)`. A symlink or a hard link swapped in at rotation is never
read (security review of #138 L2).

CAS must write the JSON audit format, one record per line, with a log layout
that writes the message alone (`%m%n`), and should not log request headers
(`cas.audit.engine.http-request-headers`, or `auditable-fields` without
`headers`): records with a `headers` key raise `security.audit_headers_logged`.
The `DEFAULT` (`WHO: … WHAT: …`) format is not supported
(`audit.log_format_unsupported`).

- `AUTHENTICATION_SUCCESS` → `connect`, `AUTHENTICATION_FAILED` →
  `auth_failure`, `SERVICE_TICKET_CREATED` → `read` of the matching service,
  `OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED` (OAuth 2.0 / OIDC tokens issued by
  the token endpoint, any grant) → `read` of the client's registry entry for
  the token-only grants when the token request names it (below), of `*`
  otherwise (CAS 8.0.2 writes no service in that record),
  `SAVE_SERVICE_SUCCESS` / `DELETE_SERVICE_SUCCESS` → `dcl`; other actions
  (`OAUTH2_ACCESS_TOKEN_REQUEST_CREATED` included) give no event and are
  counted only.
- OAuth 2.0 / OIDC action names and `what` shapes were taken from the CAS
  8.0.2 dev service (authorization code, implicit, `refresh_token`,
  `client_credentials`, `password`): real records, token values redacted, in
  [fixtures/cas-8.0.2-oauth-oidc-audit.jsonl](fixtures/cas-8.0.2-oauth-oidc-audit.jsonl)
  (the client `scratch-m2m` and `https://m2m.example.org/cb` come from a
  local-only service definition with every grant enabled, not from the dev
  registry). An authorization code login writes `SERVICE_TICKET_CREATED`
  (`service` = the redirect URI) and then the token response: two `read`
  events. `OIDC_ID_TOKEN_CREATED` (its `what` holds the ID token and the
  token request's `Authorization` header, client secret included),
  `OAUTH2_AUTHORIZATION_RESPONSE_CREATED` and `OAUTH2_USER_PROFILE_CREATED`
  are counted only; their `what` is never read.
- **Token-only grants** ([ADR-0044](../../../docs/adr/0044-cas-token-only-grants-client-naming.md)):
  `refresh_token`, `client_credentials` and `password` write no service
  ticket, and their token request's `service` is the client id. From
  `OAUTH2_ACCESS_TOKEN_REQUEST_CREATED` (`who` `audit:unknown`) the parser
  reads only the strings `grant_type` and `service` of the object-form
  `what` (`code`, the authorization code or refresh token id, `scope`,
  `response_type` and every other key are skipped unread; a duplicate
  `grant_type` or `service` drops the record), and, for that record and the
  token response only, `serverIpAddress` as an IP literal. The service index
  maps a keyed tag of each OAuth / OIDC entry's top-level `clientId` (exact
  bytes, at most 1024; a client id shared by two entries maps to none) to
  its entry; raw client ids are not kept, and the tag key is a fresh random
  key of each index. Each token request stays pending for 5 s (at most 1024
  per stream, the oldest evicted; not persisted; dropped when the index is
  replaced), keyed by a keyed tag of the client address, the server address
  and the whole user agent. A token response is named after the entry when
  every pending request of its key selects that entry and, for
  `client_credentials`, its `who` tag equals the client id tag; the request
  consumed is the oldest the response can belong to. A pending request that
  cannot name (`authorization_code`, the device grant, an unknown grant or
  client id, no object `what`) only makes a response of its key `*`.
  Otherwise the response is a `read` of `*`, nothing is consumed, and the
  case is counted: named, unmatched, ambiguous and evicted counts go to the
  agent log, at most one line per 10 minutes, counts only. Losses fail
  towards `*` (security review of #182): an evicted request or a line
  dropped in a read (oversized, unparsable, a panic) makes every pending
  request unnamed and taints 5 s around the read; a skipped registry file
  (or more than 4096 services) disables the client match of that index; a
  pending request more than 5 s before or after a record is dropped; a
  duplicate `serverIpAddress` drops the token record only. Residual risk: a
  token request record lost where the agent cannot see it (a restart
  between request and response, a record CAS did not write), with another
  request of the same key pending, can name the wrong client within 5 s.
- `what` (which can hold a ticket id, a live SSO bearer credential) is a
  string or, as CAS 8.0 writes it, an object such as
  `{"service": "https://…", "ticketId": "ST-1-…"}`: from an object only the
  string `service` is read, every other key (`ticketId`, `principal`,
  `credential`…) and nested value is skipped without being copied, and a
  duplicate `service` drops the record. Kept keys and values are borrowed
  from the line (held by the tailer in a zeroizing buffer) as raw JSON and
  unescaped by the core's `jtext` module (`databastion_core::jtext`, shared
  with the service-definition parser and the MySQL / MariaDB JSON audit
  records) into zeroizing buffers sized once,
  so `serde_json`'s private scratch buffer, which is never wiped, receives no
  string of the record. It is reduced
  to the service URL's scheme and host at parse time, used only to pick a
  registry entry, then dropped. Ticket ids are never kept, logged,
  fingerprinted nor reported. Only a literal `@` ends a userinfo there; an
  authority holding `%` or `\`, or followed by an `@` before the next `/`,
  `?` or `#`, names no service (`*`), as does a lookup that reaches a
  `serviceId` pattern that cannot be evaluated (Java-only syntax, or beyond
  the compiled-pattern budget) before a match. The service index is the one
  of the last Discovery scan, or is built when the stream starts if no scan
  ran since the agent started.
- `userAgent` keeps its first product token, reduced to the contract
  `Principal.application` alphabet (`[A-Za-z0-9._:/+-]`, others become `_`)
  and 64 characters.
- Principals are fingerprinted except `clear_principals`; failed
  authentications always are.
- Client addresses: IPv4-mapped and IPv4-compatible IPv6 addresses are read
  as IPv4; `::` and `::1` are sent as is. `truncated` keeps an IPv4 /24 and an IPv6 /56; for 6to4
  (`2002::/16`) the embedded IPv4 address is cut to its /24; for Teredo
  (`2001::/32`) the /56 zeroes the obfuscated client address and port.
  Failures without a parseable address share one "unknown address" window
  for the many-accounts signal.
- Signals: `volume.failed_logins_many_accounts` (one address, 16 distinct
  principals failing within 10 minutes; further failures aggregated per
  address and minute with the principal `*`) and
  `volume.failed_logins_one_account` (one principal, 20 failures within
  10 minutes). Client addresses come from `X-Forwarded-For` by default and are
  only as trustworthy as the proxy in front of CAS. The windows are keyed by
  tags of a random key made when the stream starts (never persisted nor
  sent); failures aggregated because a window was full are counted in the
  heartbeat metric `audit_window_overflow_total`. The `*` principal is
  `EventPrincipal::many_accounts`: the core sends `db_user` `*` only for it,
  on a `cas_audit_log` `auth_failure` with the many-accounts signal.
- Level: never Full; Partial with a successful authentication and a service
  ticket or token issuance (`OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED`) in the
  last 24 h; Limited with one of them; None before any record.

## Not done yet

Subdirectories of the registry (CAS reads the JSON and YAML registries
recursively, with one subdirectory per service type; the agent lists one
level only), YAML anchors, aliases and merge keys (refused), and the records
of the OAuth 2.0 device authorization grant (not exercised against CAS 8.0.2).
