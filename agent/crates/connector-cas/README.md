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
- **YAML** (`yaml_dir`, `src/parse/yaml.rs`): CAS 8.0.2 loads a YAML file
  only when it starts with `--- !<class>` (`RegisteredServiceYamlSerializer`:
  Jackson writes class hints as verbatim tags) and reads one document. The
  agent requires the same start at byte 0, takes the class from that root
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
  collections nested deeper than 4, collections deeper than 32, or more than
  32 768 lines. `&`, `*`, `!` and `#` inside quoted, plain and block
  scalars and comments are text. The class hints are then blanked (replaced
  by spaces, positions unchanged) in a zeroizing copy, which goes through
  the same closed visitor and bounds as JSON with `serde_yaml_ng`: the YAML
  parser never sees an anchor, an alias, a merge key nor a tag.
- **YAML parser choice**: `serde_yaml_ng` 0.10, the maintained fork of the
  deprecated `serde_yaml` (MIT / Apache-2.0), which the core already links
  to read `agent.yaml`: no new crate in the agent binary (ADR-0041 decisions
  4 and 13). It drives the closed serde visitor directly (no generic value
  first) and refuses a stream of several documents. `serde_yml` was not
  taken (unsound, unmaintained: RUSTSEC-2025-0068), nor `yaml-rust2` /
  `saphyr` (new dependencies, and their event APIs would need a second
  walker beside the serde visitor). Its scanner is `unsafe-libyaml` 0.2.11,
  a machine translation of libyaml with `unsafe` code, archived by its
  author (no advisory against 0.2.11; RUSTSEC-2023-0075 is fixed in it): the
  pre-scan is what keeps hostile constructs away from it, and
  `serde_yaml_ng` still bounds alias expansion and recursion on its own.
  Moving the core and this crate together to a maintained fork
  (`serde_norway`) or a safe parser is a separate decision.
- **Zeroization gap (YAML)**: the file buffer, the blanked copy and every
  kept value are zeroizing, as for JSON, but libyaml's internal buffers and
  `serde_yaml_ng`'s event list hold copies of every scalar (the
  `clientSecret` included) that are freed without being wiped. The JSON
  path has the narrower gap of `serde_json`'s escape scratch buffer (ROADMAP
  follow-up: move `definition.rs` to `jtext`).
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
  the token endpoint, any grant) → `read` of `*` (CAS 8.0.2 writes no service
  in that record), `SAVE_SERVICE_SUCCESS` / `DELETE_SERVICE_SUCCESS` → `dcl`;
  other actions are counted only.
- OAuth 2.0 / OIDC action names and `what` shapes were taken from the CAS
  8.0.2 dev service (authorization code, implicit, `refresh_token`,
  `client_credentials`, `password`): real records, token values redacted, in
  [fixtures/cas-8.0.2-oauth-oidc-audit.jsonl](fixtures/cas-8.0.2-oauth-oidc-audit.jsonl)
  (the client `scratch-m2m` and `https://m2m.example.org/cb` come from a
  local-only service definition with every grant enabled, not from the dev
  registry). An authorization code login writes `SERVICE_TICKET_CREATED`
  (`service` = the redirect URI) and then the token response: two `read`
  events. `OAUTH2_ACCESS_TOKEN_REQUEST_CREATED` (`who` `audit:unknown`),
  `OIDC_ID_TOKEN_CREATED` (its `what` holds the ID token and the token
  request's `Authorization` header, client secret included),
  `OAUTH2_AUTHORIZATION_RESPONSE_CREATED` and `OAUTH2_USER_PROFILE_CREATED`
  are counted only; their `what` is never read.
- `what` (which can hold a ticket id, a live SSO bearer credential) is a
  string or, as CAS 8.0 writes it, an object such as
  `{"service": "https://…", "ticketId": "ST-1-…"}`: from an object only the
  string `service` is read, every other key (`ticketId`, `principal`,
  `credential`…) and nested value is skipped without being copied, and a
  duplicate `service` drops the record. Kept keys and values are borrowed
  from the line (held by the tailer in a zeroizing buffer) as raw JSON and
  unescaped by the crate (`parse/jtext.rs`) into zeroizing buffers sized once,
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
