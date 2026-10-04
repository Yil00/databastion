# databastion-connector-cas

Apereo CAS connector of the DataBastion agent (phase 8,
[ADR-0041](../../../docs/adr/0041-cas-connector.md)). It reads **local files
only** and opens no network connection of any kind: no HTTP client, no
database client, no actuator endpoint, no CAS credential. CAS stores held in
PostgreSQL, MySQL / MariaDB, MongoDB or OpenLDAP are read by that engine's
connector, with the CAS store guard (ADR-0041 decision 5, a later task).

**Status**: the crate is complete for the file sources but **not wired into
the agent core yet**: the `cas` engine, the `cas_audit_log` source, its target
notes and its two signals are added to the protocol in P8-C. Until then a
`cas` target cannot be declared in `agent.yaml`, and the crate keeps its own
closed types (`CasNoteCode`, `CasSignal`, `CasEvent`, `CasHealth`).

## Target

```yaml
targets:
  - id: cas-prod
    engine: cas
    cas:
      service_registry:
        json_dir: /etc/cas/services        # JSON only for now (yaml_dir is refused)
      audit_log:
        path: /var/log/cas/cas_audit.log   # audit-format: JSON, one record per line
        timezone: UTC                      # or a fixed offset ±HH:MM
      clear_principals: [svc-monitoring]   # at most 64; `*` and `unidentified` refused
      client_addr: truncated               # clear | truncated (default) | omitted
```

Absolute paths only, resolved when the configuration is loaded and refused
under `/proc`, `/sys`, `/dev` and the agent's own directories. No `host`,
`port`, `account` or `secret`.

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

- The directory is listed non-recursively; each `.json` entry (at most 4096,
  each at most 1 MiB) is opened with `openat(…, O_NOFOLLOW | O_NONBLOCK)` and
  checked on the descriptor (`fstat`): regular file, one hard link, not
  writable by the agent. Other entries are ignored; refused ones are counted.
- A file is used only when its top-level object has an `@class` of a CAS
  registered service and a `serviceId`; anything else is skipped and none of
  its values is classified. JSON comments are not accepted.
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
  string and fragment, before classification. An `@` before the `//` (JDBC
  `thin:scott/tiger@//db`) drops everything before it; without a `//`, an
  `@` preceded by `:` or `/` (`user:pass@host`, JDBC `scott/tiger@db:1521:SID`)
  drops everything up to it. Plain e-mail addresses are kept.
- Besides the four names of ADR-0041 decision 3, a directory holding
  `application[-*]`, `cas[-*]` or `bootstrap[-*]` `.yml` / `.yaml` /
  `.properties` files, or key material (`thekeystore`, `*.jwks`, `*.jks`,
  `*.p12`, `*.pem`, `*.key`, `*.pfx`, `*.jceks`, `*.keystore`, `*.bcfks`), is
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

CAS must write the JSON audit format, one record per line, with a log layout
that writes the message alone (`%m%n`), and should not log request headers
(`cas.audit.engine.http-request-headers`, or `auditable-fields` without
`headers`): records with a `headers` key raise `security.audit_headers_logged`.
The `DEFAULT` (`WHO: … WHAT: …`) format is not supported
(`audit.log_format_unsupported`).

- `AUTHENTICATION_SUCCESS` → `connect`, `AUTHENTICATION_FAILED` →
  `auth_failure`, `SERVICE_TICKET_CREATED` → `read` of the matching service,
  `SAVE_SERVICE_SUCCESS` / `DELETE_SERVICE_SUCCESS` → `dcl`; other actions are
  counted only.
- `what` (which can hold a ticket id, a live SSO bearer credential) is reduced
  to the service URL's scheme and host at parse time, used only to pick a
  registry entry, then dropped. Ticket ids are never kept, logged,
  fingerprinted nor reported.
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
  only as trustworthy as the proxy in front of CAS.
- Level: never Full; Partial with a successful authentication and a service
  ticket in the last 24 h; Limited with one of them; None before any record.

## Not done yet

The core tailer opens the audit log without `O_NOFOLLOW` and without this
crate's validation hook: a gate for the wiring PR after P8-C (security review
of #138 L2). YAML registries, the OIDC / OAuth token issuance actions (names to verify
against CAS 8.0), the core wiring and the console rendering (P8-C), the CAS
store guard in the other connectors, the CAS dev service and the end-to-end,
I2 and load tests (P8-D).
