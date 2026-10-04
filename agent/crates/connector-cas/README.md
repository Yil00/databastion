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
  name contains `secret`, `password`, `passwd`, `key`, `token`, `credential`,
  `jwk`, `private` or `keystore`. For `clientSecret`, only its form is
  recorded (absent, reference, encrypted, clear): services holding one in
  clear are counted (`security.client_secrets_in_clear`).
- URLs lose their userinfo, query string and fragment before classification.
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
- Signals: `volume.failed_logins_many_accounts` (one address, 16 distinct
  principals failing within 10 minutes; further failures aggregated per
  address and minute with the principal `*`) and
  `volume.failed_logins_one_account` (one principal, 20 failures within
  10 minutes). Client addresses come from `X-Forwarded-For` by default and are
  only as trustworthy as the proxy in front of CAS.
- Level: never Full; Partial with a successful authentication and a service
  ticket in the last 24 h; Limited with one of them; None before any record.

## Not done yet

YAML registries, the OIDC / OAuth token issuance actions (names to verify
against CAS 8.0), the core wiring and the console rendering (P8-C), the CAS
store guard in the other connectors, the CAS dev service and the end-to-end,
I2 and load tests (P8-D).
