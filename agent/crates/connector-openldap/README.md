# databastion-connector-openldap

OpenLDAP connector of the DataBastion agent: Discovery, `check()` and Audit
through `cn=accesslog` (phase 6,
[ADR-0029](../../../docs/adr/0029-openldap-connector.md)). The client, the
searches and the Audit source are described in
[agent/README.md](../../README.md#openldap-connector); this page records what
an operator sets up and what the connector does not cover.

## Account

A dedicated service DN with `read` on the monitored tree, **no access to
password attributes**, and `read` on the `slapo-accesslog` database for
Audit. In `cn=config` (adapt the suffix and the DN):

```
# Data database: credentials first, then the tree.
olcAccess: {0}to attrs=userPassword,authPassword by self =xw by anonymous auth by * none
olcAccess: {1}to dn.subtree="dc=example,dc=org" by dn.exact="cn=databastion,ou=services,dc=example,dc=org" read by * break
# Log database (Audit only).
olcAccess: {0}to dn.subtree="cn=accesslog" by dn.exact="cn=databastion,ou=services,dc=example,dc=org" read by * none
# Result sizes: at least limits.max_sample_rows on the tree, 1000 on the log.
olcLimits: dn.exact="cn=databastion,ou=services,dc=example,dc=org" size=1000 time=60
```

- The connector never requests `userPassword`, `authPassword`, their
  subtypes, nor the Samba, Kerberos and `pwdHistory` hashes, whatever the
  ACL grants. Their presence is not reported either: the hash scheme is
  inside the value.
- With SASL `EXTERNAL` over `ldapi://` (`openldap.bind: sasl_external`), map
  the agent's Unix uid to the service DN (`olcAuthzRegexp`) and set that DN
  as `account`; no `secret`.
- Restrict the service DN to the agent's address (recommended): the log
  records no client address, so the agent cannot tell its own reads from
  someone else's with its credentials. Before rule {1} on the data database:

  ```
  olcAccess: {0}to * by dn.exact="cn=databastion,ou=services,dc=example,dc=org" peername.ip=10.0.0.15 break by dn.exact="cn=databastion,ou=services,dc=example,dc=org" none by * break
  ```

- Write, `manage` and `auth` access are never needed. OpenLDAP does not show
  a read-only account its effective rights, so `check()` cannot evaluate
  them and always reports `privilege.write_not_evaluated`: check `olcAccess`
  yourself.

`check()` notes:

| Note | Meaning |
|---|---|
| `privilege.password_attributes_readable` | an attributes-only search of the first 64 entries of a naming context disclosed `userPassword` or `authPassword` (the values were not read) |
| `privilege.config_readable` | `cn=config` is readable: ACLs, root password hashes, every setting |
| `privilege.accesslog_without_audit` | `cn=accesslog` is readable while no Audit stream runs |
| `privilege.write_not_evaluated` | always: write access cannot be evaluated read-only |
| `audit.accesslog_not_readable` | no Audit source (level None) |
| `audit.reads_not_logged` | naming contexts without a search record in the last 24 h (count) |
| `audit.failed_operations_not_logged` | naming contexts where no failed operation is proven logged (the agent's read of a missing entry left no record: `olcAccessLogSuccess: TRUE`, or not checked yet): at most Partial (count) |
| `audit.records_dropped` | log entries that did not parse in the last 24 h (count) |

## Audit

`slapo-accesslog` on each monitored database, logging reads:

```
olcOverlay: accesslog
olcAccessLogDB: cn=accesslog
olcAccessLogOps: reads writes session
olcAccessLogSuccess: FALSE
olcAccessLogPurge: 07+00:00 01+00:00
```

(`olcAccessLogSuccess: FALSE` is required for Full: with `TRUE`, failed binds and searches cut by a limit after returning entries are not logged, and `check()` reports at most Partial) and an `entryCSN` index on the log database (`olcDbIndex: entryCSN eq`,
with `reqStart`, `reqDN` and `objectClass`). `olcAccessLogSuccess: FALSE`
also logs failed binds. The level is Full once every naming context shows a
search record from the last 24 h: `check()` looks for one and, when there is
none, reads the context's root entry itself, so a server that logs reads
proves it at the first check. A search record below a naming context nested
in another one proves the nested context only.

Principals: an entry DN usually names a person, so Audit events carry the
DN in clear only for `anonymous`, the agent's own DN and the DNs listed in
`openldap.clear_principals` (service and administrator accounts); every
other principal is sent as the agent's keyed fingerprint of the DN.

What the log does not give, and so the events lack: the client address
(principals carry none, and the agent's own activity is recognized by its
DN, shapes and row budget only) and the object class of the entries a
search returned (events name the objects of the console's
`sensitive_objects` below the search base, else `*` with the container).

## Target settings

```yaml
- id: ldap-main
  engine: openldap
  host: ldap1.internal
  port: 636
  account: cn=databastion,ou=services,dc=example,dc=org
  secret: {file: /etc/databastion/secrets/ldap-main}
  openldap:
    tls: verify_full        # or start_tls (389), or disable (ldapi:// / loopback only)
    # ca_file: /etc/databastion/ldap-ca.pem
    bind: simple            # or sasl_external (ldapi:// socket, no secret)
    accesslog_base: cn=accesslog
    # DNs sent by name in Audit events (others: fingerprints)
    clear_principals: ["cn=admin,dc=example,dc=org"]
```

## Not covered

- Entries whose parent is not a container (`uid=x,cn=group,ou=a,…`), and the
  root entry of each naming context itself.
- Attributes of a syntax outside the text allow-list (DN references,
  binaries, certificates, unknown syntaxes).
- Samples are the first entries of each container in server order, cut by the
  server's size limit for the service DN when it is below `sample_rows`.
- Referrals and subordinate servers (counted, never followed).
- `olcAccessLogSuccess: TRUE` (failed binds are not logged) and an
  `olcAccessLogBase` covering part of a naming context cannot be seen by the
  agent.
- Log entries purged (`olcAccessLogPurge`) before the agent read them.
