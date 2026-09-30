# databastion-connector-mongodb

MongoDB connector of the DataBastion agent: Discovery and `check()` (P5-A,
[ADR-0026](../../../docs/adr/0026-mongodb-connector.md)) and Audit (P5-B,
P5-C, [ADR-0027](../../../docs/adr/0027-mongodb-audit.md)). The
client, the commands, the sampling and the Audit sources are described in
[agent/README.md](../../README.md#mongodb-connector); this page records what
an operator sets up and what the connector does not cover.

## Account

A custom role with `find` and `listCollections` on each monitored database,
SCRAM-SHA-256 credentials, and the agent's address as the only client
source:

```js
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
  authenticationRestrictions: [{ clientSource: ["10.0.0.15"] }]
});
```

Time-series collections are read through their view (`find` with a limit).
Their bucket collections (`system.buckets.*`) are not covered by
`collection: ""`: if a server refuses the read, the scan counts the
collection as not readable and `check()` reports
`coverage.timeseries_not_readable` (observed in the last scan). The fallback
grant reads their own documents only and is not reported as
over-privilege:

```js
{ resource: { db: "app", system_buckets: "" }, actions: ["find"] }
```

`collection: ""` covers the database's collections except `system.*`. The
connector needs nothing else: databases and collections are listed with
`authorizedDatabases` / `authorizedCollections`, the size estimate is a
`count`, and a user can always kill its own cursors. `check()` reports, as
notes, anything beyond this grant:

| Note | Meaning |
|---|---|
| `privilege.write_actions` | write or administration actions (count) |
| `privilege.read_beyond_discovery` | read actions other than `find` / `listCollections`, e.g. `changeStream` (count) |
| `privilege.cluster_actions` | cluster-wide actions, e.g. `inprog`, `getCmdLineOpts` (count) |
| `privilege.any_database` | a privilege on every database (`readAnyDatabase`, an empty database name) |
| `privilege.system_collections` | `system.*` collections, or the `admin`, `local`, `config` databases |

The built-in `read` role (change streams, `system.js`) and `clusterMonitor`
(other sessions' operations, `system.profile` of every database) are
reported: they are not needed for Discovery.

## Audit

| Edition | Source (`audit_source`) | Level |
|---|---|---|
| Enterprise, Percona Server for MongoDB | `auditLog` JSON file (`mongodb_audit_log`) | Partial once a successful `authCheck` was read in the last 24 h, Limited once any record was read in the last 24 h, None before (ADR-0030) |
| Any | structured JSON server log (`mongodb_log`) | Limited once a record was read in the last 24 h, None before |
| Any (not a `mongos`) | profiler, `system.profile` (`mongodb_profiler`) | Limited once an entry was read in the last 24 h, None before |

Full is never reported: the `auditLog` has no document counts, and the log
and the profiler only hold the operations the server records (slower than
`slowms`, or sampled; the profiler also overwrites itself). One source per
target, in this order of preference.

**File sources** (no database grant). Declare the file in the target:

```yaml
  mongodb:
    audit_log: {path: /var/log/mongodb/auditLog.json, format: audit_log}   # or format: server_log
```

- `auditLog`: `auditLog.destination: file`, `auditLog.format: JSON` (the
  `mongo` schema; BSON and OCSF are not supported), and
  `setParameter.auditAuthorizationSuccess: true`, without which reads and
  writes are not logged (only authentications, DDL, user changes and
  refused commands): the level stays Limited with
  `audit.authcheck_success_pending`. An `auditLog.filter` that leaves reads
  out is the operator's choice and cannot be detected.
- Server log: `systemLog.destination: file` (JSON, MongoDB 4.4 and later).
  Operations are logged when slower than `operationProfiling.slowOpThresholdMs`
  (`slowms`), sampled by `slowOpSampleRate`: a low `slowms` sees more, at a
  cost.
- File ACL: the agent's user reads the file (for instance `0640` with a
  dedicated group on the log directory), never the data directory. These
  files hold other users' literals (filters, documents): never make them
  world-readable. The agent keeps no literal (closed-shape facts only).

**Profiler** (when the agent cannot read the files, e.g. it does not run on
the database host). Profiling itself (`profile` level, `slowms`) is set by
the operator. The account needs `find` on each database's `system.profile`,
in a role of its own:

```js
db.getSiblingDB("admin").createRole({
  role: "databastionAuditProfiler",
  privileges: [
    { resource: { db: "app", collection: "system.profile" }, actions: ["find"] }
  ],
  roles: []
});
db.getSiblingDB("admin").grantRolesToUser("databastion", [{ role: "databastionAuditProfiler", db: "admin" }]);
```

This grant lets the account read every profiled command of the database,
literals included, over the network: prefer a file source. `check()` counts
it as the Audit grant only while an Audit stream reads the profiler, and
reports it as `privilege.system_collections` otherwise.

| Note | Meaning |
|---|---|
| `audit.authcheck_success_pending` | `auditLog`: no successful `authCheck` read in the last 24 h (Limited) |
| `audit.auditlog_on_community` | an `auditLog` is declared, but the server is Community: not used |
| `audit.log_without_row_counts` | the `auditLog` has no document counts |
| `audit.slow_operations_only` | server log or profiler: slow or sampled operations only |
| `audit.limited_pending_first_record` | `auditLog`, server log or profiler: nothing read in the last 24 h (None) |
| `audit.source_not_configured` | no usable source (level None) |
| `audit.log_not_readable` | the declared file cannot be read by the agent |
| `audit.records_dropped` | records that did not parse, oversized or damaged, in the last 24 h |

Detected: `signature.mongodump` and `signature.mongoexport` (the tools'
application name, which a client declares itself), whole-collection reads
(`shape.full_table_read`) and more than 10 000 documents in one operation
(`volume.large_result`, log and profiler). The agent's own reads are left
out only from its account, its address and its application name
(`databastion-agent`), within its Discovery budget, and only reads: writes,
DDL and DCL with its identity are always reported. On the `auditLog` (no
counts), only a `find` with a limit within the budget is left out.

## Target settings

```yaml
- id: mongo-app
  engine: mongodb
  host: db3.internal          # one member or a mongos; or socket: /tmp/mongodb-27017.sock
  port: 27017
  account: databastion
  secret: {file: /etc/databastion/secrets/mongo-app}
  mongodb:
    tls: verify_full          # disable (socket / loopback literal), disable_insecure (warned)
    ca_file: /etc/databastion/mongo-ca.pem
    auth_source: admin
```

To scan a replica set, declare the member to read from (a secondary spares
the primary); the connector never contacts the other members.

## Not covered

- Views (their pipeline is never run), `system.*` and queryable-encryption
  state collections, and the `admin`, `local` and `config` databases.
- Time-series collections the server refuses to the account (see above).
- Collections the account holds no privilege on: with `authorizedCollections`
  they are not listed, so they cannot be counted as not covered.
- Document parts beyond the walk bounds: nesting deeper than 20 levels,
  array elements after the 16th, values after the 512th of a document.
- Encrypted, UUID, compressed, sensitive and vector binaries, binaries that
  are not UTF-8 text, ObjectIds, booleans, JavaScript code, timestamps,
  non-integral doubles.
- Accounts without SCRAM-SHA-256 credentials (SCRAM-SHA-1 only, LDAP,
  Kerberos, X.509, AWS, OIDC), `mongodb+srv` URIs, servers older than 5.0.
- Audit: operations the server does not record (Community: faster than
  `slowms`), profiler entries overwritten between two polls, the activity of
  other replica-set members (the log and the profiler are per node), the
  user of a connection that authenticated before the agent started reading
  the server log (reported as an unidentified account).

Residual risks are listed in ADR-0026 and ADR-0027.
