# databastion-connector-mongodb

MongoDB connector of the DataBastion agent: Discovery and `check()` (P5-A,
[ADR-0026](../../../docs/adr/0026-mongodb-connector.md)). The client, the
commands and the sampling are described in
[agent/README.md](../../README.md#mongodb-connector); this page records what
an operator sets up and what the connector does not cover. Audit (P5-B,
P5-C) is not implemented: `check()` reports the audit level **None**.

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
reported: they are not needed for Discovery. The grants of the Audit sources
will be defined with P5-B / P5-C.

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

Residual risks are listed in ADR-0026.
