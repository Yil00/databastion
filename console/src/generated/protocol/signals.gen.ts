// GENERATED FILE, DO NOT EDIT. Source: shared/protocol/signals.json.
// Regenerate with `pnpm protocol:generate` (from console/).

/** Registered access-event signal ids (contract signal registry), with their meaning and engines. */
export const SIGNAL_REGISTRY = {
  "shape.bulk_search": {
    "description": "An LDAP search over a container or a subtree (scope one-level, subtree or children) whose filter selects no entry by value: presence tests and objectClass equality assertions only, such as (objectClass=*): the shape of an LDIF export or a bulk ldapsearch. Heuristic: evadable by design.",
    "engines": [
      "openldap"
    ]
  },
  "shape.full_table_copy": {
    "description": "A COPY out of the database of a whole relation, or of a query without filter, aggregation or small limit. Heuristic: evadable by design.",
    "engines": [
      "postgres"
    ]
  },
  "shape.full_table_read": {
    "description": "A read (SELECT, TABLE; a MongoDB find or aggregate) of whole relations or collections: no top-level filter, no aggregation, and no limit or a limit above the agent's large-result threshold (Firebird: FIRST, ROWS or FETCH FIRST). Heuristic: evadable by design.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb",
      "sqlserver",
      "firebird"
    ]
  },
  "shape.keyspace_enumeration": {
    "description": "A Redis / Valkey keyspace enumeration seen in a slow-log or command-log entry: KEYS, or a SCAN with a COUNT above 1000 (redis-cli --scan uses COUNT 10, is usually fast and never sets it). Heuristic: only slow or logged commands are seen, so evadable by design.",
    "engines": [
      "redis",
      "valkey"
    ]
  },
  "signature.backup_database": {
    "description": "A full copy of a database made by or through the server. SQL Server: BACKUP DATABASE or BACKUP LOG (to a file or URL), DBCC CLONEDATABASE, or sp_detach_db (the data files become copyable). Firebird: a services Backup Database or Incremental Backup Database, a connection whose client process name is gbak (declared by the client, so evadable), ALTER DATABASE BEGIN BACKUP (nbackup), CREATE SHADOW, ALTER DATABASE ADD FILE or ADD DIFFERENCE FILE, each reported as a read of *, always reported.",
    "engines": [
      "sqlserver",
      "firebird"
    ]
  },
  "signature.bcp": {
    "description": "A SQL Server bulk export: a read by a client whose application name is one of a closed list of export tools (bcp, sqlpackage export, the SQL Server Import and Export Wizard / DTS), or a session that probed the table's metadata (SET FMTONLY ON, sp_describe_first_result_set) before reading it whole. Heuristic: the application name is declared by the client, so evadable by design.",
    "engines": [
      "sqlserver"
    ]
  },
  "signature.cas_ticket_read": {
    "description": "A read of a Redis / Valkey key guarded by the CAS store guard: a key of the CAS ticket registry's prefix or of the declared CAS stores, or whose name holds a ticket id of a strict CAS prefix (TGT, ST, PT, PGT, OC, AT, RT). Reported as a read of *; the ticket id is never kept. A match on the generic ticket-id shape alone gives the read of * without this signal.",
    "engines": [
      "redis",
      "valkey"
    ]
  },
  "signature.copy_to_file": {
    "description": "A server-side export to a file (COPY ... TO '<file>'), including one issued from dynamic SQL or a procedural block.",
    "engines": [
      "postgres"
    ]
  },
  "signature.copy_to_program": {
    "description": "A server-side export to a program (COPY ... TO PROGRAM).",
    "engines": [
      "postgres"
    ]
  },
  "signature.full_sync": {
    "description": "A full synchronization of a Redis / Valkey server (INFO stats sync_full grew): a copy of the whole dataset over the replication protocol, as a replica's first sync, redis-cli --rdb or a rogue replica make. Reported as a read of * with the replica's address when a replica entry not declared in the agent's configuration shows it.",
    "engines": [
      "redis",
      "valkey"
    ]
  },
  "signature.into_outfile": {
    "description": "A server-side export to a file on the database server (SELECT ... INTO OUTFILE or INTO DUMPFILE), including one the server refused.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "signature.mongodump": {
    "description": "A mongodump run: a read of a collection (find, aggregate, getMore) by a client whose application name (appName) is mongodump. Heuristic: the application name is declared by the client, so evadable by design.",
    "engines": [
      "mongodb"
    ]
  },
  "signature.mongoexport": {
    "description": "A mongoexport run: a read of a collection (find, aggregate, getMore) by a client whose application name (appName) is mongoexport. Heuristic: the application name is declared by the client, so evadable by design.",
    "engines": [
      "mongodb"
    ]
  },
  "signature.mysqldump": {
    "description": "A mysqldump, mariadb-dump, mysqlpump or mydumper run: a whole-table read with SQL_NO_CACHE (what these tools send), by a client whose program_name is one of them, or in a session that took a consistent snapshot, a global read lock or LOCK TABLES, or ran SHOW CREATE TABLE on that table. Heuristic: evadable by design.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "signature.pg_dump": {
    "description": "A pg_dump or pg_dumpall run: that application name on a whole-relation read or copy, or one session copying several whole relations to the client, whatever its application name.",
    "engines": [
      "postgres"
    ]
  },
  "signature.remote_data_access": {
    "description": "Data leaving through the server to another place, flagged even if refused. SQL Server: OPENROWSET (BULK too), OPENDATASOURCE, OPENQUERY, EXEC ... AT, a four-part name in a write target, BULK INSERT, CREATE EXTERNAL TABLE AS SELECT, xp_cmdshell, xp_dirtree / xp_fileexist / xp_subdirs, sp_send_dbmail with @query, sp_invoke_external_rest_endpoint, sp_OACreate / sp_OAMethod, sp_execute_external_script. Firebird: EXECUTE STATEMENT ... ON EXTERNAL, external-file table reads, CREATE TABLE ... EXTERNAL FILE.",
    "engines": [
      "sqlserver",
      "firebird"
    ]
  },
  "volume.failed_logins_many_accounts": {
    "description": "One client address with failed authentications for at least 16 distinct principals within 10 minutes (credential stuffing or password spraying, indistinguishable without the passwords, which are never seen). On CAS, the further failures of that address are aggregated per minute under the principal * (several accounts). Heuristic: the address comes from X-Forwarded-For by default, so evadable by design.",
    "engines": [
      "cas"
    ]
  },
  "volume.failed_logins_one_account": {
    "description": "One principal (fingerprint) with at least 20 failed authentications within 10 minutes, whatever the client addresses (online guessing against one account, including from many addresses). Heuristic: evadable by design.",
    "engines": [
      "cas"
    ]
  },
  "volume.large_reply": {
    "description": "A Valkey command whose reply exceeded the server's large-reply threshold (an entry of the command log's large-reply type, Valkey 8.1 and later), with the reply size as the event's bytes.",
    "engines": [
      "valkey"
    ]
  },
  "volume.large_result": {
    "description": "More rows returned or affected than the agent's large-result threshold (above its maximum Discovery sample, so the agent's own sampling never carries it). Rows, not bytes: on Firebird, a few rows of large blobs do not raise it.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb",
      "openldap",
      "sqlserver",
      "firebird"
    ]
  }
} as const;
