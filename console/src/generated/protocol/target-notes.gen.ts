// GENERATED FILE, DO NOT EDIT. Source: shared/protocol/target-notes.json.
// Regenerate with `pnpm protocol:generate` (from console/).

/** Registered `TargetNote` codes: the phrase catalog (`{count}` and `{labels}` placeholders) and engines. */
export const TARGET_NOTE_REGISTRY = {
  "audit.accesslog_not_readable": {
    "description": "cn=accesslog (openldap.accesslog_base) is not readable by the agent's service DN, or does not exist: no Audit source.",
    "engines": [
      "openldap"
    ]
  },
  "audit.audit_log_filter_not_read": {
    "description": "The audit_log_filter component is active, but its log file is not configured in agent.yaml (mysql.audit_log), so the agent does not read it.",
    "engines": [
      "mysql"
    ]
  },
  "audit.audit_log_plugin_not_read": {
    "description": "The audit_log plugin is active, but its log file is not configured in agent.yaml (mysql.audit_log), so the agent does not read it.",
    "engines": [
      "mysql"
    ]
  },
  "audit.auditlog_on_community": {
    "description": "The auditLog configured in agent.yaml (mongodb.audit_log, format audit_log) needs MongoDB Enterprise or Percona Server for MongoDB, but the server is MongoDB Community: it is not used.",
    "engines": [
      "mongodb"
    ]
  },
  "audit.auth_failures_not_seen": {
    "description": "No failed authentication (AUTHENTICATION_FAILED) read from the CAS audit log in the last 7 days: check that the CAS audit configuration does not exclude it. The level stays Partial.",
    "engines": [
      "cas"
    ]
  },
  "audit.auth_records_not_seen": {
    "description": "Limited: CAS audit records were read in the last 24 h, but no successful authentication (AUTHENTICATION_SUCCESS): authentication actions may be excluded from the CAS audit trail.",
    "engines": [
      "cas"
    ]
  },
  "audit.authcheck_success_pending": {
    "description": "Partial once the Audit stream has read a successful authCheck record of the auditLog (auditAuthorizationSuccess enabled; none in the last 24 h): reported Limited until then.",
    "engines": [
      "mongodb"
    ]
  },
  "audit.failed_operations_not_logged": {
    "description": "{count} naming context(s) where no failed operation is proven to be logged in cn=accesslog in the last 24 h: the agent's read of a missing entry left no record (olcAccessLogSuccess: TRUE logs successful operations only), or it could not be checked yet. Capped or failed exports may go unseen; the level is at most Partial.",
    "engines": [
      "openldap"
    ]
  },
  "audit.full_pending_first_record": {
    "description": "Full once the Audit stream has read a pgaudit record (none in the last 24 h): reported Partial until then.",
    "engines": [
      "postgres"
    ]
  },
  "audit.general_log_enabled": {
    "description": "The general query log is enabled; it is not used as an audit source.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "audit.history_long_consumer_disabled": {
    "description": "The performance_schema events_statements_history_long consumer is disabled.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "audit.history_not_readable": {
    "description": "The performance_schema statement history is not readable by the agent's account.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "audit.limited_pending_first_record": {
    "description": "Limited once the Audit stream has read a record of its source (MongoDB server log or profiler, CAS audit log; none in the last 24 h): reported None until then.",
    "engines": [
      "mongodb",
      "cas"
    ]
  },
  "audit.log_format_unsupported": {
    "description": "The CAS audit log holds records but none in the JSON audit format (cas.audit.engine.audit-format: JSON, one record per line): the DEFAULT format is not read, so there is no Audit source.",
    "engines": [
      "cas"
    ]
  },
  "audit.log_not_readable": {
    "description": "The audit log file configured in agent.yaml is not readable by the agent (on CAS, also when it is refused because the agent could write it or one of its parent directories).",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb",
      "cas"
    ]
  },
  "audit.log_plugin_mismatch": {
    "description": "The audit log configured in agent.yaml has no matching active audit plugin logging statements in a supported format: it is not used.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "audit.log_without_row_counts": {
    "description": "The audit log carries no row counts: result volumes are unknown.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb"
    ]
  },
  "audit.partial_pending_first_record": {
    "description": "Partial once the Audit stream has read a record of the audit log (none in the last 24 h): reported Limited until then.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "audit.performance_schema_not_readable": {
    "description": "performance_schema is not readable by the agent's account (no Audit grant).",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "audit.pgaudit_log_not_configured": {
    "description": "pgaudit is present; Full needs its log file in agent.yaml (postgres.audit_log).",
    "engines": [
      "postgres"
    ]
  },
  "audit.pgaudit_not_loaded": {
    "description": "pgaudit settings are set, but the pgaudit library is not loaded (shared_preload_libraries): pgaudit writes no record.",
    "engines": [
      "postgres"
    ]
  },
  "audit.pgaudit_read_class_missing": {
    "description": "pgaudit.log does not include the read class.",
    "engines": [
      "postgres"
    ]
  },
  "audit.reads_not_logged": {
    "description": "{count} naming context(s) with no search record in cn=accesslog in the last 24 h, even after a probe search by the agent: reads there are not logged (olcAccessLogOps without reads, no accesslog overlay on that database, or an olcAccessLogBase that excludes it).",
    "engines": [
      "openldap"
    ]
  },
  "audit.records_dropped": {
    "description": "{count} audit log record(s) dropped in the last 24 h: not parsable, oversized or damaged.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb",
      "openldap",
      "cas"
    ]
  },
  "audit.records_dropped_severity": {
    "description": "{count} pgaudit record(s) dropped in the last 24 h: their severity differs from pgaudit.log_level.",
    "engines": [
      "postgres"
    ]
  },
  "audit.server_audit_not_read": {
    "description": "server_audit is active ({labels}: logging_on / logging_off, file_output / non_file_output), but its log file is not configured in agent.yaml (mysql.audit_log), so the agent does not read it.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "audit.service_ticket_records_not_seen": {
    "description": "Limited: successful authentications were read from the CAS audit log in the last 24 h, but no service ticket or token issuance record: which application received a ticket is not known.",
    "engines": [
      "cas"
    ]
  },
  "audit.slow_operations_only": {
    "description": "The audit source only records the operations the server logs or profiles (slower than slowms, or sampled): fast reads, such as a quick dump of a small collection, can go unseen.",
    "engines": [
      "mongodb"
    ]
  },
  "audit.source_not_configured": {
    "description": "No MongoDB Audit source: declare the auditLog or the server log file in agent.yaml (mongodb.audit_log), or grant find on system.profile of the monitored databases.",
    "engines": [
      "mongodb"
    ]
  },
  "audit.statement_consumers_disabled": {
    "description": "The performance_schema consumers the statement history depends on (global_instrumentation, thread_instrumentation, events_statements_current) are disabled.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "audit.stream_not_available": {
    "description": "The connector has no Audit stream in this agent build: the audit level is reported None, whatever the server logs or profiles.",
    "engines": [
      "mongodb"
    ]
  },
  "audit.stream_stopped": {
    "description": "The Audit stream stopped after {count} internal errors of the agent in a row (the agent log names the code location): the audit level is reported None until Audit is reconfigured or the agent restarts.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb",
      "openldap",
      "cas"
    ]
  },
  "check.server_is_mariadb": {
    "description": "The server is MariaDB while the target is declared as mysql.",
    "engines": [
      "mysql"
    ]
  },
  "check.server_is_mysql": {
    "description": "The server is MySQL while the target is declared as mariadb.",
    "engines": [
      "mariadb"
    ]
  },
  "check.stage_failed": {
    "description": "check() failed at stage {labels} (a stage_* label); the cause is last_error.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb",
      "openldap",
      "cas"
    ]
  },
  "check.timed_out": {
    "description": "check() did not finish within its time bound.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb",
      "openldap",
      "cas"
    ]
  },
  "coverage.cas_guard_tripped": {
    "description": "{count} column(s) or field(s) held CAS ticket-id-shaped values: those values were dropped before classification and the columns or fields were not read further (CAS store guard).",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb",
      "openldap"
    ]
  },
  "coverage.other_engine_tables": {
    "description": "{count} table(s) with a storage engine outside the local-data allow-list, not sampled.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "coverage.registry_files_skipped": {
    "description": "{count} CAS service registry file(s) skipped: not readable, refused (symbolic or hard link, writable by the agent), too large, not a service definition or not parsable. None of their values is classified.",
    "engines": [
      "cas"
    ]
  },
  "coverage.relations_rls_skipped": {
    "description": "{count} relation(s) skipped because of row-level security (ADR-0012).",
    "engines": [
      "postgres"
    ]
  },
  "coverage.relations_without_select": {
    "description": "{count} relation(s) without SELECT for the agent's role, not sampled.",
    "engines": [
      "postgres"
    ]
  },
  "coverage.remote_engine_tables": {
    "description": "{count} table(s) with a remote-access storage engine, never read (I5).",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "coverage.schemas_without_usage": {
    "description": "{count} schema(s) without USAGE for the agent's role, not covered.",
    "engines": [
      "postgres"
    ]
  },
  "coverage.timeseries_not_readable": {
    "description": "{count} time-series collection(s) refused to the agent's account in the last scan (their reads may need find on their bucket collections, system_buckets resource).",
    "engines": [
      "mongodb"
    ]
  },
  "coverage.views_not_sampled": {
    "description": "{count} view(s) not sampled (their base tables or collections are).",
    "engines": [
      "mysql",
      "mariadb",
      "mongodb"
    ]
  },
  "privilege.accesslog_without_audit": {
    "description": "cn=accesslog is readable while no Audit stream runs for the target: other users' search filters, compared values and old values are readable.",
    "engines": [
      "openldap"
    ]
  },
  "privilege.any_database": {
    "description": "A privilege applies to every database (for example readAnyDatabase, or a resource with an empty database name): databases created later are readable too.",
    "engines": [
      "mongodb"
    ]
  },
  "privilege.beyond_select": {
    "description": "{count} privilege(s) beyond SELECT on databases, tables or columns; the most severe: {labels}.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.cluster_actions": {
    "description": "{count} cluster-wide action(s) (for example inprog, serverStatus, getCmdLineOpts): other sessions' operations and server settings are visible.",
    "engines": [
      "mongodb"
    ]
  },
  "privilege.config_readable": {
    "description": "The engine's configuration is readable by the agent's account. OpenLDAP: cn=config is readable by the agent's service DN (access control rules, root password hashes, every server setting). CAS: CAS configuration files (cas.properties, cas.yml, application.yml or .properties) sit in the declared service registry directory and hold every CAS secret: the registry source is refused and those files are never opened.",
    "engines": [
      "openldap",
      "cas"
    ]
  },
  "privilege.extended_variant": {
    "description": "Extended-variant grants, expected because extended_grants is set: {labels}.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb"
    ]
  },
  "privilege.global_privileges": {
    "description": "{count} global privilege(s) other than SELECT and USAGE; the most severe: {labels}.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.global_select": {
    "description": "Global SELECT: system tables are readable, including mysql.user password hashes.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.grant_option": {
    "description": "A privilege of the account is WITH GRANT OPTION.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.not_evaluated": {
    "description": "Privileges not evaluated: the account name could not be matched, or a privilege list could not be fully read (cut at its limit, or rows skipped; on MongoDB, connectionStatus not readable; on PostgreSQL, the CAS store guard's candidate relation or column list cut at its limit, a name not UTF-8, or its query failed).",
    "engines": [
      "mysql",
      "mariadb",
      "mongodb",
      "postgres"
    ]
  },
  "privilege.other_roles": {
    "description": "Member of {count} non-predefined role(s).",
    "engines": [
      "postgres"
    ]
  },
  "privilege.owner_of_objects": {
    "description": "Owner of {count} object(s).",
    "engines": [
      "postgres"
    ]
  },
  "privilege.password_attributes_readable": {
    "description": "The agent's service DN can read userPassword or authPassword values (seen with an attributes-only search: the values were not read).",
    "engines": [
      "openldap"
    ]
  },
  "privilege.performance_schema_unused": {
    "description": "SELECT on performance_schema is unused (the audit log is the Audit source): the statement text of every session is readable, with clear-text passwords on MariaDB.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.performance_schema_without_audit": {
    "description": "SELECT on performance_schema while no Audit stream runs for the target: the statement text of every session is readable.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.predefined_roles": {
    "description": "Member of predefined roles beyond the minimal grants: {labels}.",
    "engines": [
      "postgres"
    ]
  },
  "privilege.read_beyond_discovery": {
    "description": "{count} read action(s) beyond find and listCollections (for example changeStream, which streams every future write, dbHash or listIndexes).",
    "engines": [
      "mongodb"
    ]
  },
  "privilege.registry_writable": {
    "description": "{count} CAS service registry file(s) or directories writable by the agent's account (directly, through its groups or an ACL, or through a parent directory), so the registry is not read from them: the agent must only read service definitions, since an account that can write them could change what CAS releases to whom.",
    "engines": [
      "cas"
    ]
  },
  "privilege.role_attributes": {
    "description": "Role attributes beyond the minimal grants: {labels}.",
    "engines": [
      "postgres"
    ]
  },
  "privilege.roles_not_evaluated": {
    "description": "{count} granted role(s) whose privileges are not evaluated.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.system_collections": {
    "description": "Access to system collections or to the admin, local or config databases: credentials, the oplog, other users' profiled queries or stored JavaScript may be readable.",
    "engines": [
      "mongodb"
    ]
  },
  "privilege.system_database_select": {
    "description": "SELECT on the mysql or sys system database.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.ticket_credentials_readable": {
    "description": "The agent's account can read credential columns of a CAS ticket registry or audit trail (ticket ids, bodies, principals, attributes, AUD_RESOURCE, AUD_HEADERS), directly, through a role or PUBLIC, or through a schema- or database-wide grant: grant SELECT on the metadata columns only. The agent never reads them.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb"
    ]
  },
  "privilege.write_actions": {
    "description": "{count} write or administration action(s) (for example insert, update, remove, drop, index, user or role management).",
    "engines": [
      "mongodb"
    ]
  },
  "privilege.write_not_evaluated": {
    "description": "Write access of the service DN is not evaluated: OpenLDAP shows a read-only account neither its access control rules nor its effective rights. Check olcAccess (docs/05-security.md).",
    "engines": [
      "openldap"
    ]
  },
  "privilege.write_on_relations": {
    "description": "Write privilege on {count} relation(s).",
    "engines": [
      "postgres"
    ]
  },
  "security.audit_headers_logged": {
    "description": "CAS audit records carry request headers (cas.audit.engine.http-request-headers), so the audit log holds cookies, including the ticket-granting cookie: remove headers from the audited fields. The agent skips them.",
    "engines": [
      "cas"
    ]
  },
  "security.client_secrets_in_clear": {
    "description": "{count} CAS service definition(s) with an OAuth or OIDC client secret in clear: encrypt them. The agent never samples, masks nor fingerprints a client secret.",
    "engines": [
      "cas"
    ]
  },
  "security.init_connect": {
    "description": "init_connect is set: SQL runs at every login of the agent's account.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "security.login_event_trigger": {
    "description": "An enabled login event trigger runs user code at every connection of the agent.",
    "engines": [
      "postgres"
    ]
  },
  "security.ticket_registry_unencrypted": {
    "description": "{count} CAS ticket(s) stored without ticket registry encryption (crypto.enabled false): ticket ids and principals are in clear in the table or collection. The agent read only the ticket types and counts.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb"
    ]
  },
  "security.tls_disabled": {
    "description": "TLS disabled on a network connection (tls: disable_insecure): traffic in clear, read-only not guaranteed.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb",
      "mongodb"
    ]
  }
} as const;
