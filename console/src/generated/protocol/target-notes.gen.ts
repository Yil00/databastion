// GENERATED FILE, DO NOT EDIT. Source: shared/protocol/target-notes.json.
// Regenerate with `pnpm protocol:generate` (from console/).

/** Registered `TargetNote` codes: the phrase catalog (`{count}` and `{labels}` placeholders) and engines. */
export const TARGET_NOTE_REGISTRY = {
  "audit.audit_log_plugin_not_read": {
    "description": "The audit_log plugin is active, but Full needs the agent to read its log file (not configured yet).",
    "engines": [
      "mysql"
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
  "audit.log_not_readable": {
    "description": "The audit log file configured in agent.yaml is not readable by the agent.",
    "engines": [
      "postgres"
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
  "audit.pgaudit_read_class_missing": {
    "description": "pgaudit.log does not include the read class.",
    "engines": [
      "postgres"
    ]
  },
  "audit.records_dropped_severity": {
    "description": "{count} pgaudit record(s) dropped in the last 24 h: their severity differs from pgaudit.log_level.",
    "engines": [
      "postgres"
    ]
  },
  "audit.server_audit_not_read": {
    "description": "server_audit is active ({labels}: logging_on / logging_off, file_output / non_file_output), but Full needs the agent to read its log file (not configured yet).",
    "engines": [
      "mysql",
      "mariadb"
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
      "mariadb"
    ]
  },
  "check.timed_out": {
    "description": "check() did not finish within its time bound.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb"
    ]
  },
  "coverage.other_engine_tables": {
    "description": "{count} table(s) with a storage engine outside the local-data allow-list, not sampled.",
    "engines": [
      "mysql",
      "mariadb"
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
  "coverage.views_not_sampled": {
    "description": "{count} view(s) not sampled (their base tables are).",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.beyond_select": {
    "description": "Privileges beyond SELECT on databases, tables or columns: {labels}.",
    "engines": [
      "mysql",
      "mariadb"
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
    "description": "Global privileges other than SELECT and USAGE: {labels}.",
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
    "description": "Privileges not evaluated: the account name could not be matched.",
    "engines": [
      "mysql",
      "mariadb"
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
  "privilege.predefined_roles": {
    "description": "Member of predefined roles beyond the minimal grants: {labels}.",
    "engines": [
      "postgres"
    ]
  },
  "privilege.role_attributes": {
    "description": "Role attributes beyond the minimal grants: {labels}.",
    "engines": [
      "postgres"
    ]
  },
  "privilege.roles_not_evaluated": {
    "description": "Granted {count} role(s), whose privileges are not evaluated.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.system_database_select": {
    "description": "SELECT on the mysql or sys system database.",
    "engines": [
      "mysql",
      "mariadb"
    ]
  },
  "privilege.write_on_relations": {
    "description": "Write privilege on {count} relation(s).",
    "engines": [
      "postgres"
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
  "security.tls_disabled": {
    "description": "TLS disabled on a network connection (tls: disable_insecure): traffic in clear, read-only not guaranteed.",
    "engines": [
      "postgres",
      "mysql",
      "mariadb"
    ]
  }
} as const;
