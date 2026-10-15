//! Target notes (`TargetStatus.notes`, ADR-0015, ADR-0022).
//!
//! A note explains a target's status from `check()`: why the audit level
//! is degraded, what Discovery does not cover, over-privilege of the
//! agent's account, an insecure setting. It is a **closed** code
//! ([`NoteCode`], registered in `shared/protocol/target-notes.json`) with
//! an optional count and closed labels ([`NoteLabel`], the contract
//! `TargetNoteLabel` enum): no field can carry free text, so a note never
//! carries a sampled value, a credential, a host name, a query or a driver
//! message (I2, I3).
//!
//! Connectors build notes with these types only; the core converts them to
//! the protocol type and sends them only when the console's latest
//! heartbeat response listed `target_status.notes` (ADR-0022,
//! `capabilities`).

use databastion_protocol::TargetNoteLabel;

/// Contract `TargetStatus.notes.maxItems`.
pub(crate) const MAX_NOTES: usize = 16;
/// Contract `TargetNote.labels.maxItems`.
const MAX_LABELS: usize = 16;

/// Labels that matter most, in decreasing severity: kept first when a note
/// has more than [`MAX_LABELS`] labels to send, so that e.g. `super` or
/// `file` is never cut from a long privilege list. Any label not listed
/// ranks after them (in enum order), and `other` last. The ranking applies
/// to the labels **as sent**, after negotiation ([`to_protocol`]): a label
/// the console has not negotiated is `other` by then, so it never takes the
/// place of one it can receive.
const SEVERITY: &[TargetNoteLabel] = {
    use TargetNoteLabel as L;
    &[
        // Microsoft SQL Server refusal list (ADR-0051 decision 4): the
        // password_hash probe and the rights that own the server or a
        // database first, so a long refusal never loses them.
        L::PasswordHashProbe,
        L::Sysadmin,
        L::ControlServer,
        L::DbOwner,
        L::Control,
        L::Securityadmin,
        L::MsLoginManager,
        L::ImpersonateAnyLogin,
        L::Impersonate,
        L::AlterAnyLogin,
        L::AlterAnyServerRole,
        L::AlterAnyServerAudit,
        L::AlterAnyDatabaseAudit,
        L::ViewAnyCryptographicallySecuredDefinition,
        L::AlterAnyEventSession,
        L::AlterAnyDatabaseEventSession,
        L::CreateAnyDatabaseEventSession,
        L::DropAnyDatabaseEventSession,
        L::TakeOwnership,
        // PostgreSQL role attributes and predefined roles.
        L::Superuser,
        L::Bypassrls,
        L::Createrole,
        L::Replication,
        L::PgExecuteServerProgram,
        L::PgWriteServerFiles,
        L::PgReadServerFiles,
        L::PgWriteAllData,
        L::PgReadAllData,
        L::Createdb,
        L::PgSignalBackend,
        L::PgCreateSubscription,
        L::PgDatabaseOwner,
        L::PgMaintain,
        // MySQL / MariaDB privileges.
        L::Super,
        L::File,
        L::Process,
        L::Shutdown,
        L::CreateUser,
        L::Reload,
        L::SystemUser,
        L::SetUserId,
        L::SetAnyDefiner,
        L::SetUser,
        L::ConnectionAdmin,
        L::SystemVariablesAdmin,
        L::RoleAdmin,
        L::CreateRole,
        L::DropRole,
        L::AuditAdmin,
        L::AuditAbortExempt,
        L::EncryptionKeyAdmin,
        L::FirewallAdmin,
        L::BinlogAdmin,
        L::BinlogReplay,
        L::ReplicationSlaveAdmin,
        L::ReplicationMasterAdmin,
        L::FederatedAdmin,
        L::BackupAdmin,
        L::CloneAdmin,
        L::Execute,
        L::CreateRoutine,
        L::AlterRoutine,
        L::Trigger,
        L::Event,
        L::Drop,
        L::Delete,
        L::DeleteHistory,
        L::Update,
        L::Insert,
        L::Alter,
        L::Create,
        L::Index,
        L::References,
        L::LockTables,
        L::ReplicationSlave,
        L::ReplicationClient,
        L::ShowDatabases,
    ]
};

/// Truncation rank of a label: its place in [`SEVERITY`], then any other
/// label, `other` last.
fn severity_rank(label: TargetNoteLabel) -> usize {
    if label == TargetNoteLabel::Other {
        return usize::MAX;
    }
    SEVERITY
        .iter()
        .position(|l| *l == label)
        .unwrap_or(SEVERITY.len())
}

/// Closed target-note code. Each value is registered in
/// `shared/protocol/target-notes.json` (checked both ways by
/// `tests/contract_target_notes.rs`). A code is never built with `format!`
/// nor from engine text: add a variant (and a registry entry) instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NoteCode {
    /// `audit.accesslog_not_readable`.
    AuditAccesslogNotReadable,
    /// `audit.audit_log_filter_not_read`.
    AuditAuditLogFilterNotRead,
    /// `audit.audit_log_plugin_not_read`.
    AuditAuditLogPluginNotRead,
    /// `audit.auditlog_on_community`.
    AuditAuditlogOnCommunity,
    /// `audit.auth_failures_not_seen`.
    AuditAuthFailuresNotSeen,
    /// `audit.auth_records_not_seen`.
    AuditAuthRecordsNotSeen,
    /// `audit.authcheck_success_pending`.
    AuditAuthcheckSuccessPending,
    /// `audit.digest_consumer_disabled`.
    AuditDigestConsumerDisabled,
    /// `audit.failed_operations_not_logged`.
    AuditFailedOperationsNotLogged,
    /// `audit.full_pending_first_record`.
    AuditFullPendingFirstRecord,
    /// `audit.general_log_enabled`.
    AuditGeneralLogEnabled,
    /// `audit.history_long_consumer_disabled`.
    AuditHistoryLongConsumerDisabled,
    /// `audit.history_not_readable`.
    AuditHistoryNotReadable,
    /// `audit.limited_pending_first_record`.
    AuditLimitedPendingFirstRecord,
    /// `audit.log_format_unsupported`.
    AuditLogFormatUnsupported,
    /// `audit.log_not_readable`.
    AuditLogNotReadable,
    /// `audit.log_plugin_mismatch`.
    AuditLogPluginMismatch,
    /// `audit.log_without_row_counts`.
    AuditLogWithoutRowCounts,
    /// `audit.partial_pending_first_record`.
    AuditPartialPendingFirstRecord,
    /// `audit.performance_schema_not_readable`.
    AuditPerformanceSchemaNotReadable,
    /// `audit.pgaudit_log_not_configured`.
    AuditPgauditLogNotConfigured,
    /// `audit.pgaudit_not_loaded`.
    AuditPgauditNotLoaded,
    /// `audit.pgaudit_read_class_missing`.
    AuditPgauditReadClassMissing,
    /// `audit.reads_not_logged`.
    AuditReadsNotLogged,
    /// `audit.records_dropped`.
    AuditRecordsDropped,
    /// `audit.records_dropped_severity`.
    AuditRecordsDroppedSeverity,
    /// `audit.server_audit_not_read`.
    AuditServerAuditNotRead,
    /// `audit.service_ticket_records_not_seen`.
    AuditServiceTicketRecordsNotSeen,
    /// `audit.slow_operations_only`.
    AuditSlowOperationsOnly,
    /// `audit.source_not_configured`.
    AuditSourceNotConfigured,
    /// `audit.statement_consumers_disabled`.
    AuditStatementConsumersDisabled,
    /// `audit.statement_text_limit_low`.
    AuditStatementTextLimitLow,
    /// `audit.stream_not_available`.
    AuditStreamNotAvailable,
    /// `audit.stream_stopped`.
    AuditStreamStopped,
    /// `check.server_is_mariadb`.
    CheckServerIsMariadb,
    /// `check.server_is_mysql`.
    CheckServerIsMysql,
    /// `check.stage_failed`.
    CheckStageFailed,
    /// `check.timed_out`.
    CheckTimedOut,
    /// `coverage.cas_guard_tripped`.
    CoverageCasGuardTripped,
    /// `coverage.other_engine_tables`.
    CoverageOtherEngineTables,
    /// `coverage.registry_files_skipped`.
    CoverageRegistryFilesSkipped,
    /// `coverage.relations_rls_skipped`.
    CoverageRelationsRlsSkipped,
    /// `coverage.relations_without_select`.
    CoverageRelationsWithoutSelect,
    /// `coverage.remote_engine_tables`.
    CoverageRemoteEngineTables,
    /// `coverage.schemas_without_usage`.
    CoverageSchemasWithoutUsage,
    /// `coverage.timeseries_not_readable`.
    CoverageTimeseriesNotReadable,
    /// `coverage.views_not_sampled`.
    CoverageViewsNotSampled,
    /// `privilege.accesslog_without_audit`.
    PrivilegeAccesslogWithoutAudit,
    /// `privilege.any_database`.
    PrivilegeAnyDatabase,
    /// `privilege.beyond_select`.
    PrivilegeBeyondSelect,
    /// `privilege.cluster_actions`.
    PrivilegeClusterActions,
    /// `privilege.config_readable`.
    PrivilegeConfigReadable,
    /// `privilege.extended_variant`.
    PrivilegeExtendedVariant,
    /// `privilege.global_privileges`.
    PrivilegeGlobalPrivileges,
    /// `privilege.global_select`.
    PrivilegeGlobalSelect,
    /// `privilege.grant_option`.
    PrivilegeGrantOption,
    /// `privilege.not_evaluated`.
    PrivilegeNotEvaluated,
    /// `privilege.other_roles`.
    PrivilegeOtherRoles,
    /// `privilege.owner_of_objects`.
    PrivilegeOwnerOfObjects,
    /// `privilege.password_attributes_readable`.
    PrivilegePasswordAttributesReadable,
    /// `privilege.performance_schema_unused`.
    PrivilegePerformanceSchemaUnused,
    /// `privilege.performance_schema_without_audit`.
    PrivilegePerformanceSchemaWithoutAudit,
    /// `privilege.predefined_roles`.
    PrivilegePredefinedRoles,
    /// `privilege.read_beyond_discovery`.
    PrivilegeReadBeyondDiscovery,
    /// `privilege.registry_writable`.
    PrivilegeRegistryWritable,
    /// `privilege.role_attributes`.
    PrivilegeRoleAttributes,
    /// `privilege.roles_not_evaluated`.
    PrivilegeRolesNotEvaluated,
    /// `privilege.system_collections`.
    PrivilegeSystemCollections,
    /// `privilege.system_database_select`.
    PrivilegeSystemDatabaseSelect,
    /// `privilege.ticket_credentials_readable`.
    PrivilegeTicketCredentialsReadable,
    /// `privilege.write_actions`.
    PrivilegeWriteActions,
    /// `privilege.write_not_evaluated`.
    PrivilegeWriteNotEvaluated,
    /// `privilege.write_on_relations`.
    PrivilegeWriteOnRelations,
    /// `security.audit_headers_logged`.
    SecurityAuditHeadersLogged,
    /// `security.client_secrets_in_clear`.
    SecurityClientSecretsInClear,
    /// `security.init_connect`.
    SecurityInitConnect,
    /// `security.login_event_trigger`.
    SecurityLoginEventTrigger,
    /// `security.ticket_registry_unencrypted`.
    SecurityTicketRegistryUnencrypted,
    /// `security.tls_disabled`.
    SecurityTlsDisabled,
    /// `security.default_user_nopass`.
    SecurityDefaultUserNopass,
    /// `privilege.admin_commands`.
    PrivilegeAdminCommands,
    /// `privilege.scripting`.
    PrivilegeScripting,
    /// `privilege.pubsub_channels`.
    PrivilegePubsubChannels,
    /// `privilege.declared_keys_not_readable`.
    PrivilegeDeclaredKeysNotReadable,
    /// `coverage.cluster_node_only`.
    CoverageClusterNodeOnly,
    /// `coverage.module_types_not_sampled`.
    CoverageModuleTypesNotSampled,
    /// `audit.acl_log_only`.
    AuditAclLogOnly,
    /// `check.server_is_valkey`.
    CheckServerIsValkey,
    /// `check.server_is_redis`.
    CheckServerIsRedis,
    /// `audit.audit_changes_not_audited` (Microsoft SQL Server, ADR-0051).
    AuditAuditChangesNotAudited,
    /// `audit.failed_logins_not_audited` (Microsoft SQL Server, ADR-0051).
    AuditFailedLoginsNotAudited,
    /// `audit.server_audit_filtered` (Microsoft SQL Server, ADR-0051).
    AuditServerAuditFiltered,
    /// `audit.sqlserver_audit_needs_control_server` (Microsoft SQL Server, ADR-0051).
    AuditSqlserverAuditNeedsControlServer,
    /// `audit.xe_causality_off` (Microsoft SQL Server, ADR-0051).
    AuditXeCausalityOff,
    /// `audit.xe_events_missing` (Microsoft SQL Server, ADR-0051).
    AuditXeEventsMissing,
    /// `audit.xe_session_filtered` (Microsoft SQL Server, ADR-0051).
    AuditXeSessionFiltered,
    /// `coverage.computed_columns_not_sampled` (Microsoft SQL Server, ADR-0051).
    CoverageComputedColumnsNotSampled,
    /// `coverage.encrypted_columns` (Microsoft SQL Server, ADR-0051).
    CoverageEncryptedColumns,
    /// `coverage.masked_columns` (Microsoft SQL Server, ADR-0051).
    CoverageMaskedColumns,
    /// `coverage.rls_not_verifiable` (Microsoft SQL Server, ADR-0051).
    CoverageRlsNotVerifiable,
    /// `privilege.audit_grant_without_audit` (Microsoft SQL Server, ADR-0051).
    PrivilegeAuditGrantWithoutAudit,
    /// `privilege.database_roles` (Microsoft SQL Server, ADR-0051).
    PrivilegeDatabaseRoles,
    /// `privilege.refused` (Microsoft SQL Server, ADR-0051).
    PrivilegeRefused,
    /// `privilege.server_roles` (Microsoft SQL Server, ADR-0051).
    PrivilegeServerRoles,
}

impl NoteCode {
    /// Every code, in registry order.
    pub const ALL: &'static [Self] = &[
        Self::AuditAccesslogNotReadable,
        Self::AuditAuditLogFilterNotRead,
        Self::AuditAuditLogPluginNotRead,
        Self::AuditAuditlogOnCommunity,
        Self::AuditAuthFailuresNotSeen,
        Self::AuditAuthRecordsNotSeen,
        Self::AuditAuthcheckSuccessPending,
        Self::AuditDigestConsumerDisabled,
        Self::AuditFailedOperationsNotLogged,
        Self::AuditFullPendingFirstRecord,
        Self::AuditGeneralLogEnabled,
        Self::AuditHistoryLongConsumerDisabled,
        Self::AuditHistoryNotReadable,
        Self::AuditLimitedPendingFirstRecord,
        Self::AuditLogFormatUnsupported,
        Self::AuditLogNotReadable,
        Self::AuditLogPluginMismatch,
        Self::AuditLogWithoutRowCounts,
        Self::AuditPartialPendingFirstRecord,
        Self::AuditPerformanceSchemaNotReadable,
        Self::AuditPgauditLogNotConfigured,
        Self::AuditPgauditNotLoaded,
        Self::AuditPgauditReadClassMissing,
        Self::AuditReadsNotLogged,
        Self::AuditRecordsDropped,
        Self::AuditRecordsDroppedSeverity,
        Self::AuditServerAuditNotRead,
        Self::AuditServiceTicketRecordsNotSeen,
        Self::AuditSlowOperationsOnly,
        Self::AuditSourceNotConfigured,
        Self::AuditStatementConsumersDisabled,
        Self::AuditStatementTextLimitLow,
        Self::AuditStreamNotAvailable,
        Self::AuditStreamStopped,
        Self::CheckServerIsMariadb,
        Self::CheckServerIsMysql,
        Self::CheckStageFailed,
        Self::CheckTimedOut,
        Self::CoverageCasGuardTripped,
        Self::CoverageOtherEngineTables,
        Self::CoverageRegistryFilesSkipped,
        Self::CoverageRelationsRlsSkipped,
        Self::CoverageRelationsWithoutSelect,
        Self::CoverageRemoteEngineTables,
        Self::CoverageSchemasWithoutUsage,
        Self::CoverageTimeseriesNotReadable,
        Self::CoverageViewsNotSampled,
        Self::PrivilegeAccesslogWithoutAudit,
        Self::PrivilegeAnyDatabase,
        Self::PrivilegeBeyondSelect,
        Self::PrivilegeClusterActions,
        Self::PrivilegeConfigReadable,
        Self::PrivilegeExtendedVariant,
        Self::PrivilegeGlobalPrivileges,
        Self::PrivilegeGlobalSelect,
        Self::PrivilegeGrantOption,
        Self::PrivilegeNotEvaluated,
        Self::PrivilegeOtherRoles,
        Self::PrivilegeOwnerOfObjects,
        Self::PrivilegePasswordAttributesReadable,
        Self::PrivilegePerformanceSchemaUnused,
        Self::PrivilegePerformanceSchemaWithoutAudit,
        Self::PrivilegePredefinedRoles,
        Self::PrivilegeReadBeyondDiscovery,
        Self::PrivilegeRegistryWritable,
        Self::PrivilegeRoleAttributes,
        Self::PrivilegeRolesNotEvaluated,
        Self::PrivilegeSystemCollections,
        Self::PrivilegeSystemDatabaseSelect,
        Self::PrivilegeTicketCredentialsReadable,
        Self::PrivilegeWriteActions,
        Self::PrivilegeWriteNotEvaluated,
        Self::PrivilegeWriteOnRelations,
        Self::SecurityAuditHeadersLogged,
        Self::SecurityClientSecretsInClear,
        Self::SecurityInitConnect,
        Self::SecurityLoginEventTrigger,
        Self::SecurityTicketRegistryUnencrypted,
        Self::SecurityTlsDisabled,
        Self::SecurityDefaultUserNopass,
        Self::PrivilegeAdminCommands,
        Self::PrivilegeScripting,
        Self::PrivilegePubsubChannels,
        Self::PrivilegeDeclaredKeysNotReadable,
        Self::CoverageClusterNodeOnly,
        Self::CoverageModuleTypesNotSampled,
        Self::AuditAclLogOnly,
        Self::CheckServerIsValkey,
        Self::CheckServerIsRedis,
        Self::AuditAuditChangesNotAudited,
        Self::AuditFailedLoginsNotAudited,
        Self::AuditServerAuditFiltered,
        Self::AuditSqlserverAuditNeedsControlServer,
        Self::AuditXeCausalityOff,
        Self::AuditXeEventsMissing,
        Self::AuditXeSessionFiltered,
        Self::CoverageComputedColumnsNotSampled,
        Self::CoverageEncryptedColumns,
        Self::CoverageMaskedColumns,
        Self::CoverageRlsNotVerifiable,
        Self::PrivilegeAuditGrantWithoutAudit,
        Self::PrivilegeDatabaseRoles,
        Self::PrivilegeRefused,
        Self::PrivilegeServerRoles,
    ];

    /// The registered code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditAccesslogNotReadable => "audit.accesslog_not_readable",
            Self::AuditAuditLogFilterNotRead => "audit.audit_log_filter_not_read",
            Self::AuditAuditLogPluginNotRead => "audit.audit_log_plugin_not_read",
            Self::AuditAuditlogOnCommunity => "audit.auditlog_on_community",
            Self::AuditAuthFailuresNotSeen => "audit.auth_failures_not_seen",
            Self::AuditAuthRecordsNotSeen => "audit.auth_records_not_seen",
            Self::AuditAuthcheckSuccessPending => "audit.authcheck_success_pending",
            Self::AuditDigestConsumerDisabled => "audit.digest_consumer_disabled",
            Self::AuditFailedOperationsNotLogged => "audit.failed_operations_not_logged",
            Self::AuditFullPendingFirstRecord => "audit.full_pending_first_record",
            Self::AuditGeneralLogEnabled => "audit.general_log_enabled",
            Self::AuditHistoryLongConsumerDisabled => "audit.history_long_consumer_disabled",
            Self::AuditHistoryNotReadable => "audit.history_not_readable",
            Self::AuditLimitedPendingFirstRecord => "audit.limited_pending_first_record",
            Self::AuditLogFormatUnsupported => "audit.log_format_unsupported",
            Self::AuditLogNotReadable => "audit.log_not_readable",
            Self::AuditLogPluginMismatch => "audit.log_plugin_mismatch",
            Self::AuditLogWithoutRowCounts => "audit.log_without_row_counts",
            Self::AuditPartialPendingFirstRecord => "audit.partial_pending_first_record",
            Self::AuditPerformanceSchemaNotReadable => "audit.performance_schema_not_readable",
            Self::AuditPgauditLogNotConfigured => "audit.pgaudit_log_not_configured",
            Self::AuditPgauditNotLoaded => "audit.pgaudit_not_loaded",
            Self::AuditPgauditReadClassMissing => "audit.pgaudit_read_class_missing",
            Self::AuditReadsNotLogged => "audit.reads_not_logged",
            Self::AuditRecordsDropped => "audit.records_dropped",
            Self::AuditRecordsDroppedSeverity => "audit.records_dropped_severity",
            Self::AuditServerAuditNotRead => "audit.server_audit_not_read",
            Self::AuditServiceTicketRecordsNotSeen => "audit.service_ticket_records_not_seen",
            Self::AuditSlowOperationsOnly => "audit.slow_operations_only",
            Self::AuditSourceNotConfigured => "audit.source_not_configured",
            Self::AuditStatementConsumersDisabled => "audit.statement_consumers_disabled",
            Self::AuditStatementTextLimitLow => "audit.statement_text_limit_low",
            Self::AuditStreamNotAvailable => "audit.stream_not_available",
            Self::AuditStreamStopped => "audit.stream_stopped",
            Self::CheckServerIsMariadb => "check.server_is_mariadb",
            Self::CheckServerIsMysql => "check.server_is_mysql",
            Self::CheckStageFailed => "check.stage_failed",
            Self::CheckTimedOut => "check.timed_out",
            Self::CoverageCasGuardTripped => "coverage.cas_guard_tripped",
            Self::CoverageOtherEngineTables => "coverage.other_engine_tables",
            Self::CoverageRegistryFilesSkipped => "coverage.registry_files_skipped",
            Self::CoverageRelationsRlsSkipped => "coverage.relations_rls_skipped",
            Self::CoverageRelationsWithoutSelect => "coverage.relations_without_select",
            Self::CoverageRemoteEngineTables => "coverage.remote_engine_tables",
            Self::CoverageSchemasWithoutUsage => "coverage.schemas_without_usage",
            Self::CoverageTimeseriesNotReadable => "coverage.timeseries_not_readable",
            Self::CoverageViewsNotSampled => "coverage.views_not_sampled",
            Self::PrivilegeAccesslogWithoutAudit => "privilege.accesslog_without_audit",
            Self::PrivilegeAnyDatabase => "privilege.any_database",
            Self::PrivilegeBeyondSelect => "privilege.beyond_select",
            Self::PrivilegeClusterActions => "privilege.cluster_actions",
            Self::PrivilegeConfigReadable => "privilege.config_readable",
            Self::PrivilegeExtendedVariant => "privilege.extended_variant",
            Self::PrivilegeGlobalPrivileges => "privilege.global_privileges",
            Self::PrivilegeGlobalSelect => "privilege.global_select",
            Self::PrivilegeGrantOption => "privilege.grant_option",
            Self::PrivilegeNotEvaluated => "privilege.not_evaluated",
            Self::PrivilegeOtherRoles => "privilege.other_roles",
            Self::PrivilegeOwnerOfObjects => "privilege.owner_of_objects",
            Self::PrivilegePasswordAttributesReadable => "privilege.password_attributes_readable",
            Self::PrivilegePerformanceSchemaUnused => "privilege.performance_schema_unused",
            Self::PrivilegePerformanceSchemaWithoutAudit => {
                "privilege.performance_schema_without_audit"
            }
            Self::PrivilegePredefinedRoles => "privilege.predefined_roles",
            Self::PrivilegeReadBeyondDiscovery => "privilege.read_beyond_discovery",
            Self::PrivilegeRegistryWritable => "privilege.registry_writable",
            Self::PrivilegeRoleAttributes => "privilege.role_attributes",
            Self::PrivilegeRolesNotEvaluated => "privilege.roles_not_evaluated",
            Self::PrivilegeSystemCollections => "privilege.system_collections",
            Self::PrivilegeSystemDatabaseSelect => "privilege.system_database_select",
            Self::PrivilegeTicketCredentialsReadable => "privilege.ticket_credentials_readable",
            Self::PrivilegeWriteActions => "privilege.write_actions",
            Self::PrivilegeWriteNotEvaluated => "privilege.write_not_evaluated",
            Self::PrivilegeWriteOnRelations => "privilege.write_on_relations",
            Self::SecurityAuditHeadersLogged => "security.audit_headers_logged",
            Self::SecurityClientSecretsInClear => "security.client_secrets_in_clear",
            Self::SecurityInitConnect => "security.init_connect",
            Self::SecurityLoginEventTrigger => "security.login_event_trigger",
            Self::SecurityTicketRegistryUnencrypted => "security.ticket_registry_unencrypted",
            Self::SecurityTlsDisabled => "security.tls_disabled",
            Self::SecurityDefaultUserNopass => "security.default_user_nopass",
            Self::PrivilegeAdminCommands => "privilege.admin_commands",
            Self::PrivilegeScripting => "privilege.scripting",
            Self::PrivilegePubsubChannels => "privilege.pubsub_channels",
            Self::PrivilegeDeclaredKeysNotReadable => "privilege.declared_keys_not_readable",
            Self::CoverageClusterNodeOnly => "coverage.cluster_node_only",
            Self::CoverageModuleTypesNotSampled => "coverage.module_types_not_sampled",
            Self::AuditAclLogOnly => "audit.acl_log_only",
            Self::CheckServerIsValkey => "check.server_is_valkey",
            Self::CheckServerIsRedis => "check.server_is_redis",
            Self::AuditAuditChangesNotAudited => "audit.audit_changes_not_audited",
            Self::AuditFailedLoginsNotAudited => "audit.failed_logins_not_audited",
            Self::AuditServerAuditFiltered => "audit.server_audit_filtered",
            Self::AuditSqlserverAuditNeedsControlServer => {
                "audit.sqlserver_audit_needs_control_server"
            }
            Self::AuditXeCausalityOff => "audit.xe_causality_off",
            Self::AuditXeEventsMissing => "audit.xe_events_missing",
            Self::AuditXeSessionFiltered => "audit.xe_session_filtered",
            Self::CoverageComputedColumnsNotSampled => "coverage.computed_columns_not_sampled",
            Self::CoverageEncryptedColumns => "coverage.encrypted_columns",
            Self::CoverageMaskedColumns => "coverage.masked_columns",
            Self::CoverageRlsNotVerifiable => "coverage.rls_not_verifiable",
            Self::PrivilegeAuditGrantWithoutAudit => "privilege.audit_grant_without_audit",
            Self::PrivilegeDatabaseRoles => "privilege.database_roles",
            Self::PrivilegeRefused => "privilege.refused",
            Self::PrivilegeServerRoles => "privilege.server_roles",
        }
    }

    /// Order in which notes are kept when a target has more than the
    /// contract allows: insecure settings first, then the check itself,
    /// privileges, audit and coverage.
    fn rank(self) -> u8 {
        let code = self.as_str();
        if code.starts_with("security.") {
            0
        } else if code.starts_with("check.") {
            1
        } else if code.starts_with("privilege.") {
            2
        } else if code.starts_with("audit.") {
            3
        } else {
            4
        }
    }
}

/// The `TargetNoteLabel` values of the revision
/// `target_status.note_labels.2026_10` (Microsoft SQL Server, ADR-0051
/// decision 4). Until the agent negotiates that token (with the SQL Server
/// connector), [`NoteLabel::parse`] maps them to `other`: a console built
/// before the revision rejects them (ADR-0022 decision 4), and a MySQL /
/// MariaDB server could name a dynamic privilege after one of them.
pub(crate) const LABELS_REVISION_2026_10: &[&str] = &[
    "sysadmin",
    "securityadmin",
    "serveradmin",
    "setupadmin",
    "processadmin",
    "diskadmin",
    "dbcreator",
    "bulkadmin",
    "ms_database_connector",
    "ms_database_manager",
    "ms_definition_reader",
    "ms_login_manager",
    "ms_performance_definition_reader",
    "ms_security_definition_reader",
    "ms_server_performance_state_reader",
    "ms_server_security_state_reader",
    "ms_server_state_manager",
    "ms_server_state_reader",
    "db_owner",
    "db_securityadmin",
    "db_accessadmin",
    "db_backupoperator",
    "db_ddladmin",
    "db_datawriter",
    "db_datareader",
    "db_denydatareader",
    "db_denydatawriter",
    "control_server",
    "alter_any_server_audit",
    "alter_any_event_session",
    "alter_any_event_session_enable",
    "alter_any_event_session_disable",
    "alter_any_event_session_add_event",
    "alter_any_event_session_drop_event",
    "alter_any_event_session_add_target",
    "alter_any_event_session_drop_target",
    "alter_any_event_session_option",
    "create_any_event_session",
    "drop_any_event_session",
    "alter_any_login",
    "alter_any_server_role",
    "impersonate_any_login",
    "view_any_cryptographically_secured_definition",
    "view_any_definition",
    "view_any_security_definition",
    "administer_bulk_operations",
    "alter_any_linked_server",
    "alter_trace",
    "view_server_state",
    "view_server_performance_state",
    "view_server_security_audit",
    "view_server_security_state",
    "control",
    "impersonate",
    "take_ownership",
    "alter_any_database_audit",
    "view_database_security_audit",
    "unmask",
    "view_definition",
    "view_database_state",
    "showplan",
    "password_hash_probe",
];

/// The `TargetNoteLabel` values of the revision
/// `target_status.note_labels.2026_10_b` (Microsoft SQL Server, ADR-0051
/// refinement of 2026-10-14, items 5 to 7): the database-scoped
/// event-session permissions of the refusal list, the other permissions
/// the connector judges by name, and the `check()` reads it names with
/// `privilege.not_evaluated`. Negotiated on their own token, like
/// [`LABELS_REVISION_2026_10`]: `other` until the console lists it.
pub(crate) const LABELS_REVISION_2026_10_B: &[&str] = &[
    "alter_any_database_event_session",
    "alter_any_database_event_session_enable",
    "alter_any_database_event_session_disable",
    "alter_any_database_event_session_add_event",
    "alter_any_database_event_session_drop_event",
    "alter_any_database_event_session_add_target",
    "alter_any_database_event_session_drop_target",
    "alter_any_database_event_session_option",
    "create_any_database_event_session",
    "drop_any_database_event_session",
    "view_any_performance_definition",
    "view_security_definition",
    "view_performance_definition",
    "view_database_security_state",
    "view_database_performance_state",
    "view_any_column_encryption_key_definition",
    "view_any_column_master_key_definition",
    "logon_trigger_probe",
    "refusal_list_probe",
    "cas_store_guard_probe",
];

/// The `target_status.note_labels.<revision>` tokens the console listed in
/// its latest heartbeat response (ADR-0022 decision 4). Each revision is
/// negotiated on its own: a label is sent only when the token of its own
/// revision is listed, `other` otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LabelRevisions {
    /// `target_status.note_labels.2026_10` ([`LABELS_REVISION_2026_10`]).
    pub(crate) r2026_10: bool,
    /// `target_status.note_labels.2026_10_b` ([`LABELS_REVISION_2026_10_B`]).
    pub(crate) r2026_10_b: bool,
}

impl LabelRevisions {
    /// Every revision this build knows (tests).
    #[cfg(test)]
    pub(crate) const ALL: Self = Self {
        r2026_10: true,
        r2026_10_b: true,
    };

    /// Whether `value` (a contract `TargetNoteLabel` value) may be sent.
    fn allows(self, value: &str) -> bool {
        (self.r2026_10 || !LABELS_REVISION_2026_10.contains(&value))
            && (self.r2026_10_b || !LABELS_REVISION_2026_10_B.contains(&value))
    }
}

/// Whether `value` belongs to a revision after protocol 0.1.0.
fn in_a_revision(value: &str) -> bool {
    LABELS_REVISION_2026_10.contains(&value) || LABELS_REVISION_2026_10_B.contains(&value)
}

/// Closed label of a note: a value of the contract `TargetNoteLabel` enum.
/// Anything that does not map to it is `other`, so a label never carries
/// text from the engine.
///
/// New label values are a contract enum change, negotiated with a
/// `target_status.note_labels.<revision>` token (ADR-0022 decision 4). The
/// values of this build are those of protocol 0.1.0, sent without a token,
/// and those of the SQL Server revisions `2026_10`
/// ([`LABELS_REVISION_2026_10`]) and `2026_10_b`
/// ([`LABELS_REVISION_2026_10_B`]), each sent only once the console lists
/// its own token, `other` before ([`to_protocol`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoteLabel(TargetNoteLabel);

impl NoteLabel {
    /// The fallback label.
    pub const OTHER: Self = Self(TargetNoteLabel::Other);

    /// A label given as its exact contract value (lower snake case, e.g.
    /// `bypassrls`, `pg_monitor`, `logging_on`); anything else is `other`,
    /// and so are the values of the SQL Server revisions
    /// ([`LABELS_REVISION_2026_10`], [`LABELS_REVISION_2026_10_B`]), which
    /// only [`sqlserver`](Self::sqlserver) builds: a MySQL / MariaDB server
    /// could name a dynamic privilege after one of them.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        if in_a_revision(value) {
            return Self::OTHER;
        }
        value.parse::<TargetNoteLabel>().map_or(Self::OTHER, Self)
    }

    /// A MySQL / MariaDB privilege name as the server lists it (e.g.
    /// `SHOW VIEW`, `BINLOG_ADMIN`): lowercased, spaces replaced by `_`
    /// (contract rule), then [`parse`](Self::parse). Longer than 64 bytes,
    /// or with any character outside `[A-Za-z_ ]`: `other`.
    #[must_use]
    pub fn privilege(name: &str) -> Self {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'_' || b == b' ')
        {
            return Self::OTHER;
        }
        let normalized: String = name
            .chars()
            .map(|c| {
                if c == ' ' {
                    '_'
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        Self::parse(&normalized)
    }

    /// The `stage_*` label of a connector stage name (`connect`, `tls`,
    /// `auth`…, the stages of the connectors' errors); unknown: `other`.
    #[must_use]
    pub fn stage(stage: &str) -> Self {
        Self(match stage {
            "secret" => TargetNoteLabel::StageSecret,
            "tls" => TargetNoteLabel::StageTls,
            "connect" => TargetNoteLabel::StageConnect,
            "auth" => TargetNoteLabel::StageAuth,
            "session_setup" => TargetNoteLabel::StageSessionSetup,
            "begin" => TargetNoteLabel::StageBegin,
            "commit" => TargetNoteLabel::StageCommit,
            "introspection" => TargetNoteLabel::StageIntrospection,
            "columns" => TargetNoteLabel::StageColumns,
            "sample" => TargetNoteLabel::StageSample,
            "check" => TargetNoteLabel::StageCheck,
            "audit" => TargetNoteLabel::StageAudit,
            "kill" => TargetNoteLabel::StageKill,
            _ => TargetNoteLabel::Other,
        })
    }

    /// A Microsoft SQL Server label (ADR-0051 decision 4): any contract
    /// value, the revisions `target_status.note_labels.2026_10` and
    /// `2026_10_b` included (each sent as `other` until the console lists
    /// its token, see [`to_protocol`]); anything else is `other`.
    #[must_use]
    pub fn sqlserver(value: &str) -> Self {
        value.parse::<TargetNoteLabel>().map_or(Self::OTHER, Self)
    }

    /// A SQL Server permission or role name as the server lists it
    /// (`CONTROL SERVER`, `db_owner`, `##MS_LoginManager##`), mapped by the
    /// contract rule: permissions lowercased with spaces replaced by `_`;
    /// fixed roles in lower case; `##MS_Name##` as `ms_` and the name in
    /// lower snake case. Anything else (longer than 64 bytes, characters
    /// outside `[A-Za-z_ #]`, an unknown value) is `other`.
    #[must_use]
    pub fn sqlserver_name(name: &str) -> Self {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'_' || b == b' ' || b == b'#')
        {
            return Self::OTHER;
        }
        if let Some(inner) = name
            .strip_prefix("##MS_")
            .and_then(|n| n.strip_suffix("##"))
        {
            let mut out = String::from("ms");
            for c in inner.chars() {
                if c.is_ascii_uppercase() {
                    out.push('_');
                    out.push(c.to_ascii_lowercase());
                } else if c.is_ascii_lowercase() {
                    out.push(c);
                } else {
                    return Self::OTHER;
                }
            }
            return Self::sqlserver(&out);
        }
        if name.contains('#') {
            return Self::OTHER;
        }
        let normalized: String = name
            .chars()
            .map(|c| {
                if c == ' ' {
                    '_'
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        Self::sqlserver(&normalized)
    }

    /// This label as sent: a value of a revision the console did not
    /// negotiate becomes `other`.
    fn negotiated(self, revisions: LabelRevisions) -> Self {
        if revisions.allows(self.0.to_string().as_str()) {
            self
        } else {
            Self::OTHER
        }
    }

    /// Whether this is the fallback `other`.
    #[must_use]
    pub fn is_other(self) -> bool {
        self.0 == TargetNoteLabel::Other
    }

    /// The contract value.
    #[must_use]
    pub fn as_str(self) -> String {
        self.0.to_string()
    }
}

/// One note of a target's `check()`: a closed code, an optional count and
/// closed labels (at most 16, sorted and deduplicated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetNote {
    code: NoteCode,
    count: Option<u64>,
    labels: Vec<NoteLabel>,
}

impl TargetNote {
    /// A note without count or labels.
    #[must_use]
    pub const fn new(code: NoteCode) -> Self {
        Self {
            code,
            count: None,
            labels: Vec::new(),
        }
    }

    /// Sets the count the note is about.
    #[must_use]
    pub fn with_count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    /// Adds labels (sorted, deduplicated). Nothing is cut here: the cut to
    /// the contract's 16 happens when the note is sent, after negotiation
    /// ([`to_protocol`]).
    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = NoteLabel>) -> Self {
        self.labels.extend(labels);
        self.normalize_labels();
        self
    }

    /// Sorts the labels in enum order and deduplicates them. Bounded
    /// without a cut: the labels are values of the closed contract enum, so
    /// a note holds at most one of each.
    fn normalize_labels(&mut self) {
        self.labels.sort_unstable();
        self.labels.dedup();
    }

    /// The code.
    #[must_use]
    pub const fn code(&self) -> NoteCode {
        self.code
    }

    /// The count, if any.
    #[must_use]
    pub const fn count(&self) -> Option<u64> {
        self.count
    }

    /// The labels, in enum order: all of them, before negotiation and the
    /// cut to the contract's 16 ([`to_protocol`]).
    #[must_use]
    pub fn labels(&self) -> &[NoteLabel] {
        &self.labels
    }
}

/// How [`Notes`] combines the counts of two notes with the same code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountMerge {
    /// Keep the larger count (the same fact seen twice, e.g. a cluster-wide
    /// role membership seen from each database).
    Max,
    /// Add the counts (per-database facts, e.g. relations without
    /// `SELECT` in each database).
    Sum,
}

/// The notes of one `check()`, one per code: a note added with a code
/// already present is merged into it (labels united, counts combined).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notes(Vec<TargetNote>);

impl Notes {
    /// Adds `note`; the same code seen twice keeps the larger count.
    pub fn add(&mut self, note: TargetNote) {
        self.merge(note, CountMerge::Max);
    }

    /// Adds `note`, combining its count with `how` when the code is
    /// already present.
    pub fn merge(&mut self, note: TargetNote, how: CountMerge) {
        match self.0.iter_mut().find(|n| n.code == note.code) {
            None => self.0.push(note),
            Some(existing) => {
                existing.count = match (existing.count, note.count) {
                    (Some(a), Some(b)) => Some(match how {
                        CountMerge::Max => a.max(b),
                        CountMerge::Sum => a.saturating_add(b),
                    }),
                    (a, b) => a.or(b),
                };
                existing.labels.extend(note.labels);
                existing.normalize_labels();
            }
        }
    }

    /// Adds every note of `other` with [`add`](Self::add).
    pub fn extend(&mut self, other: impl IntoIterator<Item = TargetNote>) {
        for n in other {
            self.add(n);
        }
    }

    /// Whether a note with `code` is present.
    #[must_use]
    pub fn contains(&self, code: NoteCode) -> bool {
        self.0.iter().any(|n| n.code == code)
    }

    /// The notes, in the order they were first added.
    #[must_use]
    pub fn into_vec(self) -> Vec<TargetNote> {
        self.0
    }

    /// The notes, in the order they were first added.
    #[must_use]
    pub fn as_slice(&self) -> &[TargetNote] {
        &self.0
    }
}

impl IntoIterator for Notes {
    type Item = TargetNote;
    type IntoIter = std::vec::IntoIter<TargetNote>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// The labels of one note as sent: negotiated, deduplicated, the
/// [`MAX_LABELS`] most severe kept, in enum order.
fn sent_labels(labels: &[NoteLabel], revisions: LabelRevisions) -> Vec<TargetNoteLabel> {
    let mut out: Vec<TargetNoteLabel> = labels.iter().map(|l| l.negotiated(revisions).0).collect();
    out.sort_unstable_by_key(|l| (severity_rank(*l), *l));
    out.dedup();
    out.truncate(MAX_LABELS);
    out.sort_unstable();
    out
}

/// The contract `TargetStatus.notes` of a target: one note per code (the
/// first one kept), at most [`MAX_NOTES`], insecure settings, check
/// failures and privileges kept first; counts saturated at the contract
/// bound.
///
/// The labels of a revision after protocol 0.1.0
/// ([`LABELS_REVISION_2026_10`], [`LABELS_REVISION_2026_10_B`]) are sent
/// only when `revisions` holds its token (the console listed it), `other`
/// otherwise (ADR-0022 decision 4). Negotiation comes first, then the
/// ranking by [`SEVERITY`] (`other` last), then the cut to [`MAX_LABELS`]:
/// labels the console cannot receive never push out labels it can.
pub(crate) fn to_protocol(
    notes: &[TargetNote],
    revisions: LabelRevisions,
) -> Vec<databastion_protocol::TargetNote> {
    let mut kept: Vec<&TargetNote> = Vec::with_capacity(notes.len().min(MAX_NOTES));
    for n in notes {
        if !kept.iter().any(|k| k.code == n.code) {
            kept.push(n);
        }
    }
    kept.sort_by_key(|n| n.code.rank());
    kept.into_iter()
        .take(MAX_NOTES)
        .filter_map(|n| {
            Some(databastion_protocol::TargetNote {
                code: databastion_protocol::TargetNoteCode::try_from(n.code.as_str()).ok()?,
                count: n.count.map(crate::sanitize::clamped_count),
                labels: (!n.labels.is_empty()).then(|| sent_labels(&n.labels, revisions)),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn codes_are_unique_and_conform_to_the_contract_pattern() {
        let mut seen = std::collections::BTreeSet::new();
        for c in NoteCode::ALL {
            assert!(seen.insert(c.as_str()), "{} listed twice", c.as_str());
            databastion_protocol::TargetNoteCode::try_from(c.as_str()).unwrap();
        }
    }

    /// The contract `TargetNoteLabel` values of one revision: the lines
    /// after `from` and before `to` in `openapi.yaml`.
    fn contract_revision(from: &str, to: &str) -> Vec<&'static str> {
        let contract = include_str!("../../../../shared/protocol/openapi.yaml");
        let start = contract.find(from).expect("revision start marker");
        let after = &contract[start..];
        let end = after.find(to).expect("revision end marker");
        after[..end]
            .lines()
            .skip(1)
            .filter_map(|l| l.strip_prefix("        - "))
            .collect()
    }

    const REVISION_B_MARKER: &str = "        # Revision target_status.note_labels.2026_10_b (ADR-0051 refinement of 2026-10-14):\n";

    /// The labels sent for `note` with `revisions`.
    fn sent(note: &TargetNote, revisions: LabelRevisions) -> Vec<String> {
        super::to_protocol(std::slice::from_ref(note), revisions)[0]
            .labels
            .clone()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn labels_of_revision_2026_10_are_sent_as_other_until_negotiated() {
        // The list is exactly the contract values after `stage_kill`, up
        // to the next revision.
        let revision = contract_revision("        - stage_kill\n", REVISION_B_MARKER);
        assert_eq!(revision, super::LABELS_REVISION_2026_10);
        for value in super::LABELS_REVISION_2026_10 {
            assert!(value.parse::<super::TargetNoteLabel>().is_ok(), "{value}");
            assert!(super::NoteLabel::parse(value).is_other(), "{value}");
        }
        // A MySQL / MariaDB privilege named like one of them.
        assert!(super::NoteLabel::privilege("CONTROL SERVER").is_other());
        // SQL Server names keep their label in the agent, and are sent
        // only once the console lists the revision token.
        let l = super::NoteLabel::sqlserver_name("CONTROL SERVER");
        assert_eq!(l.as_str(), "control_server");
        assert_eq!(
            super::NoteLabel::sqlserver_name("##MS_LoginManager##").as_str(),
            "ms_login_manager"
        );
        assert_eq!(
            super::NoteLabel::sqlserver_name("db_owner").as_str(),
            "db_owner"
        );
        assert!(super::NoteLabel::sqlserver_name("##MS_Unknown##").is_other());
        assert!(super::NoteLabel::sqlserver_name("ALTER ANY UNKNOWN THING").is_other());
        assert_eq!(
            super::NoteLabel::sqlserver_name("SELECT").as_str(),
            "select"
        );
        let note = super::TargetNote::new(super::NoteCode::PrivilegeRefused)
            .with_labels([l, super::NoteLabel::sqlserver_name("SELECT")]);
        let none = LabelRevisions::default();
        let a = LabelRevisions {
            r2026_10: true,
            r2026_10_b: false,
        };
        let b = LabelRevisions {
            r2026_10: false,
            r2026_10_b: true,
        };
        assert_eq!(sent(&note, none), vec!["other", "select"]);
        assert_eq!(sent(&note, b), vec!["other", "select"]);
        assert_eq!(sent(&note, a), vec!["select", "control_server"]);
        assert_eq!(
            sent(&note, LabelRevisions::ALL),
            vec!["select", "control_server"]
        );
        assert!(super::NoteLabel::privilege("SHOW VIEW").as_str() == "show_view");
    }

    #[test]
    fn labels_of_revision_2026_10_b_are_sent_as_other_until_negotiated() {
        // The list is exactly the contract values of the revision, the
        // last ones of the enum.
        let revision = contract_revision(REVISION_B_MARKER, "    DetectedTarget:");
        assert_eq!(revision, super::LABELS_REVISION_2026_10_B);
        for value in super::LABELS_REVISION_2026_10_B {
            assert!(value.parse::<super::TargetNoteLabel>().is_ok(), "{value}");
            // Never built from a MySQL / MariaDB or PostgreSQL name.
            assert!(super::NoteLabel::parse(value).is_other(), "{value}");
            assert_eq!(super::NoteLabel::sqlserver(value).as_str(), *value);
        }
        assert!(
            super::LABELS_REVISION_2026_10_B
                .iter()
                .all(|v| !super::LABELS_REVISION_2026_10.contains(v)),
            "a value belongs to one revision only"
        );
        assert!(super::NoteLabel::privilege("ALTER ANY DATABASE EVENT SESSION").is_other());
        // The ten database-scoped event-session permissions (refinement
        // item 5), as SQL Server names them.
        let names = [
            "ALTER ANY DATABASE EVENT SESSION",
            "ALTER ANY DATABASE EVENT SESSION ENABLE",
            "ALTER ANY DATABASE EVENT SESSION DISABLE",
            "ALTER ANY DATABASE EVENT SESSION ADD EVENT",
            "ALTER ANY DATABASE EVENT SESSION DROP EVENT",
            "ALTER ANY DATABASE EVENT SESSION ADD TARGET",
            "ALTER ANY DATABASE EVENT SESSION DROP TARGET",
            "ALTER ANY DATABASE EVENT SESSION OPTION",
            "CREATE ANY DATABASE EVENT SESSION",
            "DROP ANY DATABASE EVENT SESSION",
        ];
        let labels: Vec<NoteLabel> = names
            .iter()
            .map(|n| super::NoteLabel::sqlserver_name(n))
            .collect();
        assert!(labels.iter().all(|l| !l.is_other()));
        let refused = super::TargetNote::new(super::NoteCode::PrivilegeRefused).with_labels(
            labels
                .iter()
                .copied()
                .chain([super::NoteLabel::sqlserver_name("CONTROL SERVER")]),
        );
        let a = LabelRevisions {
            r2026_10: true,
            r2026_10_b: false,
        };
        let b = LabelRevisions {
            r2026_10: false,
            r2026_10_b: true,
        };
        // Not negotiated: every revision value is `other`, once.
        assert_eq!(sent(&refused, LabelRevisions::default()), vec!["other"]);
        assert_eq!(sent(&refused, a), vec!["other", "control_server"]);
        let only_b = sent(&refused, b);
        assert_eq!(only_b.len(), 11);
        assert_eq!(only_b[0], "other");
        assert!(!only_b.contains(&"control_server".to_owned()));
        // Negotiated: the real labels, in enum order.
        let all = sent(&refused, LabelRevisions::ALL);
        assert_eq!(all.len(), 11);
        assert!(!all.contains(&"other".to_owned()));
        let mut expected: Vec<String> = names
            .iter()
            .map(|n| n.to_lowercase().replace(' ', "_"))
            .collect();
        expected.insert(0, "control_server".to_owned());
        assert_eq!(all, expected);
        // The not-evaluated reads.
        let probes = super::TargetNote::new(super::NoteCode::PrivilegeNotEvaluated).with_labels(
            [
                "password_hash_probe",
                "logon_trigger_probe",
                "refusal_list_probe",
            ]
            .map(super::NoteLabel::sqlserver),
        );
        assert_eq!(sent(&probes, LabelRevisions::default()), vec!["other"]);
        assert_eq!(sent(&probes, a), vec!["other", "password_hash_probe"]);
        assert_eq!(
            sent(&probes, b),
            vec!["other", "logon_trigger_probe", "refusal_list_probe"]
        );
        assert_eq!(
            sent(&probes, LabelRevisions::ALL),
            vec![
                "password_hash_probe",
                "logon_trigger_probe",
                "refusal_list_probe"
            ]
        );
    }

    #[test]
    fn labels_are_closed() {
        assert_eq!(NoteLabel::parse("bypassrls").as_str(), "bypassrls");
        assert_eq!(NoteLabel::parse("pg_monitor").as_str(), "pg_monitor");
        assert!(NoteLabel::parse("app_owner").is_other());
        assert!(NoteLabel::parse("BYPASSRLS").is_other());
        assert!(NoteLabel::parse("hunter2 secret").is_other());
        assert_eq!(NoteLabel::privilege("SHOW VIEW").as_str(), "show_view");
        assert_eq!(
            NoteLabel::privilege("BINLOG ADMIN").as_str(),
            "binlog_admin"
        );
        assert_eq!(
            NoteLabel::privilege("BINLOG_ADMIN").as_str(),
            "binlog_admin"
        );
        assert!(NoteLabel::privilege("weird-SECRET").is_other());
        assert!(NoteLabel::privilege("").is_other());
        assert!(NoteLabel::privilege(&"A".repeat(65)).is_other());
        assert_eq!(NoteLabel::stage("connect").as_str(), "stage_connect");
        assert_eq!(NoteLabel::stage("kill").as_str(), "stage_kill");
        assert!(NoteLabel::stage("stage_connect").is_other());
        assert!(NoteLabel::stage("x").is_other());
    }

    #[test]
    fn labels_are_sorted_deduplicated_and_bounded() {
        let many = [
            "alter",
            "create",
            "delete",
            "drop",
            "event",
            "execute",
            "file",
            "index",
            "insert",
            "process",
            "reload",
            "super",
            "trigger",
            "update",
            "references",
            "shutdown",
            "create_view",
            "show_view",
        ];
        let n = TargetNote::new(NoteCode::PrivilegeBeyondSelect)
            .with_labels(many.iter().map(|p| NoteLabel::parse(p)))
            .with_labels([NoteLabel::OTHER, NoteLabel::OTHER]);
        // Kept whole (deduplicated, sorted) until sent.
        assert_eq!(n.labels().len(), many.len() + 1);
        let mut sorted = n.labels().to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, n.labels());
        // Cut to the contract's 16 when sent.
        let out = sent(&n, LabelRevisions::default());
        assert_eq!(out.len(), MAX_LABELS);
        let mut sorted = out.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), MAX_LABELS);
    }

    #[test]
    fn the_most_severe_labels_survive_truncation() {
        // 18 labels of lesser severity, listed first, then the ones that
        // matter most: those are kept, `other` and unlisted labels go.
        let lesser = [
            "show_view",
            "create_view",
            "show_databases",
            "lock_tables",
            "references",
            "index",
            "create",
            "alter",
            "insert",
            "update",
            "delete",
            "drop",
            "event",
            "trigger",
            "alter_routine",
            "create_routine",
            "execute",
            "flush_tables",
        ];
        let n = TargetNote::new(NoteCode::PrivilegeGlobalPrivileges)
            .with_labels([NoteLabel::OTHER])
            .with_labels(lesser.iter().map(|p| NoteLabel::parse(p)))
            .with_labels(["super", "file", "process"].map(NoteLabel::parse));
        let kept = sent(&n, LabelRevisions::default());
        assert_eq!(kept.len(), MAX_LABELS);
        for must in ["super", "file", "process", "execute"] {
            assert!(kept.iter().any(|k| k == must), "{must} cut: {kept:?}");
        }
        for gone in ["other", "show_view", "create_view", "flush_tables"] {
            assert!(!kept.iter().any(|k| k == gone), "{gone} kept: {kept:?}");
        }
        let as_sent = super::to_protocol(std::slice::from_ref(&n), LabelRevisions::default())[0]
            .labels
            .clone()
            .unwrap();
        let mut sorted = as_sent.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, as_sent, "sent in enum order");
        // PostgreSQL attributes rank first, and survive a merge too.
        let mut notes = Notes::default();
        notes.add(
            TargetNote::new(NoteCode::PrivilegeRoleAttributes)
                .with_labels(lesser.iter().map(|p| NoteLabel::parse(p))),
        );
        notes.add(
            TargetNote::new(NoteCode::PrivilegeRoleAttributes)
                .with_labels(["superuser", "bypassrls", "createrole"].map(NoteLabel::parse)),
        );
        let kept = sent(&notes.as_slice()[0], LabelRevisions::default());
        assert_eq!(kept.len(), MAX_LABELS);
        for must in ["superuser", "bypassrls", "createrole"] {
            assert!(kept.iter().any(|k| k == must), "{must} cut: {kept:?}");
        }
    }

    /// Security review L1: labels of a revision the console has not
    /// negotiated become `other` before the cut, so they never push out
    /// labels it can receive; the hash probe always survives.
    #[test]
    fn the_cut_to_sixteen_keeps_the_labels_the_console_can_receive() {
        // A console that lists `2026_10` only.
        let a = LabelRevisions {
            r2026_10: true,
            r2026_10_b: false,
        };
        // 14 labels of 2026_10 outside the severity list, the hash probe,
        // and the 20 labels of 2026_10_b (three of them in the severity
        // list): 35 labels, 15 of them sendable.
        let sendable = [
            "serveradmin",
            "setupadmin",
            "processadmin",
            "diskadmin",
            "dbcreator",
            "bulkadmin",
            "ms_database_connector",
            "ms_database_manager",
            "ms_definition_reader",
            "db_securityadmin",
            "db_accessadmin",
            "db_backupoperator",
            "db_ddladmin",
            "db_datawriter",
        ];
        let note = TargetNote::new(NoteCode::PrivilegeRefused).with_labels(
            sendable
                .iter()
                .chain(super::LABELS_REVISION_2026_10_B)
                .chain(&["password_hash_probe"])
                .map(|v| NoteLabel::sqlserver(v)),
        );
        assert_eq!(note.labels().len(), 35);
        let out = sent(&note, a);
        assert_eq!(out.len(), 16, "{out:?}");
        for must in sendable.iter().chain(&["password_hash_probe", "other"]) {
            assert!(out.iter().any(|l| l == must), "{must} cut: {out:?}");
        }
        for v in super::LABELS_REVISION_2026_10_B {
            assert!(!out.iter().any(|l| l == v), "{v} sent unnegotiated");
        }
        // With more sendable labels than slots, the hash probe still
        // survives, and `other` is the first to go.
        let crowded = note.clone().with_labels(
            [
                "select",
                "insert",
                "update",
                "delete",
                "alter",
                "execute",
                "control",
                "impersonate",
            ]
            .map(NoteLabel::sqlserver),
        );
        let out = sent(&crowded, a);
        assert_eq!(out.len(), 16);
        assert!(out.iter().any(|l| l == "password_hash_probe"), "{out:?}");
        assert!(!out.iter().any(|l| l == "other"), "{out:?}");
        // Both revisions: the 16 most severe, the hash probe first.
        let out = sent(&crowded, LabelRevisions::ALL);
        assert_eq!(out.len(), 16);
        assert!(out.iter().any(|l| l == "password_hash_probe"), "{out:?}");
        assert!(
            out.iter().any(|l| l == "alter_any_database_event_session"),
            "{out:?}"
        );
    }

    #[test]
    fn notes_merge_by_code() {
        let mut notes = Notes::default();
        notes.merge(
            TargetNote::new(NoteCode::CoverageSchemasWithoutUsage).with_count(2),
            CountMerge::Sum,
        );
        notes.merge(
            TargetNote::new(NoteCode::CoverageSchemasWithoutUsage).with_count(3),
            CountMerge::Sum,
        );
        notes.add(TargetNote::new(NoteCode::PrivilegeOtherRoles).with_count(2));
        notes.add(TargetNote::new(NoteCode::PrivilegeOtherRoles).with_count(2));
        notes.add(
            TargetNote::new(NoteCode::PrivilegeRoleAttributes)
                .with_labels([NoteLabel::parse("superuser")]),
        );
        notes.add(
            TargetNote::new(NoteCode::PrivilegeRoleAttributes)
                .with_labels([NoteLabel::parse("bypassrls"), NoteLabel::parse("superuser")]),
        );
        let v = notes.into_vec();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].count(), Some(5));
        assert_eq!(v[1].count(), Some(2));
        assert_eq!(v[2].labels().len(), 2);
    }

    #[test]
    fn protocol_notes_are_bounded_ranked_and_saturated() {
        let mut notes: Vec<TargetNote> = NoteCode::ALL
            .iter()
            .map(|c| TargetNote::new(*c).with_count(u64::MAX))
            .collect();
        notes.push(TargetNote::new(NoteCode::SecurityTlsDisabled));
        let out = to_protocol(&notes, LabelRevisions::default());
        assert_eq!(out.len(), MAX_NOTES);
        // Security and check notes are never the ones cut.
        for c in NoteCode::ALL {
            if c.rank() <= 1 {
                assert!(out.iter().any(|n| n.code.as_str() == c.as_str()), "{c:?}");
            }
        }
        assert!(
            out.iter()
                .all(|n| n.count.as_ref().unwrap().0 == crate::sanitize::MAX_COUNT)
        );
        let json = serde_json::to_value(&out).unwrap();
        for n in json.as_array().unwrap() {
            let keys: Vec<&String> = n.as_object().unwrap().keys().collect();
            assert!(
                keys.iter()
                    .all(|k| ["code", "count", "labels"].contains(&k.as_str()))
            );
        }
        // No labels: the field is omitted.
        let one = to_protocol(
            &[TargetNote::new(NoteCode::CheckTimedOut)],
            LabelRevisions::default(),
        );
        assert_eq!(
            serde_json::to_value(&one).unwrap(),
            serde_json::json!([{"code": "check.timed_out"}])
        );
    }
}
