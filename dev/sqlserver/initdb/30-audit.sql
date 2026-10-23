-- DataBastion dev audit setup (ADR-0051 decision 6), created by the operator (here, `sa` at seed
-- time), never by the agent. Applied after the seed and the agent account, so neither is recorded.
-- SQL Server Audit: a FILE target, no WHERE predicate, ON_FAILURE = CONTINUE; one server audit
-- specification with read coverage for every database (SCHEMA_OBJECT_ACCESS_GROUP), the required
-- AUDIT_CHANGE_GROUP, failed logins, principal changes (password-bearing DCL), role-membership
-- changes of server and database roles (ROADMAP phase 9 follow-up, #281 review L2) and backups.
-- Extended Events: the statement-level events and rpc_completed with the five actions of the
-- Partial proof, failed logins (error_reported, error 18456 only: a bare TCP connect such as the
-- healthcheck's gives error 17830, left out by the predicate), an event_file target,
-- TRACK_CAUSALITY on, started at server start.
SET NOCOUNT ON;
USE master;
CREATE SERVER AUDIT databastion_audit
  TO FILE (FILEPATH = N'/var/opt/mssql/audit/', MAXSIZE = 64 MB, MAX_ROLLOVER_FILES = 8, RESERVE_DISK_SPACE = OFF)
  WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO
CREATE SERVER AUDIT SPECIFICATION databastion_audit_spec FOR SERVER AUDIT databastion_audit
  ADD (AUDIT_CHANGE_GROUP),
  ADD (SCHEMA_OBJECT_ACCESS_GROUP),
  ADD (FAILED_LOGIN_GROUP),
  ADD (SERVER_PRINCIPAL_CHANGE_GROUP),
  ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
  ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
  ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
  ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP),
  ADD (LOGIN_CHANGE_PASSWORD_GROUP),
  ADD (BACKUP_RESTORE_GROUP)
  WITH (STATE = ON);
GO
ALTER SERVER AUDIT databastion_audit WITH (STATE = ON);
GO
CREATE EVENT SESSION databastion_xe ON SERVER
  ADD EVENT sqlserver.sql_statement_completed (ACTION (sqlserver.server_principal_name,
    sqlserver.session_server_principal_name, sqlserver.client_app_name, sqlserver.database_name, sqlserver.session_id)),
  ADD EVENT sqlserver.sp_statement_completed (ACTION (sqlserver.server_principal_name,
    sqlserver.session_server_principal_name, sqlserver.client_app_name, sqlserver.database_name, sqlserver.session_id)),
  ADD EVENT sqlserver.rpc_completed (ACTION (sqlserver.server_principal_name,
    sqlserver.session_server_principal_name, sqlserver.client_app_name, sqlserver.database_name, sqlserver.session_id)),
  ADD EVENT sqlserver.error_reported (ACTION (sqlserver.server_principal_name,
    sqlserver.session_server_principal_name, sqlserver.client_app_name, sqlserver.database_name, sqlserver.session_id)
    WHERE ([error_number] = (18456)))
  ADD TARGET package0.event_file (SET filename = N'/var/opt/mssql/xe/databastion_xe.xel', max_file_size = 64,
    max_rollover_files = 8)
  WITH (TRACK_CAUSALITY = ON, STARTUP_STATE = ON, MAX_DISPATCH_LATENCY = 5 SECONDS);
GO
ALTER EVENT SESSION databastion_xe ON SERVER STATE = START;
GO
