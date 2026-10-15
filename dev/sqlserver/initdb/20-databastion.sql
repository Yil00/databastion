-- DataBastion agent login, ADR-0051 decision 4, minimal variant. DEV-ONLY password, passed by
-- dev/sqlserver/entrypoint.sh as the sqlcmd variable DATABASTION_PASSWORD (never logged).
-- Schema-level SELECT on the two monitored schemas only; no VIEW DEFINITION, no db_datareader.
-- The CAS store guard gets the three columns of the ticket table it counts (ADR-0041 decision 6).
-- Audit is enabled in dev, so the Audit grant of decision 4 is given for the server's version:
-- VIEW SERVER SECURITY AUDIT (2022+, SQL Server Audit source) and VIEW SERVER PERFORMANCE STATE
-- (2022+, Extended Events source); VIEW SERVER STATE on 2019 (Extended Events only).
-- Row-level security visibility (ADR-0051 refinement item 2, option (iv), open question 5): the
-- dev and E2E account holds database VIEW DEFINITION in `retail` and its targets declare
-- `sqlserver.rls_visibility: view_definition`, so Discovery is tested; the integration tests
-- revoke it to check the minimal variant's whole-database skip.
SET NOCOUNT ON;
USE master;
CREATE LOGIN databastion WITH PASSWORD = N'$(DATABASTION_PASSWORD)', CHECK_POLICY = ON, DEFAULT_DATABASE = retail;
GO
DECLARE @major int = CONVERT(int, SERVERPROPERTY('ProductMajorVersion'));
IF @major >= 16
BEGIN
  EXEC (N'GRANT VIEW SERVER SECURITY AUDIT TO databastion; GRANT VIEW SERVER PERFORMANCE STATE TO databastion;');
END
ELSE
BEGIN
  EXEC (N'GRANT VIEW SERVER STATE TO databastion;');
END
GO
USE retail;
CREATE USER databastion FOR LOGIN databastion;
GRANT SELECT ON SCHEMA::crm TO databastion;
GRANT SELECT ON SCHEMA::finance TO databastion;
GRANT SELECT ON cas.cas_tickets (type, creation_time, expiration_time) TO databastion;
GRANT VIEW DEFINITION TO databastion;
GO
