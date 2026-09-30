-- Runs once, after the dev seed (10-seed.sql = dev/seed/out/postgres.sql, the data that
-- dev/ground-truth.json describes), as POSTGRES_USER on the `shop` database.
--
-- Discovery grants of the minimal ADR-0012 variant (docs/adr/0012-postgresql-agent-grants.md),
-- per application schema, as in dev/postgres/initdb/20-databastion.sh: USAGE and SELECT on the
-- seeded schemas, and default privileges FOR ROLE their owner so later tables are readable too.
-- Read-only (I4): no write privilege, no pg_read_all_data, no pg_monitor.
GRANT USAGE ON SCHEMA crm, billing, ops TO databastion_agent;
GRANT SELECT ON ALL TABLES IN SCHEMA crm, billing, ops TO databastion_agent;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA crm, billing, ops
  GRANT SELECT ON TABLES TO databastion_agent;
