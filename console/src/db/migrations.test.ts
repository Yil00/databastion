import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { MIGRATIONS_FOLDER, runMigrations } from "@/db/run-migrations";
import { adminQuery, createRuntimeRole, hasDb, pgAdminUrl, roleUrl, setupTestDatabase } from "@/test/db";

async function withClient<T>(url: string, fn: (c: Client) => Promise<T>): Promise<T> {
  const c = new Client({ connectionString: url });
  await c.connect();
  try {
    return await fn(c);
  } finally {
    await c.end();
  }
}

/** Runs `sql` as the cluster administrator inside database `db`. */
async function adminInDb(db: string, sql: string): Promise<void> {
  const url = new URL(String(pgAdminUrl));
  url.pathname = `/${db}`;
  await withClient(url.toString(), (c) => c.query(sql));
}

describe.skipIf(!hasDb)("migrations (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  let ownerUrl: string;

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    ownerUrl = String(process.env.DATABASE_URL);
  });
  afterAll(async () => teardown?.());

  describe("0010: security_events is not deletable by the runtime role (L2)", () => {
    it("the runtime role can insert and acknowledge, but not delete, truncate or rewrite", async () => {
      const { url } = await createRuntimeRole();
      await withClient(url, async (c) => {
        const inserted = await c.query<{ id: string }>(
          "insert into security_events (kind, severity) values ('rotation_conflict', 'critical') returning id",
        );
        const id = inserted.rows[0]?.id;
        expect(id).toBeDefined();
        await c.query("update security_events set acknowledged_at = now() where id = $1", [id]);
        for (const stmt of [
          "delete from security_events",
          "truncate security_events",
          "update security_events set kind = 'x'",
          "update security_events set severity = 'low'",
          "update security_events set details = null",
        ]) {
          await expect(c.query(stmt), stmt).rejects.toThrow(/permission denied/);
        }
        const [row] = (await c.query("select count(*)::int as n from security_events where id = $1", [id]))
          .rows as { n: number }[];
        expect(row?.n).toBe(1);
      });
      await withClient(ownerUrl, async (c) => {
        const { rows } = await c.query(`
          select has_table_privilege('databastion_app', 'public.security_events', 'DELETE') as del,
                 has_table_privilege('databastion_app', 'public.security_events', 'UPDATE') as upd,
                 has_table_privilege('databastion_app', 'public.security_events', 'INSERT') as ins,
                 has_column_privilege('databastion_app', 'public.security_events', 'acknowledged_by', 'UPDATE') as ack_by,
                 has_column_privilege('databastion_app', 'public.security_events', 'kind', 'UPDATE') as kind_upd`);
        expect(rows[0]).toEqual({ del: false, upd: false, ins: true, ack_by: true, kind_upd: false });
      });
    });

    it("deleting a referenced agent still works for the runtime role (ON DELETE SET NULL runs as the owner)", async () => {
      const { url } = await createRuntimeRole();
      await withClient(url, async (c) => {
        const agent = await c.query<{ id: string }>(
          "insert into agents (name, hostname, version) values ('del', 'del', '0.1.0') returning id",
        );
        const agentId = agent.rows[0]?.id;
        await c.query(
          "insert into security_events (kind, severity, agent_id) values ('rotation_conflict', 'critical', $1)",
          [agentId],
        );
        await c.query("delete from agents where id = $1", [agentId]);
        const { rows } = await c.query("select agent_id from security_events where kind = 'rotation_conflict' and agent_id is null");
        expect(rows.length).toBeGreaterThan(0);
      });
    });
  });

  describe("0009: refuses to run when pgboss is owned by another role", () => {
    const guardSql = readFileSync(path.join(MIGRATIONS_FOLDER, "0009_pgboss_owner_guard.sql"), "utf8");

    it("passes when the owner role owns pgboss (normal migration)", async () => {
      await withClient(ownerUrl, async (c) => {
        const { rows } = await c.query(
          "select pg_get_userbyid(nspowner) = current_user as own from pg_namespace where nspname = 'pgboss'",
        );
        expect(rows[0]).toEqual({ own: true });
        await expect(c.query(guardSql)).resolves.toBeDefined();
      });
    });

    it("raises when pgboss belongs to another role, on a re-run of the migration", async () => {
      const suffix = randomBytes(6).toString("hex");
      const db = `g_${suffix}`;
      const owner = `go_${suffix}`;
      const other = `gx_${suffix}`;
      await adminQuery(`create role ${owner} login nosuperuser nocreatedb nocreaterole`);
      await adminQuery(`create role ${other} nologin`);
      await adminQuery(`create database ${db} owner ${owner}`);
      try {
        const url = roleUrl(owner, db);
        await runMigrations(url);
        await adminInDb(db, `alter schema pgboss owner to ${other}`);
        await withClient(url, async (c) => {
          await expect(c.query(guardSql)).rejects.toThrow(/schema pgboss is owned by role/);
        });
      } finally {
        await adminQuery(`drop database if exists ${db} with (force)`);
        await adminQuery(`drop role if exists ${owner}`);
        await adminQuery(`drop role if exists ${other}`);
      }
    });

    // On a fresh database, 0004 already fails there (its GRANT on a schema the owner does not own);
    // the guard (0009) is what protects databases that applied 0004 earlier (test above).
    it("a fresh migration over a planted pgboss schema aborts with nothing applied", async () => {
      const suffix = randomBytes(6).toString("hex");
      const db = `p_${suffix}`;
      const owner = `po_${suffix}`;
      const other = `px_${suffix}`;
      await adminQuery(`create role ${owner} login nosuperuser nocreatedb nocreaterole`);
      await adminQuery(`create role ${other} nologin`);
      await adminQuery(`create database ${db} owner ${owner}`);
      try {
        await adminInDb(db, `create schema pgboss authorization ${other}`);
        const url = roleUrl(owner, db);
        await expect(runMigrations(url)).rejects.toThrow();
        // One transaction: none of the migrations was applied.
        await withClient(url, async (c) => {
          const { rows } = await c.query("select to_regclass('public.agents') is null as absent");
          expect(rows[0]).toEqual({ absent: true });
        });
      } finally {
        await adminQuery(`drop database if exists ${db} with (force)`);
        await adminQuery(`drop role if exists ${owner}`);
        await adminQuery(`drop role if exists ${other}`);
      }
    });
  });
});
