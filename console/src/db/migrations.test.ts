import { randomBytes } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { readMigrationFiles } from "drizzle-orm/migrator";

import { Client, Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { applyAccessEventsBytesOnline, ONLINE_0027_TAG, validateDeferredConstraints } from "@/db/online-constraints";
import { MIGRATIONS_FOLDER, PgbossOwnerError, runMigrations } from "@/db/run-migrations";
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

  describe("0011: findings tables", () => {
    it("the runtime role can read and write findings and batches; locations are unique per agent", async () => {
      const { url } = await createRuntimeRole();
      await withClient(url, async (c) => {
        const agent = await c.query<{ id: string }>(
          "insert into agents (name, hostname, version) values ('h', 'h', '0.1.0') returning id",
        );
        const agentId = agent.rows[0]?.id;
        await c.query(
          "insert into agent_targets (agent_id, target_id, engine, reachable, audit_level) values ($1, 'pg', 'postgres', true, 'none')",
          [agentId],
        );
        const insert = (id: string) =>
          c.query(
            `insert into findings (id, agent_id, target_id, location_key, engine, database_name, object_name,
               field_name, classifier, classifiers_version, confidence, sampled, matched, last_batch_id)
             values ($1, $2, 'pg', $3, 'postgres', 'crm', 'clients', 'email', 'pii.email', '2026.09.1', 0.5, 10, 5, $1)`,
            [id, agentId, "a".repeat(64)],
          );
        await insert("01920f60-3c1a-7b2e-9f00-5a1b2c3d4e5f");
        await expect(insert("01920f60-3c1a-7b2e-9f00-5a1b2c3d4e60")).rejects.toThrow(/findings_location_key/);
        await c.query(
          "insert into findings_batches (agent_id, batch_id, body_sha256, findings_count) values ($1, $2, $3, 1)",
          [agentId, "01920f60-3c1a-7b2e-9f00-5a1b2c3d4e5f", "b".repeat(64)],
        );
        // A finding must reference a target reported by its agent.
        await expect(
          c.query(
            `insert into findings (id, agent_id, target_id, location_key, engine, database_name, object_name,
               field_name, classifier, classifiers_version, confidence, sampled, matched, last_batch_id)
             values ($1, $2, 'other', $3, 'postgres', 'crm', 'clients', 'email', 'pii.email', '2026.09.1', 0.5, 10, 5, $1)`,
            ["01920f60-3c1a-7b2e-9f00-5a1b2c3d4e61", agentId, "c".repeat(64)],
          ),
        ).rejects.toThrow(/findings_agent_target_fk/);
        await c.query("update findings set false_positive_at = now()");
        await c.query("delete from agents where id = $1", [agentId]);
        const left = await c.query("select count(*)::int as n from findings");
        expect((left.rows[0] as { n: number }).n).toBe(0);
      });
    });
  });

  describe("0012: findings_batches append-only, findings not deletable by the runtime role (L3)", () => {
    it("the runtime role can insert and read, update findings, but not delete / rewrite batches", async () => {
      const { url } = await createRuntimeRole();
      await withClient(url, async (c) => {
        const agent = await c.query<{ id: string }>(
          "insert into agents (name, hostname, version) values ('h2', 'h2', '0.1.0') returning id",
        );
        const agentId = agent.rows[0]?.id;
        await c.query(
          "insert into agent_targets (agent_id, target_id, engine, reachable, audit_level) values ($1, 'pg', 'postgres', true, 'none')",
          [agentId],
        );
        await c.query(
          "insert into findings_batches (agent_id, batch_id, body_sha256, findings_count) values ($1, $2, $3, 1)",
          [agentId, "01920f60-3c1a-7b2e-9f00-5a1b2c3d4e70", "d".repeat(64)],
        );
        await c.query(
          `insert into findings (id, agent_id, target_id, location_key, engine, database_name, object_name,
             field_name, classifier, classifiers_version, confidence, sampled, matched, last_batch_id)
           values ($1, $2, 'pg', $3, 'postgres', 'crm', 'clients', 'email', 'pii.email', '2026.09.1', 0.5, 10, 5, $1)`,
          ["01920f60-3c1a-7b2e-9f00-5a1b2c3d4e71", agentId, "e".repeat(64)],
        );
        await c.query("update findings set matched = 6, false_positive_matched = 6 where agent_id = $1", [agentId]);
        for (const stmt of [
          "delete from findings_batches",
          "truncate findings_batches",
          "update findings_batches set body_sha256 = repeat('0', 64)",
          "update findings_batches set findings_count = 0",
          "delete from findings",
          "truncate findings",
        ]) {
          await expect(c.query(stmt), stmt).rejects.toThrow(/permission denied/);
        }
        // Deleting the agent still cascades (foreign-key actions run as the table owner).
        await c.query("delete from agents where id = $1", [agentId]);
        const left = await c.query("select (select count(*) from findings)::int + (select count(*) from findings_batches)::int as n");
        expect((left.rows[0] as { n: number }).n).toBe(0);
      });
    });
  });

  describe("0030: rate_limit_counters (P4-D shared rate limits)", () => {
    it("the runtime role can select, insert, update and delete, nothing else", async () => {
      const { url } = await createRuntimeRole();
      await withClient(url, async (c) => {
        await c.query(
          `insert into rate_limit_counters (limiter, key_hash, window_start, expires_at, count)
           values ('test.grants', $1, now(), now() + interval '1 minute', 1)
           on conflict (limiter, key_hash) do update set count = rate_limit_counters.count + 1`,
          ["a".repeat(64)],
        );
        await c.query("update rate_limit_counters set count = count - 1 where limiter = 'test.grants'");
        const read = await c.query("select count from rate_limit_counters where limiter = 'test.grants'");
        expect((read.rows[0] as { count: number }).count).toBe(0);
        await c.query("delete from rate_limit_counters where limiter = 'test.grants'");
        await expect(c.query("truncate rate_limit_counters")).rejects.toThrow(/permission denied/);
        // The constraints bound what a compromised process can store: hashed keys, sane windows.
        for (const [limiter, key, count] of [["test.grants", "admin|198.51.100.7", 1], ["Bad Name", "b".repeat(64), 1], ["test.grants", "c".repeat(64), -1]] as const) {
          await expect(
            c.query(
              "insert into rate_limit_counters (limiter, key_hash, window_start, expires_at, count) values ($1, $2, now(), now() + interval '1 minute', $3)",
              [limiter, key, count],
            ),
          ).rejects.toThrow(/violates check constraint/);
        }
      });
      const privileges = await withClient(ownerUrl, (c) =>
        c.query(`select privilege_type from information_schema.role_table_grants
                 where grantee = 'databastion_app' and table_name = 'rate_limit_counters' order by 1`),
      );
      expect(privileges.rows.map((r) => (r as { privilege_type: string }).privilege_type)).toEqual(["DELETE", "INSERT", "SELECT", "UPDATE"]);
    });
  });

  describe("0027: access_events_bytes without a long lock (P7)", () => {
    /** A copy of the migrations folder whose journal stops before `tag`. */
    function folderBefore(tag: string): { folder: string; cleanup: () => void } {
      const dir = mkdtempSync(path.join(tmpdir(), "databastion-migrations-"));
      const folder = path.join(dir, "drizzle");
      cpSync(MIGRATIONS_FOLDER, folder, { recursive: true });
      const journalPath = path.join(folder, "meta", "_journal.json");
      const journal = JSON.parse(readFileSync(journalPath, "utf8")) as { entries: { tag: string }[] };
      const at = journal.entries.findIndex((e) => e.tag === tag);
      expect(at).toBeGreaterThan(0);
      journal.entries = journal.entries.slice(0, at);
      writeFileSync(journalPath, JSON.stringify(journal));
      return { folder, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
    }

    const constraintSql = `
      select pg_get_constraintdef(c.oid) as def, c.convalidated as validated
        from pg_constraint c where c.conname = 'access_events_bytes' and c.conrelid = 'public.access_events'::regclass`;
    const columnSql = `
      select data_type, is_nullable, column_default from information_schema.columns
       where table_schema = 'public' and table_name = 'access_events' and column_name = 'bytes'`;

    async function seedEvents(c: Client, n: number): Promise<string> {
      const agent = await c.query<{ id: string }>(
        "insert into agents (name, hostname, version) values ('ae', 'ae', '0.1.0') returning id",
      );
      const agentId = String(agent.rows[0]?.id);
      await c.query(
        "insert into agent_targets (agent_id, target_id, engine, reachable, audit_level) values ($1, 'pg', 'postgres', true, 'full')",
        [agentId],
      );
      await c.query(
        `insert into access_events (agent_id, target_id, batch_id, item_index, ts, principal_key, db_user, action, objects, source, aggregated_count)
         select $1, 'pg', gen_random_uuid(), i, now(), repeat('a', 64), 'app', 'read', '[]'::jsonb, 'pgaudit', 1
           from generate_series(1, $2::int) i`,
        [agentId, n],
      );
      return agentId;
    }

    it("an install at 0026 with events gets 0027 as NOT VALID + VALIDATE, recorded with the 0027 hash; same schema as a fresh install", async () => {
      const suffix = randomBytes(6).toString("hex");
      const db = `u_${suffix}`;
      const owner = `uo_${suffix}`;
      await adminQuery(`create role ${owner} login nosuperuser nocreatedb nocreaterole`);
      await adminQuery(`create database ${db} owner ${owner}`);
      const before = folderBefore(ONLINE_0027_TAG);
      try {
        const url = roleUrl(owner, db);
        await runMigrations(url, before.folder);
        await withClient(url, async (c) => {
          expect((await c.query(columnSql)).rows).toEqual([]);
          await seedEvents(c, 5000);
        });
        // The pre-flight of runMigrations, called directly to check that it took the online path.
        const pool = new Pool({ connectionString: url, max: 1, options: "-c search_path=public" });
        try {
          await expect(applyAccessEventsBytesOnline(pool, before.folder)).resolves.toBe("not_needed");
          await expect(applyAccessEventsBytesOnline(pool, MIGRATIONS_FOLDER)).resolves.toBe("applied");
          await expect(applyAccessEventsBytesOnline(pool, MIGRATIONS_FOLDER)).resolves.toBe("not_needed");
        } finally {
          await pool.end();
        }
        await runMigrations(url);
        const fresh = await withClient(ownerUrl, async (c) => ({
          constraint: (await c.query(constraintSql)).rows,
          column: (await c.query(columnSql)).rows,
        }));
        await withClient(url, async (c) => {
          expect((await c.query(constraintSql)).rows).toEqual(fresh.constraint);
          expect((await c.query(columnSql)).rows).toEqual(fresh.column);
          expect(fresh.constraint).toEqual([{ def: "CHECK (((bytes IS NULL) OR (bytes >= 0)))", validated: true }]);
          // Every migration recorded once, 0027 with the hash of its unchanged file.
          const all = readMigrationFiles({ migrationsFolder: MIGRATIONS_FOLDER });
          const recorded = await c.query<{ hash: string; created_at: string }>(
            "select hash, created_at from drizzle.__drizzle_migrations order by created_at",
          );
          expect(recorded.rows.map((r) => [r.hash, Number(r.created_at)])).toEqual(all.map((m) => [m.hash, m.folderMillis]));
          const n = await c.query<{ n: number; with_bytes: number }>(
            "select count(*)::int as n, count(bytes)::int as with_bytes from access_events",
          );
          expect(n.rows[0]).toEqual({ n: 5000, with_bytes: 0 });
          await expect(c.query("update access_events set bytes = -1 where item_index = 1")).rejects.toThrow(/access_events_bytes/);
        });
        // A second run changes nothing; a fresh install never takes the online path.
        await expect(runMigrations(url)).resolves.toBeUndefined();
        const freshPool = new Pool({ connectionString: ownerUrl, max: 1 });
        try {
          await expect(applyAccessEventsBytesOnline(freshPool, MIGRATIONS_FOLDER)).resolves.toBe("not_needed");
        } finally {
          await freshPool.end();
        }
      } finally {
        before.cleanup();
        await adminQuery(`drop database if exists ${db} with (force)`);
        await adminQuery(`drop role if exists ${owner}`);
      }
    });

    it("a constraint left NOT VALID is validated on the next run, without blocking concurrent writes", async () => {
      await withClient(ownerUrl, async (c) => {
        await seedEvents(c, 100);
        // State of a run interrupted between the two steps.
        await c.query("alter table access_events drop constraint access_events_bytes");
        await c.query(
          'alter table access_events add constraint access_events_bytes check ("access_events"."bytes" is null or "access_events"."bytes" >= 0) not valid',
        );
        expect((await c.query(constraintSql)).rows[0]).toMatchObject({ validated: false });
      });
      // A writer holds an open transaction (ROW EXCLUSIVE on access_events): VALIDATE only takes
      // SHARE UPDATE EXCLUSIVE, so it completes while the insert is still uncommitted.
      const writer = new Client({ connectionString: ownerUrl });
      await writer.connect();
      const pool = new Pool({ connectionString: ownerUrl, max: 1, options: "-c lock_timeout=5000" });
      try {
        await writer.query("begin");
        await writer.query(
          `insert into access_events (agent_id, target_id, batch_id, item_index, ts, principal_key, db_user, action, objects, source, aggregated_count, bytes)
           select agent_id, target_id, gen_random_uuid(), 0, now(), repeat('b', 64), 'app', 'read', '[]'::jsonb, 'pgaudit', 1, 42
             from agent_targets limit 1`,
        );
        await expect(validateDeferredConstraints(pool)).resolves.toEqual(["access_events_bytes"]);
        await writer.query("commit");
        await expect(validateDeferredConstraints(pool)).resolves.toEqual([]);
      } finally {
        await writer.end();
        await pool.end();
      }
      await withClient(ownerUrl, async (c) => {
        expect((await c.query(constraintSql)).rows[0]).toEqual({ def: "CHECK (((bytes IS NULL) OR (bytes >= 0)))", validated: true });
        await c.query("delete from agents where name = 'ae'");
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
        // Every migrate run repeats the check as a pre-flight, even with no pending migration.
        const preflight = runMigrations(url);
        await expect(preflight).rejects.toBeInstanceOf(PgbossOwnerError);
        await expect(preflight).rejects.toThrow(/schema pgboss is owned by role gx_/);
        // Fixed ownership: migrate runs again.
        await adminInDb(db, `alter schema pgboss owner to ${owner}`);
        await expect(runMigrations(url)).resolves.toBeUndefined();
      } finally {
        await adminQuery(`drop database if exists ${db} with (force)`);
        await adminQuery(`drop role if exists ${owner}`);
        await adminQuery(`drop role if exists ${other}`);
      }
    });

    // On a fresh database the pre-flight refuses before any migration (0004 would fail too, on its
    // GRANT on a schema the owner does not own); 0009 and the pre-flight protect databases that
    // applied 0004 earlier (test above).
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
        await expect(runMigrations(url)).rejects.toBeInstanceOf(PgbossOwnerError);
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
