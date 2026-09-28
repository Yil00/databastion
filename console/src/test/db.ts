import { randomBytes } from "node:crypto";

import { Client } from "pg";
import { inject } from "vitest";

import { closeDb } from "@/db/client";
import { runMigrations } from "@/db/run-migrations";
import { jobHub } from "@/server/agent-api/job-hub";

export const pgAdminUrl = inject("pgAdminUrl");
export const hasDb = pgAdminUrl !== null;

async function asAdmin<T>(fn: (c: Client) => Promise<T>): Promise<T> {
  if (!pgAdminUrl) throw new Error("no test database");
  const c = new Client({ connectionString: pgAdminUrl });
  await c.connect();
  try {
    return await fn(c);
  } finally {
    await c.end();
  }
}

/** Runs `sql` as the cluster administrator (role creation: the owner has no CREATEROLE). */
export const adminQuery = (sql: string) => asAdmin((c) => c.query(sql));

async function ensureGroupRole(c: Client): Promise<void> {
  // Same as deploy/initdb: the group role exists before the migrations run.
  await c.query(`do $$ begin
    create role databastion_app nologin nosuperuser nocreatedb nocreaterole nobypassrls;
  exception when duplicate_object or unique_violation then null; end $$`);
}

/** URL of `pgAdminUrl` with another role / database (trust authentication in the test cluster). */
export function roleUrl(role: string, database?: string): string {
  const url = new URL(String(process.env.DATABASE_URL ?? pgAdminUrl));
  url.username = role;
  url.password = "";
  if (database) url.pathname = `/${database}`;
  return url.toString();
}

/**
 * Creates a fresh database for the calling test file, owned by a fresh NON-superuser owner role
 * (as in production), migrates it as that owner and points `DATABASE_URL` at the owner.
 * Returns a teardown that drops both.
 */
export async function setupTestDatabase(): Promise<() => Promise<void>> {
  const suffix = randomBytes(6).toString("hex");
  const name = `t_${suffix}`;
  const owner = `o_${suffix}`;
  await asAdmin(async (c) => {
    await ensureGroupRole(c);
    await c.query(`create role ${owner} login nosuperuser nocreatedb nocreaterole`);
    await c.query(`create database ${name} owner ${owner}`);
  });
  const url = roleUrl(owner, name);
  await runMigrations(url);
  process.env.DATABASE_URL = url;
  return async () => {
    await jobHub.close();
    await closeDb();
    await asAdmin(async (c) => {
      await c.query(`drop database if exists ${name} with (force)`);
      await c.query(`drop role if exists ${owner}`);
    });
  };
}

/** Creates a runtime LOGIN role, member of databastion_app, and returns its URL for this database. */
export async function createRuntimeRole(): Promise<{ role: string; url: string }> {
  const role = `r_${randomBytes(6).toString("hex")}`;
  await adminQuery(`create role ${role} login nosuperuser nocreatedb nocreaterole in role databastion_app`);
  return { role, url: roleUrl(role) };
}
