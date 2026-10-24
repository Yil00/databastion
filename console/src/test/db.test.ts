import { randomBytes } from "node:crypto";

import { Client, Pool } from "pg";
import { describe, expect, it } from "vitest";

import { dropTestDatabase, hasDb, pgAdminUrl } from "./db";

/**
 * Regression test of the intermittent unhandled FATAL 57P01 (CI Console job 120858331040):
 * `Pool.end()` resolves before its backends have exited, and a forced drop right after it
 * terminated them under clients still listening with the pool's idle `error` listener. With an
 * already connected admin session (no connection setup to hide the window), most rounds raised a
 * pool `error` event with a forced drop; `dropTestDatabase` lets the backends exit first.
 */
describe.skipIf(!hasDb)("test database teardown", () => {
  it("dropping a database right after Pool.end() terminates no closing client", async () => {
    const admin = new Client({ connectionString: String(pgAdminUrl) });
    await admin.connect();
    const errors: unknown[] = [];
    try {
      for (let i = 0; i < 10; i++) {
        const name = `d_${randomBytes(6).toString("hex")}`;
        await admin.query(`create database ${name}`);
        try {
          const url = new URL(String(pgAdminUrl));
          url.pathname = `/${name}`;
          const pool = new Pool({ connectionString: url.toString(), max: 4 });
          pool.on("error", (err) => errors.push(err));
          // Four concurrent queries: four connections, all idle in the pool when it ends.
          await Promise.all([0, 1, 2, 3].map(() => pool.query("select pg_sleep(0.01)")));
          await pool.end();
        } finally {
          await dropTestDatabase(admin, name);
        }
      }
      // A late ErrorResponse would arrive before the sockets' end.
      await new Promise((r) => setTimeout(r, 100));
    } finally {
      await admin.end();
    }
    expect(errors).toEqual([]);
  });
});
