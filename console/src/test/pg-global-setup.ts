import { spawnSync } from "node:child_process";
import { chownSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import type { TestProject } from "vitest/node";

/**
 * Starts a throwaway PostgreSQL cluster on 127.0.0.1 for the DB tests and deletes it afterwards.
 * - `TEST_DATABASE_URL` set: used as is (an admin URL allowed to CREATE DATABASE).
 * - Otherwise, the binaries from `PG_BIN` (default /usr/lib/postgresql/16/bin) are used.
 * - Neither available: DB tests are skipped with a clear message; unit tests still run.
 */
declare module "vitest" {
  export interface ProvidedContext {
    pgAdminUrl: string | null;
  }
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => (addr && typeof addr === "object" ? resolve(addr.port) : reject(new Error("no port"))));
    });
  });
}

export default async function setup(project: TestProject) {
  if (process.env.TEST_DATABASE_URL) {
    project.provide("pgAdminUrl", process.env.TEST_DATABASE_URL);
    return;
  }
  const bin = process.env.PG_BIN ?? "/usr/lib/postgresql/16/bin";
  if (!existsSync(path.join(bin, "initdb"))) {
    // eslint-disable-next-line no-console -- test harness message
    console.warn(`[db tests] SKIPPED: no PostgreSQL binaries in ${bin} and no TEST_DATABASE_URL.`);
    project.provide("pgAdminUrl", null);
    return;
  }
  const dir = mkdtempSync(path.join(tmpdir(), "databastion-pg-"));
  const asRoot = process.getuid?.() === 0;
  // initdb refuses to run as root: use the `postgres` system user in that case.
  const run = (cmd: string, args: string[]) => {
    const [c, a] = asRoot ? ["runuser", ["-u", "postgres", "--", cmd, ...args]] : [cmd, args];
    const res = spawnSync(c, a as string[], { cwd: "/", timeout: 60_000, encoding: "utf8" });
    if (res.status !== 0) throw new Error(`${path.basename(cmd)} failed: ${res.stderr || res.error}`);
  };
  if (asRoot) {
    const pgUid = Number(spawnSync("id", ["-u", "postgres"], { encoding: "utf8" }).stdout.trim());
    chownSync(dir, pgUid, -1);
  }
  const port = await freePort();
  const data = path.join(dir, "data");
  run(path.join(bin, "initdb"), ["-D", data, "-U", "postgres", "--auth=trust", "-E", "UTF8"]);
  run(path.join(bin, "pg_ctl"), [
    "-D", data, "-l", path.join(dir, "log"), "-w", "-t", "30",
    "-o", `-p ${port} -k ${dir} -c listen_addresses=127.0.0.1 -c fsync=off -c max_connections=200`,
    "start",
  ]);
  project.provide("pgAdminUrl", `postgres://postgres@127.0.0.1:${port}/postgres`);
  return () => {
    try {
      run(path.join(bin, "pg_ctl"), ["-D", data, "-m", "immediate", "-w", "stop"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}
