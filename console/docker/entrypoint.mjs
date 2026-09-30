// DataBastion console image entrypoint: `web` (default), `worker`, `migrate`, `bootstrap-admin`.
// The runtime image is distroless (no shell): this dispatcher runs under the image's Node.js and
// replaces itself (`process.execve`, like `exec` in a shell) with the selected process, which
// becomes PID 1 and receives the container's signals directly.
// Secrets come from *_FILE variables (Docker secrets); nothing is written to the filesystem.

const COMMANDS = {
  web: { cwd: "/app/web", args: ["server.js"] },
  worker: { cwd: "/app/console", args: ["--import", "tsx", "src/worker/index.ts"] },
  migrate: { cwd: "/app/console", args: ["--import", "tsx", "src/db/migrate.ts"] },
  "bootstrap-admin": { cwd: "/app/console", args: ["--import", "tsx", "src/cli/bootstrap-admin.ts"] },
};

const name = process.argv[2] ?? "web";
if (!Object.hasOwn(COMMANDS, name)) {
  process.stderr.write("usage: entrypoint web|worker|migrate|bootstrap-admin\n");
  process.exit(64);
}
const { cwd, args } = COMMANDS[name];
process.chdir(cwd);
process.execve(process.execPath, [process.execPath, ...args], process.env);
