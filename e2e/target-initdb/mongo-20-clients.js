// Runs once, after dev's 10-seed.js (the seed and the agent's ADR-0026 account), on the mongo
// entrypoint's initialization server (no authentication yet): the Audit test accounts of the e2e
// harness, used from the separate mongo-client container, never the agent's account.
// e2e_exporter runs mongodump, e2e_analyst runs queries whose filters hold ground-truth literals.
// Built-in `read` on the seeded `app` database only (mongodump --db app needs find,
// listCollections and listIndexes); SCRAM-SHA-256. The password is read from the Docker secret
// file here, never on a command line nor in the environment.
const fs = require("fs");
const pwd = fs.readFileSync("/run/secrets/client_password", "utf8");
if (!pwd) throw new Error("empty client password");
const admin = db.getSiblingDB("admin");
for (const user of ["e2e_exporter", "e2e_analyst"]) {
  admin.createUser({
    user,
    pwd,
    mechanisms: ["SCRAM-SHA-256"],
    roles: [{ role: "read", db: "app" }],
  });
}
