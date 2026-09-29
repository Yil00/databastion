// Runs once on an empty data directory (mongo entrypoint, before authentication is enabled).
// Loads dev/seed/out/mongo.json into the `app` database and creates the agent account of
// ADR-0026 (docs/adr/0026-mongodb-connector.md): a custom role with `find` and `listCollections`
// on the `app` database only, SCRAM-SHA-256 credentials only. No `read` role (change streams,
// system.js), no `clusterMonitor` (other sessions' operations, system.profile of every database).
// Dev-only deviation: no `authenticationRestrictions`, since the agent connects through the
// published port and its source address is the Docker gateway.
// The agent password comes from DATABASTION_DB_PASSWORD (dev/.env) or, when
// DATABASTION_DB_PASSWORD_FILE is set, from that file as it is (the e2e harness passes a Docker
// secret, which then never is in the environment).
const fs = require("fs");
const agentPassword = process.env.DATABASTION_DB_PASSWORD_FILE
  ? fs.readFileSync(process.env.DATABASTION_DB_PASSWORD_FILE, "utf8")
  : process.env.DATABASTION_DB_PASSWORD;
if (!agentPassword) throw new Error("DATABASTION_DB_PASSWORD or DATABASTION_DB_PASSWORD_FILE is required");
const seed = JSON.parse(fs.readFileSync("/seed/mongo.json", "utf8"));
const app = db.getSiblingDB("app");
for (const [name, docs] of Object.entries(seed.collections)) {
  app.getCollection(name).insertMany(docs);
}
const admin = db.getSiblingDB("admin");
admin.createRole({
  role: "databastionDiscovery",
  privileges: [{ resource: { db: "app", collection: "" }, actions: ["find", "listCollections"] }],
  roles: [],
});
admin.createUser({
  user: "databastion",
  pwd: agentPassword,
  mechanisms: ["SCRAM-SHA-256"],
  roles: [{ role: "databastionDiscovery", db: "admin" }],
});
