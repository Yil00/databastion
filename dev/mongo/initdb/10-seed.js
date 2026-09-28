// Runs once on an empty data directory (mongo entrypoint, before authentication is enabled).
// Loads dev/seed/out/mongo.json into the `app` database and creates the read-only account from
// docs/05-security.md (`read` on the targeted database + `clusterMonitor`).
const fs = require("fs");
const seed = JSON.parse(fs.readFileSync("/seed/mongo.json", "utf8"));
const app = db.getSiblingDB("app");
for (const [name, docs] of Object.entries(seed.collections)) {
  app.getCollection(name).insertMany(docs);
}
db.getSiblingDB("admin").createUser({
  user: "databastion",
  pwd: process.env.DATABASTION_DB_PASSWORD,
  roles: [{ role: "read", db: "app" }, { role: "clusterMonitor", db: "admin" }],
});
