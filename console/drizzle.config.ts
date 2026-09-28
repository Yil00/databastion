import { defineConfig } from "drizzle-kit";

// `drizzle-kit generate` only diffs src/db/schema.ts against drizzle/meta and
// does not need a database. Migrations are applied by `pnpm db:migrate`
// (src/db/migrate.ts), which reads DATABASE_URL / DATABASE_URL_FILE.
export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  strict: true,
  verbose: true,
});
