import { pgTable, text, timestamp } from "drizzle-orm/pg-core";

/**
 * Console internal schema. Changes go through `pnpm db:generate`, which
 * writes a versioned SQL migration under drizzle/ (never edit the DB by hand).
 *
 * `meta` is a small key/value table for console-level metadata
 * (e.g. installation id, schema bootstrap markers). It must never hold
 * secrets or sensitive values.
 */
export const meta = pgTable("meta", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});
