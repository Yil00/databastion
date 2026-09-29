ALTER TABLE "agents" ADD COLUMN "dropped_batches_unalerted" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "dropped_batches_since" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "dropped_batches_alerted_at" timestamp with time zone;