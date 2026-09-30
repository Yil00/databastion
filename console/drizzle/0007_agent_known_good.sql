ALTER TABLE "agents" ADD COLUMN "known_good_fingerprint" text;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "known_good_at" timestamp with time zone;