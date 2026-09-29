DROP INDEX "access_events_pending_idx";--> statement-breakpoint
ALTER TABLE "access_events" ADD COLUMN "unexpected_target" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "event_anomaly" boolean;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "event_overflow" boolean DEFAULT false NOT NULL;--> statement-breakpoint
CREATE INDEX "access_events_pending_idx" ON "access_events" USING btree ("agent_id","received_at","id") WHERE "access_events"."evaluated_at" is null;