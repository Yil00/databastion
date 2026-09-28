CREATE TYPE "public"."notification_channel_type" AS ENUM('email', 'webhook');--> statement-breakpoint
CREATE TYPE "public"."notification_delivery_status" AS ENUM('pending', 'sending', 'delivered', 'failed', 'skipped');--> statement-breakpoint
CREATE TABLE "notification_channels" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"type" "notification_channel_type" NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"system_alerts" boolean DEFAULT false NOT NULL,
	"config" jsonb NOT NULL,
	"secret" "bytea",
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_by" uuid,
	CONSTRAINT "notification_channels_slug_format" CHECK ("notification_channels"."slug" ~ '^[a-z0-9][a-z0-9_.-]{0,62}$')
);
--> statement-breakpoint
CREATE TABLE "notification_deliveries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"idempotency_key" text NOT NULL,
	"event" text NOT NULL,
	"channel_id" uuid,
	"channel_slug" text NOT NULL,
	"incident_id" uuid,
	"agent_id" uuid,
	"security_event_id" uuid,
	"payload" jsonb NOT NULL,
	"status" "notification_delivery_status" DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"next_attempt_at" timestamp with time zone DEFAULT now() NOT NULL,
	"lease_until" timestamp with time zone,
	"last_attempt_at" timestamp with time zone,
	"delivered_at" timestamp with time zone,
	"last_error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "notification_deliveries_attempts" CHECK ("notification_deliveries"."attempts" >= 0),
	CONSTRAINT "notification_deliveries_last_error_format" CHECK ("notification_deliveries"."last_error" ~ '^[a-z0-9_]{1,64}$')
);
--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "silence_alerted_for" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_channel_id_notification_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."notification_channels"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_security_event_id_security_events_id_fk" FOREIGN KEY ("security_event_id") REFERENCES "public"."security_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "notification_channels_slug_key" ON "notification_channels" USING btree ("slug");--> statement-breakpoint
CREATE UNIQUE INDEX "notification_deliveries_idempotency_key" ON "notification_deliveries" USING btree ("idempotency_key");--> statement-breakpoint
CREATE INDEX "notification_deliveries_due_idx" ON "notification_deliveries" USING btree ("next_attempt_at") WHERE "notification_deliveries"."status" in ('pending', 'sending');--> statement-breakpoint
CREATE INDEX "notification_deliveries_incident_idx" ON "notification_deliveries" USING btree ("incident_id");