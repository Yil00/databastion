CREATE TYPE "public"."incident_severity" AS ENUM('low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."incident_status" AS ENUM('open', 'acknowledged', 'resolved', 'false_positive');--> statement-breakpoint
CREATE TYPE "public"."policy_source" AS ENUM('finding');--> statement-breakpoint
CREATE TABLE "incidents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"dedup_key" text NOT NULL,
	"source" "policy_source" NOT NULL,
	"policy_id" uuid,
	"policy_name" text NOT NULL,
	"policy_revision" integer NOT NULL,
	"severity" "incident_severity" NOT NULL,
	"status" "incident_status" DEFAULT 'open' NOT NULL,
	"notify_channels" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"finding_id" uuid,
	"agent_id" uuid,
	"target_id" text,
	"classifier" text,
	"finding_matched" integer,
	"finding_classifiers_version" text,
	"last_finding_seen_at" timestamp with time zone,
	"match_count" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"acknowledged_at" timestamp with time zone,
	"acknowledged_by" uuid,
	"resolved_at" timestamp with time zone,
	"resolved_by" uuid,
	"false_positive_at" timestamp with time zone,
	"false_positive_by" uuid,
	CONSTRAINT "incidents_policy_name_len" CHECK (char_length("incidents"."policy_name") between 1 and 100),
	CONSTRAINT "incidents_match_count" CHECK ("incidents"."match_count" >= 1)
);
--> statement-breakpoint
CREATE TABLE "policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"source" "policy_source" DEFAULT 'finding' NOT NULL,
	"conditions" jsonb NOT NULL,
	"actions" jsonb NOT NULL,
	"revision" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_by" uuid,
	"changed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"evaluated_at" timestamp with time zone,
	CONSTRAINT "policies_name_len" CHECK (char_length("policies"."name") between 1 and 100),
	CONSTRAINT "policies_description_len" CHECK (char_length("policies"."description") <= 500),
	CONSTRAINT "policies_revision_positive" CHECK ("policies"."revision" >= 1)
);
--> statement-breakpoint
CREATE TABLE "policy_exceptions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"policy_id" uuid,
	"agent_id" uuid,
	"target_id" text,
	"classifier" text,
	"location" jsonb,
	"reason" text NOT NULL,
	"expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid,
	CONSTRAINT "policy_exceptions_scope" CHECK ("policy_exceptions"."agent_id" is not null or "policy_exceptions"."target_id" is not null or "policy_exceptions"."classifier" is not null or "policy_exceptions"."location" is not null),
	CONSTRAINT "policy_exceptions_reason_len" CHECK (char_length("policy_exceptions"."reason") between 1 and 500)
);
--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "policy_evaluated_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_policy_id_policies_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."policies"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_acknowledged_by_users_id_fk" FOREIGN KEY ("acknowledged_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_resolved_by_users_id_fk" FOREIGN KEY ("resolved_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_false_positive_by_users_id_fk" FOREIGN KEY ("false_positive_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policies" ADD CONSTRAINT "policies_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policies" ADD CONSTRAINT "policies_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_exceptions" ADD CONSTRAINT "policy_exceptions_policy_id_policies_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."policies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_exceptions" ADD CONSTRAINT "policy_exceptions_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_exceptions" ADD CONSTRAINT "policy_exceptions_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "incidents_active_dedup_key" ON "incidents" USING btree ("dedup_key") WHERE "incidents"."status" in ('open', 'acknowledged');--> statement-breakpoint
CREATE INDEX "incidents_dedup_key_idx" ON "incidents" USING btree ("dedup_key","created_at");--> statement-breakpoint
CREATE INDEX "incidents_status_idx" ON "incidents" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "incidents_finding_idx" ON "incidents" USING btree ("finding_id");--> statement-breakpoint
CREATE UNIQUE INDEX "policies_name_key" ON "policies" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "policy_exceptions_policy_idx" ON "policy_exceptions" USING btree ("policy_id");--> statement-breakpoint
CREATE INDEX "findings_policy_pending_idx" ON "findings" USING btree ("id") WHERE "findings"."policy_evaluated_at" is distinct from "findings"."last_seen_at";