CREATE TYPE "public"."agent_status" AS ENUM('enrolled', 'online', 'revoked', 'locked');--> statement-breakpoint
CREATE TYPE "public"."audit_level" AS ENUM('full', 'partial', 'limited', 'none');--> statement-breakpoint
CREATE TYPE "public"."job_status" AS ENUM('pending', 'delivered', 'running', 'succeeded', 'failed', 'expired', 'cancelled');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('admin', 'analyst');--> statement-breakpoint
CREATE TABLE "agent_targets" (
	"agent_id" uuid NOT NULL,
	"target_id" text NOT NULL,
	"engine" text NOT NULL,
	"edition" text,
	"server_version" text,
	"reachable" boolean NOT NULL,
	"audit_level" "audit_level" NOT NULL,
	"audit_source" text,
	"last_error" text,
	"metrics" jsonb,
	"present" boolean DEFAULT true NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_reported_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agent_targets_agent_id_target_id_pk" PRIMARY KEY("agent_id","target_id")
);
--> statement-breakpoint
CREATE TABLE "agents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"hostname" text NOT NULL,
	"version" text NOT NULL,
	"os" text,
	"arch" text,
	"connectors" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"classifiers_version" text,
	"status" "agent_status" DEFAULT 'enrolled' NOT NULL,
	"enrolled_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone,
	"uptime_s" integer,
	"clock_skew_ms" integer,
	"spool" jsonb,
	"metrics" jsonb,
	"detected_targets" jsonb,
	"current_secret_hash" text,
	"pending_secret_hash" text,
	"grace_expires_at" timestamp with time zone,
	"previous_secret_hash" text,
	"promoted_at" timestamp with time zone,
	"locked_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoked_by" uuid
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"at" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_type" text NOT NULL,
	"actor_id" text,
	"action" text NOT NULL,
	"outcome" text DEFAULT 'success' NOT NULL,
	"target_type" text,
	"target_id" text,
	"source_ip" text,
	"details" jsonb
);
--> statement-breakpoint
CREATE TABLE "enrollment_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"token_hash" text NOT NULL,
	"label" text,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"consumed_by_agent_id" uuid,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"agent_id" uuid NOT NULL,
	"type" text NOT NULL,
	"target_id" text,
	"classifiers_version" text,
	"params" jsonb NOT NULL,
	"status" "job_status" DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"lease_until" timestamp with time zone,
	"attempts" integer DEFAULT 0 NOT NULL,
	"delivered_at" timestamp with time zone,
	"last_status_at" timestamp with time zone,
	"progress" jsonb,
	"error" jsonb,
	"finished_at" timestamp with time zone,
	"created_by" uuid
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"username" text NOT NULL,
	"password_hash" text NOT NULL,
	"role" "user_role" DEFAULT 'analyst' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"disabled_at" timestamp with time zone,
	"last_login_at" timestamp with time zone,
	CONSTRAINT "users_username_len" CHECK (char_length("users"."username") between 1 and 64)
);
--> statement-breakpoint
ALTER TABLE "agent_targets" ADD CONSTRAINT "agent_targets_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agents" ADD CONSTRAINT "agents_revoked_by_users_id_fk" FOREIGN KEY ("revoked_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enrollment_tokens" ADD CONSTRAINT "enrollment_tokens_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enrollment_tokens" ADD CONSTRAINT "enrollment_tokens_consumed_by_agent_id_agents_id_fk" FOREIGN KEY ("consumed_by_agent_id") REFERENCES "public"."agents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "agents_status_idx" ON "agents" USING btree ("status");--> statement-breakpoint
CREATE INDEX "audit_log_at_idx" ON "audit_log" USING btree ("at");--> statement-breakpoint
CREATE INDEX "audit_log_action_idx" ON "audit_log" USING btree ("action");--> statement-breakpoint
CREATE UNIQUE INDEX "enrollment_tokens_token_hash_key" ON "enrollment_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "jobs_agent_status_idx" ON "jobs" USING btree ("agent_id","status","created_at");--> statement-breakpoint
CREATE INDEX "sessions_user_id_idx" ON "sessions" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "users_username_key" ON "users" USING btree ("username");