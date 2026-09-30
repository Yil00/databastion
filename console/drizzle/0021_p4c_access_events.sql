ALTER TYPE "public"."policy_source" ADD VALUE 'access_event';--> statement-breakpoint
CREATE TABLE "access_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"agent_id" uuid NOT NULL,
	"target_id" text NOT NULL,
	"batch_id" uuid NOT NULL,
	"item_index" integer NOT NULL,
	"ts" timestamp with time zone NOT NULL,
	"ts_last" timestamp with time zone,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"principal_key" text NOT NULL,
	"db_user" text,
	"db_user_fingerprint" text,
	"client_addr" text,
	"application" text,
	"action" text NOT NULL,
	"objects" jsonb NOT NULL,
	"rows" bigint,
	"signals" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"source" text NOT NULL,
	"aggregated_count" integer NOT NULL,
	"evaluated_at" timestamp with time zone,
	"sensitivity" double precision,
	"score" double precision,
	"anomaly" boolean,
	"baseline_rows" double precision,
	CONSTRAINT "access_events_principal" CHECK (("access_events"."db_user" is null) <> ("access_events"."db_user_fingerprint" is null)),
	CONSTRAINT "access_events_principal_key_format" CHECK ("access_events"."principal_key" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "access_events_action" CHECK ("access_events"."action" in ('connect', 'auth_failure', 'read', 'write', 'ddl', 'dcl')),
	CONSTRAINT "access_events_counts" CHECK ("access_events"."aggregated_count" >= 1 and ("access_events"."rows" is null or "access_events"."rows" >= 0))
);
--> statement-breakpoint
CREATE TABLE "audit_configs" (
	"agent_id" uuid NOT NULL,
	"target_id" text NOT NULL,
	"enabled" boolean NOT NULL,
	"aggregation_window_s" integer NOT NULL,
	"poll_interval_s" integer NOT NULL,
	"min_rows" bigint,
	"derive_from_findings" boolean DEFAULT true NOT NULL,
	"manual_objects" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"sent_objects" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"last_job_id" uuid,
	"warning" text,
	"warning_removed" integer,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_by" uuid,
	CONSTRAINT "audit_configs_agent_id_target_id_pk" PRIMARY KEY("agent_id","target_id"),
	CONSTRAINT "audit_configs_warning" CHECK ("audit_configs"."warning" is null or "audit_configs"."warning" in ('emptied', 'shrunk', 'disabled'))
);
--> statement-breakpoint
CREATE TABLE "events_batches" (
	"agent_id" uuid NOT NULL,
	"batch_id" uuid NOT NULL,
	"body_sha256" text NOT NULL,
	"events_count" integer NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "events_batches_agent_id_batch_id_pk" PRIMARY KEY("agent_id","batch_id"),
	CONSTRAINT "events_batches_sha256_format" CHECK ("events_batches"."body_sha256" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
CREATE TABLE "incident_events" (
	"incident_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "incident_events_incident_id_event_id_pk" PRIMARY KEY("incident_id","event_id")
);
--> statement-breakpoint
CREATE TABLE "principal_baselines" (
	"agent_id" uuid NOT NULL,
	"target_id" text NOT NULL,
	"principal_key" text NOT NULL,
	"db_user" text,
	"db_user_fingerprint" text,
	"events" bigint DEFAULT 0 NOT NULL,
	"mean_log_rows" double precision DEFAULT 0 NOT NULL,
	"var_log_rows" double precision DEFAULT 0 NOT NULL,
	"mean_log_score" double precision DEFAULT 0 NOT NULL,
	"var_log_score" double precision DEFAULT 0 NOT NULL,
	"rows_total" double precision DEFAULT 0 NOT NULL,
	"max_score" double precision DEFAULT 0 NOT NULL,
	"anomalies" bigint DEFAULT 0 NOT NULL,
	"first_event_at" timestamp with time zone,
	"last_event_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "principal_baselines_agent_id_target_id_principal_key_pk" PRIMARY KEY("agent_id","target_id","principal_key"),
	CONSTRAINT "principal_baselines_principal_key_format" CHECK ("principal_baselines"."principal_key" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "principal_baselines_counts" CHECK ("principal_baselines"."events" >= 0 and "principal_baselines"."anomalies" >= 0 and "principal_baselines"."var_log_rows" >= 0 and "principal_baselines"."var_log_score" >= 0)
);
--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "access_event_id" uuid;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "principal" text;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "event_database" text;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "event_bucket" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "event_score" double precision;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "event_rows" double precision;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "event_signals" jsonb;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "last_event_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "access_events" ADD CONSTRAINT "access_events_agent_target_fk" FOREIGN KEY ("agent_id","target_id") REFERENCES "public"."agent_targets"("agent_id","target_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_configs" ADD CONSTRAINT "audit_configs_last_job_id_jobs_id_fk" FOREIGN KEY ("last_job_id") REFERENCES "public"."jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_configs" ADD CONSTRAINT "audit_configs_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_configs" ADD CONSTRAINT "audit_configs_agent_target_fk" FOREIGN KEY ("agent_id","target_id") REFERENCES "public"."agent_targets"("agent_id","target_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "events_batches" ADD CONSTRAINT "events_batches_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_event_id_access_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."access_events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "principal_baselines" ADD CONSTRAINT "principal_baselines_agent_target_fk" FOREIGN KEY ("agent_id","target_id") REFERENCES "public"."agent_targets"("agent_id","target_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "access_events_ts_idx" ON "access_events" USING btree ("ts");--> statement-breakpoint
CREATE INDEX "access_events_target_ts_idx" ON "access_events" USING btree ("agent_id","target_id","ts");--> statement-breakpoint
CREATE INDEX "access_events_principal_ts_idx" ON "access_events" USING btree ("agent_id","target_id","principal_key","ts");--> statement-breakpoint
CREATE INDEX "access_events_signals_idx" ON "access_events" USING gin ("signals");--> statement-breakpoint
CREATE INDEX "access_events_pending_idx" ON "access_events" USING btree ("received_at","id") WHERE "access_events"."evaluated_at" is null;--> statement-breakpoint
CREATE INDEX "events_batches_received_idx" ON "events_batches" USING btree ("received_at");--> statement-breakpoint
CREATE INDEX "incident_events_event_idx" ON "incident_events" USING btree ("event_id");--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_access_event_id_access_events_id_fk" FOREIGN KEY ("access_event_id") REFERENCES "public"."access_events"("id") ON DELETE set null ON UPDATE no action;