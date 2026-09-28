CREATE TABLE "findings" (
	"id" uuid PRIMARY KEY NOT NULL,
	"agent_id" uuid NOT NULL,
	"target_id" text NOT NULL,
	"location_key" text NOT NULL,
	"engine" text NOT NULL,
	"database_name" text NOT NULL,
	"schema_name" text,
	"object_name" text NOT NULL,
	"field_name" text NOT NULL,
	"classifier" text NOT NULL,
	"classifiers_version" text NOT NULL,
	"confidence" double precision NOT NULL,
	"sampled" integer NOT NULL,
	"matched" integer NOT NULL,
	"estimated_rows" bigint,
	"masked_samples" "bytea",
	"fingerprints" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"first_job_id" uuid,
	"last_job_id" uuid,
	"last_batch_id" uuid NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"false_positive_at" timestamp with time zone,
	"false_positive_by" uuid,
	CONSTRAINT "findings_confidence_range" CHECK ("findings"."confidence" >= 0 and "findings"."confidence" <= 1),
	CONSTRAINT "findings_counts" CHECK ("findings"."matched" >= 0 and "findings"."matched" <= "findings"."sampled" and "findings"."sampled" <= 10000),
	CONSTRAINT "findings_location_key_format" CHECK ("findings"."location_key" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
CREATE TABLE "findings_batches" (
	"agent_id" uuid NOT NULL,
	"batch_id" uuid NOT NULL,
	"body_sha256" text NOT NULL,
	"job_id" uuid,
	"findings_count" integer NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "findings_batches_agent_id_batch_id_pk" PRIMARY KEY("agent_id","batch_id"),
	CONSTRAINT "findings_batches_sha256_format" CHECK ("findings_batches"."body_sha256" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_first_job_id_jobs_id_fk" FOREIGN KEY ("first_job_id") REFERENCES "public"."jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_last_job_id_jobs_id_fk" FOREIGN KEY ("last_job_id") REFERENCES "public"."jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_false_positive_by_users_id_fk" FOREIGN KEY ("false_positive_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_agent_target_fk" FOREIGN KEY ("agent_id","target_id") REFERENCES "public"."agent_targets"("agent_id","target_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings_batches" ADD CONSTRAINT "findings_batches_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings_batches" ADD CONSTRAINT "findings_batches_job_id_jobs_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "findings_location_key" ON "findings" USING btree ("agent_id","location_key");--> statement-breakpoint
CREATE INDEX "findings_target_classifier_idx" ON "findings" USING btree ("agent_id","target_id","classifier");--> statement-breakpoint
CREATE INDEX "findings_classifier_idx" ON "findings" USING btree ("classifier");--> statement-breakpoint
CREATE INDEX "findings_batches_job_idx" ON "findings_batches" USING btree ("job_id");