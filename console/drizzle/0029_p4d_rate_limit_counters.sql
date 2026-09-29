CREATE TABLE "rate_limit_counters" (
	"limiter" text NOT NULL,
	"key_hash" text NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"count" integer NOT NULL,
	CONSTRAINT "rate_limit_counters_limiter_key_hash_pk" PRIMARY KEY("limiter","key_hash"),
	CONSTRAINT "rate_limit_counters_limiter_format" CHECK ("rate_limit_counters"."limiter" ~ '^[a-z0-9_.]{1,64}$'),
	CONSTRAINT "rate_limit_counters_key_hash_format" CHECK ("rate_limit_counters"."key_hash" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "rate_limit_counters_count" CHECK ("rate_limit_counters"."count" >= 0),
	CONSTRAINT "rate_limit_counters_window" CHECK ("rate_limit_counters"."expires_at" > "rate_limit_counters"."window_start")
);
--> statement-breakpoint
CREATE INDEX "rate_limit_counters_expires_idx" ON "rate_limit_counters" USING btree ("expires_at");