CREATE TYPE "public"."session_method" AS ENUM('local', 'oidc');--> statement-breakpoint
CREATE TABLE "oidc_consumed_states" (
	"state_hash" text PRIMARY KEY NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "oidc_pending_logins" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"issuer" text NOT NULL,
	"subject" text NOT NULL,
	"login" text,
	"email" text,
	"email_verified" boolean DEFAULT false NOT NULL,
	"display_name" text,
	"groups" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"mapped_role" "user_role",
	"attempts" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_attempt_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "oidc_pending_logins_attempts" CHECK ("oidc_pending_logins"."attempts" >= 1)
);
--> statement-breakpoint
CREATE TABLE "user_identities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"issuer" text NOT NULL,
	"subject" text NOT NULL,
	"email" text,
	"email_verified" boolean,
	"display_name" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_login_at" timestamp with time zone,
	CONSTRAINT "user_identities_issuer_len" CHECK (char_length("user_identities"."issuer") between 1 and 2048),
	CONSTRAINT "user_identities_subject_len" CHECK (char_length("user_identities"."subject") between 1 and 255)
);
--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "password_hash" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "method" "session_method" DEFAULT 'local' NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "identity_id" uuid;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "provider_sid" text;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "refresh_token_enc" "bytea";--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "refreshed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "sso_only" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "user_identities" ADD CONSTRAINT "user_identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "oidc_consumed_states_expires_idx" ON "oidc_consumed_states" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "oidc_pending_logins_issuer_subject_key" ON "oidc_pending_logins" USING btree ("issuer","subject");--> statement-breakpoint
CREATE INDEX "oidc_pending_logins_last_attempt_idx" ON "oidc_pending_logins" USING btree ("last_attempt_at");--> statement-breakpoint
CREATE UNIQUE INDEX "user_identities_issuer_subject_key" ON "user_identities" USING btree ("issuer","subject");--> statement-breakpoint
CREATE UNIQUE INDEX "user_identities_user_issuer_key" ON "user_identities" USING btree ("user_id","issuer");--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_identity_id_user_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."user_identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_provider_sid_len" CHECK ("sessions"."provider_sid" is null or char_length("sessions"."provider_sid") between 1 and 255);--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_oidc_identity" CHECK (("sessions"."method" = 'oidc') = ("sessions"."identity_id" is not null));--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_password_hash_local" CHECK ("users"."password_hash" is not null or "users"."sso_only");