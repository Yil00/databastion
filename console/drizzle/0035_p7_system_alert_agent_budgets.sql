CREATE TABLE "system_alert_agent_budgets" (
	"channel_id" uuid NOT NULL,
	"agent_id" uuid NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"sent" integer NOT NULL,
	CONSTRAINT "system_alert_agent_budgets_channel_id_agent_id_window_start_pk" PRIMARY KEY("channel_id","agent_id","window_start"),
	CONSTRAINT "system_alert_agent_budgets_sent" CHECK ("system_alert_agent_budgets"."sent" >= 0)
);
--> statement-breakpoint
ALTER TABLE "system_alert_agent_budgets" ADD CONSTRAINT "system_alert_agent_budgets_channel_id_notification_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."notification_channels"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "system_alert_agent_budgets_window_idx" ON "system_alert_agent_budgets" USING btree ("window_start");