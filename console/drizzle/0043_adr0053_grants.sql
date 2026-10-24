-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name adr0053_grants` (ADR-0053). Every name is
-- schema-qualified.
--
-- The worker writes the bound sensitivity and score of each event with its other evaluation
-- columns (migration 0022: the runtime role may update only those, never what the agent reported,
-- `objects_overflowed` included), and keeps the flag and the highest bound score of the incidents
-- the events join, next to their other re-match columns (migrations 0016, 0022 and 0024).
GRANT UPDATE (bound_sensitivity, bound_score) ON TABLE public.access_events TO databastion_app;
--> statement-breakpoint
GRANT UPDATE (event_objects_overflowed, event_bound_score) ON TABLE public.incidents TO databastion_app;
