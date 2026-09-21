-- 014_drop_redundant_index.sql  (2026-09-21)
--
-- idx_events_eventid indexed raw_events(eventid), which is the leading column
-- of idx_raw_eventid_ts (eventid, ts) from migration 003, so every lookup it
-- could serve the composite index serves as well. It cost 31 MB and one extra
-- index write on every event ingested. schema.sql stopped creating it in the
-- same change; without that, ingest would recreate it on its next start.

DROP INDEX IF EXISTS idx_events_eventid;
