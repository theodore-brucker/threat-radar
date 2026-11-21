-- 018_eastern_days.sql  (2026-11-21)
--
-- Per-day tables are now keyed by US Eastern day (app/analytics/clock.py)
-- instead of UTC day. Rows built under UTC days are removed once, and the
-- next worker pass rebuilds them from raw events under Eastern days.
--
-- Only days that raw events still cover are removed, so a day the age prune
-- has already taken out of raw_events keeps its UTC-day row instead of
-- being lost. The insights_state key day_zone marks the change as done,
-- so later runs of this file delete nothing.

DELETE FROM asn_ip_daily
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM eventid_daily
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM session_facts
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM tunnel_targets
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM cred_pair_daily
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM payload_daily
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM source_stage_daily
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM client_fp_daily
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM cred_ip_daily
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM hassh_ip_daily
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

DELETE FROM spike_annotations
 WHERE NOT EXISTS (SELECT 1 FROM insights_state WHERE key = 'day_zone')
   AND day >= (SELECT CASE WHEN typeof(MIN(ts)) IN ('real','integer')
             THEN date(MIN(ts), 'unixepoch') ELSE substr(MIN(ts), 1, 10) END
   FROM raw_events);

INSERT OR IGNORE INTO insights_state(key, value, updated_at)
VALUES ('day_zone', 'America/New_York', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
