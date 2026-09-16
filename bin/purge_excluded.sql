-- purge_excluded.sql
--
-- Derived tables are accumulative, so excluding a source from v_events does not
-- remove it from anything already rolled up. Run this after adding a row to
-- excluded_sources, and after any intel_worker run that rebuilt only recent
-- days. Idempotent.
--
--   sudo -u radar sqlite3 /opt/threat-radar/data/radar.db < bin/purge_excluded.sql

DELETE FROM sources            WHERE ip     IN (SELECT ip FROM excluded_sources);
DELETE FROM source_stage       WHERE src_ip IN (SELECT ip FROM excluded_sources);
DELETE FROM source_stage_daily WHERE src_ip IN (SELECT ip FROM excluded_sources);
DELETE FROM session_facts      WHERE src_ip IN (SELECT ip FROM excluded_sources);
DELETE FROM asn_ip_daily       WHERE src_ip IN (SELECT ip FROM excluded_sources);
DELETE FROM payload_sightings  WHERE src_ip IN (SELECT ip FROM excluded_sources);
DELETE FROM cred_tag_ips       WHERE src_ip IN (SELECT ip FROM excluded_sources);
-- Added with the entity rollups (3.1); both are keyed by src_ip.
DELETE FROM cred_ip_daily      WHERE src_ip IN (SELECT ip FROM excluded_sources);
DELETE FROM hassh_ip_daily     WHERE src_ip IN (SELECT ip FROM excluded_sources);

-- What this cannot fix: cred_pair_daily, payload_daily, eventid_daily and
-- client_fp_daily aggregate without src_ip, so an excluded source's
-- contribution to them can only be removed by rebuilding those days from
-- v_events. That works while the raw events survive; once they age past
-- TR_RETAIN_DAYS the day cannot be rebuilt and its totals keep whatever the
-- excluded source contributed. Exclude sources promptly.
