-- 008_excluded_sources.sql  (2026-08-26)
--
-- Operator testing is indistinguishable from attacker traffic once it is in
-- raw_events, and leaving it in produced a false positive in the findings log.
-- Addresses to exclude are operator-specific, so they are not committed here.
-- The intel worker loads them from the file named by TR_EXCLUDED_SOURCES
-- (default /etc/threat-radar/excluded_sources.txt) after migrations run.
--
-- Events are kept, not deleted. Analysis reads v_events instead of raw_events.

CREATE TABLE IF NOT EXISTS excluded_sources (
  ip        TEXT PRIMARY KEY,
  reason    TEXT NOT NULL,
  added_at  TEXT NOT NULL
);

DROP VIEW IF EXISTS v_events;
CREATE VIEW v_events AS
SELECT * FROM raw_events
WHERE src_ip NOT IN (SELECT ip FROM excluded_sources);

DROP VIEW IF EXISTS v_cred_attempts;
CREATE VIEW v_cred_attempts AS
SELECT
    r.ts, r.src_ip, r.session,
    json_extract(r.payload, '$.username')  AS username,
    json_extract(r.payload, '$.password')  AS password,
    r.eventid = 'cowrie.login.success'     AS succeeded,
    CASE
        WHEN lower(json_extract(r.payload, '$.username')) IN
             ('gpu','gpuadmin','gpuuser','cuda','nvidia','ml','mlops','mluser',
              'hpc','slurm','pbs','torque','render','sim','simulation',
              'compute','cluster','ansys','abaqus','matlab','comsol',
              'engineer','engineering','cae','cad','fea','trainer')
             THEN 'persona'
        WHEN lower(json_extract(r.payload, '$.username')) IN
             ('ubuntu','deploy','deployer','docker','jenkins','runner',
              'builder','ansible','terraform','gitlab','ci','build','svc',
              'service','operator')
             THEN 'adjacent'
        ELSE 'generic'
    END                                    AS cred_tier
FROM v_events r
WHERE r.eventid IN ('cowrie.login.success','cowrie.login.failed');
