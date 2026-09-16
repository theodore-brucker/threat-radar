-- 008_excluded_sources.sql  (2026-08-26)
--
-- Operator testing is indistinguishable from attacker traffic once it is in
-- raw_events, and on 2026-08-24 it produced a false positive that reached the
-- findings log: manual verification of the honeyfs build was recorded as
-- attackers reading the AWS canarytoken and probing for NVIDIA hardware.
--
-- Events are kept, not deleted. Analysis reads v_events instead of raw_events.

CREATE TABLE IF NOT EXISTS excluded_sources (
  ip        TEXT PRIMARY KEY,
  reason    TEXT NOT NULL,
  added_at  TEXT NOT NULL
);

INSERT OR REPLACE INTO excluded_sources VALUES
  ('23.244.44.199',
   'Operator testing from home ISP (AS11776 Breezeline, Columbus). Verified '
   || '2026-08-26. 226 events across 2026-07-30, 08-17 and 08-24, including the '
   || 'honeyfs canarytoken checks and the lspci persona verification.',
   '2026-08-26T13:00:00Z');

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
