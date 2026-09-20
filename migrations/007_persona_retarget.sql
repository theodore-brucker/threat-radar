-- 007_persona_retarget.sql  (2026-08-26)
--
-- Both surviving views were keyed to a retired persona and would silently
-- report zero once the paths and accounts behind it were gone.
--
-- v_cred_attempts: cred_tier tested usernames against a hardcoded list of
-- accounts from the previous persona. Retargeted to GPU and HPC compute
-- accounts. Note the meaning has changed: build_userdb.py's PERSONA list is
-- now empty, so nothing is planted, and this tier therefore measures
-- UNSOLICITED targeting of compute accounts rather than hits on lures we
-- advertised. A near-zero reading is a real result.
--
-- v_daily_activity: dropped. Its lure_cmds column counted commands against a
-- path that no longer exists, and nothing in app/ reads it.

DROP VIEW IF EXISTS v_daily_activity;
DROP VIEW IF EXISTS v_cred_attempts;

CREATE VIEW v_cred_attempts AS
SELECT
    r.ts,
    r.src_ip,
    r.session,
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
FROM raw_events r
WHERE r.eventid IN ('cowrie.login.success','cowrie.login.failed');
