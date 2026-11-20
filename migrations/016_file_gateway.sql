-- 016_file_gateway.sql  (2026-11-20)
--
-- The sensor presents a file-transfer gateway from 2026-11-20. Its epoch is
-- recorded by 017, which names the day the collector was cut over.
--
-- v_cred_attempts is redefined so the persona tier counts accounts a file
-- exchange host would plausibly hold. Nothing is planted for these names by
-- the userdb generator, so the tier measures unsolicited targeting of
-- file-transfer accounts. It replaces the compute-node list from 008, which
-- this file overrides because the worker applies migrations in order.

DROP VIEW IF EXISTS v_cred_attempts;
CREATE VIEW v_cred_attempts AS
SELECT
    r.ts, r.src_ip, r.session,
    json_extract(r.payload, '$.username')  AS username,
    json_extract(r.payload, '$.password')  AS password,
    r.eventid = 'cowrie.login.success'     AS succeeded,
    CASE
        WHEN lower(json_extract(r.payload, '$.username')) IN
             ('sftp','sftpuser','sftpadmin','ftp','ftpuser','ftpadmin','mft',
              'mftadmin','transfer','filetransfer','edi','as2','upload',
              'uploads','download','files','partner','partners','ach','wire',
              'wires','payment','payments','treasury','bank','banking',
              'finance','fin','swift','recon','batch','positivepay',
              'statements','remit')
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
