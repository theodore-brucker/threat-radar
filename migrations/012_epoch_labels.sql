-- 012_epoch_labels.sql  (2026-09-16)
--
-- Relabels persona epochs seeded by 010 before its wording was generalised.
-- 010 inserts with OR IGNORE, so a database that already holds the old rows
-- keeps the old labels until this runs. Hostnames and sector detail were
-- dropped from the public labels because they identify the live sensor.
-- Idempotent: the worker runs every migration on every pass.

UPDATE persona_epochs
   SET name = 'File-transfer relay',
       note = 'Sensor presented a managed-file-transfer relay persona. '
           || 'Before this date the sensor ran a stock Cowrie profile, which '
           || 'commodity scanners fingerprint and filter.'
 WHERE start_day = '2026-07-31' AND name <> 'File-transfer relay';

UPDATE persona_epochs
   SET name = 'Compute node',
       note = 'Sensor presents a GPU compute node persona. Credential tiers, '
           || 'honeyfs and lspci output all changed with it, so counts either '
           || 'side of this day are not the same measurement.'
 WHERE start_day = '2026-08-24' AND name <> 'Compute node';
