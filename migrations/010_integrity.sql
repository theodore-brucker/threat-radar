-- 010_integrity.sql  (2026-09-14)
--
-- Persona epochs. The sensor has presented three different hosts over its
-- life, and a chart that runs straight across those boundaries is comparing
-- separate experiments. The file-transfer persona and the compute-node persona
-- drew different scanning populations. A change in login
-- attempts across 2026-08-24 says more about which host we advertised than
-- about attacker behaviour.
--
-- Same shape as outage_windows: named here, drawn on the chart, and used to
-- warn when a period-over-period comparison straddles a boundary.

CREATE TABLE IF NOT EXISTS persona_epochs (
  start_day  TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  note       TEXT,
  created_at TEXT
);

INSERT OR IGNORE INTO persona_epochs(start_day, name, note, created_at) VALUES
  ('2026-07-31', 'File-transfer relay',
   'Sensor presented a managed-file-transfer relay persona. '
   || 'Before this date the sensor ran a stock '
   || 'Cowrie profile, which commodity scanners fingerprint and filter.',
   '2026-09-14'),
  ('2026-08-24', 'Compute node',
   'Sensor presents a GPU compute node persona. '
   || 'Credential tiers, honeyfs and lspci output all changed with '
   || 'it, so counts either side of this day are not the same measurement.',
   '2026-09-14');
