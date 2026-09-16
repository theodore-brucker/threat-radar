-- 005_exec.sql
-- Outage bookkeeping. A period-over-period trend is a lie if the baseline
-- includes days the sensor was not working, so those days are named here and
-- excluded from every comparison rather than quietly averaged in.

CREATE TABLE IF NOT EXISTS outage_windows (
  start_day  TEXT NOT NULL,
  end_day    TEXT NOT NULL,
  scope      TEXT NOT NULL DEFAULT 'auth',   -- auth | ingest | all
  reason     TEXT,
  created_at TEXT,
  PRIMARY KEY (start_day, scope)
);

INSERT OR IGNORE INTO outage_windows(start_day, end_day, scope, reason, created_at)
VALUES ('2026-07-31', '2026-08-17', 'auth',
        'userdb.txt contained an empty password field; Cowrie auth.py raised IndexError on every authentication attempt, so no logins, commands or captures were recorded. Connections were still logged.',
        '2026-08-17');
