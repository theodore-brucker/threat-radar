-- 006_windowing.sql
-- Per-day fact tables for the three surfaces that were still reading lifetime
-- aggregates. Without these the time-window selector changes which rows appear
-- but not the numbers on them, which is what made the control feel dead.

CREATE TABLE IF NOT EXISTS cred_pair_daily (
  day       TEXT NOT NULL,
  username  TEXT NOT NULL DEFAULT '',
  password  TEXT NOT NULL DEFAULT '',
  attempts  INTEGER NOT NULL DEFAULT 0,
  successes INTEGER NOT NULL DEFAULT 0,
  src_ips   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, username, password)
);
CREATE INDEX IF NOT EXISTS idx_cred_daily_day ON cred_pair_daily(day);

CREATE TABLE IF NOT EXISTS payload_daily (
  day       TEXT NOT NULL,
  shasum    TEXT NOT NULL DEFAULT '',
  url       TEXT NOT NULL DEFAULT '',
  direction TEXT NOT NULL,
  host      TEXT,
  filename  TEXT,
  hits      INTEGER NOT NULL DEFAULT 0,
  sessions  INTEGER NOT NULL DEFAULT 0,
  src_ips   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, shasum, url, direction)
);
CREATE INDEX IF NOT EXISTS idx_payload_daily_day ON payload_daily(day);

CREATE TABLE IF NOT EXISTS source_stage_daily (
  day       TEXT NOT NULL,
  src_ip    TEXT NOT NULL,
  stage     INTEGER NOT NULL DEFAULT 0,
  sessions  INTEGER NOT NULL DEFAULT 0,
  commands  INTEGER NOT NULL DEFAULT 0,
  transfers INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, src_ip)
);
CREATE INDEX IF NOT EXISTS idx_stage_daily_day ON source_stage_daily(day);
