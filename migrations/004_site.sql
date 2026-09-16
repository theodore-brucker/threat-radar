-- 004_site.sql
-- Site unification. Additive only, except that the persona views are dropped
-- at the end because their surface is retired and two of them cannot be
-- queried inside a request budget.

PRAGMA foreign_keys=OFF;

-- Per-source escalation stage, rebuilt every worker pass.
--   0 connected      1 authenticated      2 reached a shell
--   3 transferred a file                  4 transferred confirmed malware
CREATE TABLE IF NOT EXISTS source_stage (
  src_ip      TEXT PRIMARY KEY,
  stage       INTEGER NOT NULL DEFAULT 0,
  sessions    INTEGER NOT NULL DEFAULT 0,
  events      INTEGER NOT NULL DEFAULT 0,
  commands    INTEGER NOT NULL DEFAULT 0,
  transfers   INTEGER NOT NULL DEFAULT 0,
  malicious   INTEGER NOT NULL DEFAULT 0,
  first_seen  TEXT,
  last_seen   TEXT,
  asn         TEXT,
  org         TEXT,
  country     TEXT,
  lat         REAL,
  lon         REAL
);
CREATE INDEX IF NOT EXISTS idx_stage_rank ON source_stage(stage DESC, sessions DESC);

-- SSH client fingerprints per day, so the /sources panel never scans
-- raw_events at request time. This replaces v_client_hassh.
CREATE TABLE IF NOT EXISTS client_fp_daily (
  day        TEXT NOT NULL,
  hassh      TEXT NOT NULL,
  version    TEXT,
  events     INTEGER NOT NULL DEFAULT 0,
  sessions   INTEGER NOT NULL DEFAULT 0,
  src_ips    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, hassh)
);
CREATE INDEX IF NOT EXISTS idx_fp_hassh ON client_fp_daily(hassh);

-- Samples pushed upstream. One row per hash per service.
CREATE TABLE IF NOT EXISTS payload_submissions (
  sha256       TEXT NOT NULL,
  service      TEXT NOT NULL DEFAULT 'virustotal',
  status       TEXT NOT NULL,          -- submitted | duplicate | error | skipped
  analysis_id  TEXT,
  permalink    TEXT,
  detail       TEXT,
  size_bytes   INTEGER,
  submitted_at TEXT,
  PRIMARY KEY (sha256, service)
);
CREATE INDEX IF NOT EXISTS idx_submissions_when ON payload_submissions(submitted_at);

-- The persona surface is retired. The data behind it stays in raw_events;
-- only these query shims go away. v_daily_activity and v_cred_attempts are
-- kept because the credentials page still reads cred tiers from them.
DROP VIEW IF EXISTS v_client_hassh;
DROP VIEW IF EXISTS v_persona_scorecard;
DROP VIEW IF EXISTS v_persona_targeting;
DROP VIEW IF EXISTS v_top_sources;
DROP VIEW IF EXISTS v_session_profile;
DROP VIEW IF EXISTS v_lure_hits;
DROP VIEW IF EXISTS v_lure_files;
DROP VIEW IF EXISTS v_tunnel_abuse;
