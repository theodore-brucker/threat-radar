-- 013_contributions.sql  (2026-09-20)
--
-- Two durable tables behind the contributions view. Both are append or
-- upsert only; the worker never deletes from them.
--
-- vt_snapshots keeps VirusTotal's view of a file each time the intel stage
-- looks it up. The lookup was already happening, so this costs no quota. It
-- is what lets the site show a detection trajectory (1/63 on the day we
-- uploaded, 30/66 today) and check VirusTotal's first_submission_date
-- against our own upload time to confirm who submitted first.
--
-- sample_provenance keeps the capture context for every hash: when it was
-- first seen, how it arrived, from where. payloads and payload_sightings are
-- rebuilt from raw_events on every pass, and raw_events is pruned by age, so
-- without this table a contribution loses its capture chain once the events
-- behind it are retired.

CREATE TABLE IF NOT EXISTS vt_snapshots (
  sha256                 TEXT NOT NULL,
  fetched_at             TEXT NOT NULL,
  malicious              INTEGER NOT NULL DEFAULT 0,
  suspicious             INTEGER NOT NULL DEFAULT 0,
  undetected             INTEGER NOT NULL DEFAULT 0,
  harmless               INTEGER NOT NULL DEFAULT 0,
  engines                INTEGER NOT NULL DEFAULT 0,   -- engines that returned a result
  first_submission_date  INTEGER,                      -- epoch seconds, as VirusTotal reports it
  last_submission_date   INTEGER,
  times_submitted        INTEGER,
  label                  TEXT,
  PRIMARY KEY (sha256, fetched_at)
);
CREATE INDEX IF NOT EXISTS idx_vt_snapshots_sha ON vt_snapshots(sha256, fetched_at);

CREATE TABLE IF NOT EXISTS sample_provenance (
  sha256         TEXT PRIMARY KEY,
  first_seen     TEXT,
  last_seen      TEXT,
  hits           INTEGER NOT NULL DEFAULT 0,
  sessions       INTEGER NOT NULL DEFAULT 0,
  src_ips        INTEGER NOT NULL DEFAULT 0,
  delivery       TEXT,          -- url | upload | inband
  source_url     TEXT,          -- first URL it was fetched from, when there was one
  host           TEXT,
  first_session  TEXT,
  first_src_ip   TEXT,
  updated_at     TEXT
);
