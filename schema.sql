PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS raw_events (
  id        INTEGER PRIMARY KEY,
  line_hash TEXT UNIQUE NOT NULL,
  eventid   TEXT,
  session   TEXT,
  src_ip    TEXT,
  ts        TEXT,
  payload   TEXT NOT NULL
);
-- idx_events_eventid was dropped by migration 014: idx_raw_eventid_ts covers it.
CREATE INDEX IF NOT EXISTS idx_events_src     ON raw_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON raw_events(ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON raw_events(session);

CREATE TABLE IF NOT EXISTS sources (
  ip           TEXT PRIMARY KEY,
  first_seen   TEXT,
  last_seen    TEXT,
  event_count  INTEGER DEFAULT 0,
  country      TEXT,
  country_code TEXT,
  city         TEXT,
  lat          REAL,
  lon          REAL,
  asn          INTEGER,
  as_org       TEXT,
  enriched_at  TEXT
);

CREATE TABLE IF NOT EXISTS ingest_state (
  filename    TEXT PRIMARY KEY,
  byte_offset INTEGER NOT NULL DEFAULT 0
);
