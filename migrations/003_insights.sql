-- 003_insights.sql
-- Additive only. No existing table or view is altered or dropped.

PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS insights_state (
  key         TEXT PRIMARY KEY,
  value       TEXT,
  updated_at  TEXT
);

-- Payload rollup, rebuilt by the intel worker from raw_events.
CREATE TABLE IF NOT EXISTS payloads (
  shasum      TEXT NOT NULL DEFAULT '',
  url         TEXT NOT NULL DEFAULT '',
  direction   TEXT NOT NULL,            -- download | upload
  filename    TEXT,
  host        TEXT,                     -- host or IP parsed out of url
  hits        INTEGER NOT NULL DEFAULT 0,
  sessions    INTEGER NOT NULL DEFAULT 0,
  src_ips     INTEGER NOT NULL DEFAULT 0,
  first_seen  TEXT,
  last_seen   TEXT,
  PRIMARY KEY (shasum, url, direction)
);
CREATE INDEX IF NOT EXISTS idx_payloads_last  ON payloads(last_seen);
CREATE INDEX IF NOT EXISTS idx_payloads_host  ON payloads(host);
CREATE INDEX IF NOT EXISTS idx_payloads_hash  ON payloads(shasum);

-- Which sessions and source IPs touched each payload, for pivoting.
CREATE TABLE IF NOT EXISTS payload_sightings (
  shasum      TEXT NOT NULL DEFAULT '',
  url         TEXT NOT NULL DEFAULT '',
  direction   TEXT NOT NULL,
  session     TEXT,
  src_ip      TEXT,
  ts          TEXT,
  PRIMARY KEY (shasum, url, direction, session, ts)
);
CREATE INDEX IF NOT EXISTS idx_sightings_ip   ON payload_sightings(src_ip);
CREATE INDEX IF NOT EXISTS idx_sightings_hash ON payload_sightings(shasum);

-- Reputation cache. One row per indicator per source.
CREATE TABLE IF NOT EXISTS payload_intel (
  indicator   TEXT NOT NULL,            -- sha256, url, or host
  kind        TEXT NOT NULL,            -- sha256 | url | host
  source      TEXT NOT NULL,            -- virustotal | urlhaus
  verdict     TEXT,                     -- malicious | suspicious | clean | unknown | error
  malicious   INTEGER DEFAULT 0,
  suspicious  INTEGER DEFAULT 0,
  harmless    INTEGER DEFAULT 0,
  undetected  INTEGER DEFAULT 0,
  label       TEXT,                     -- signature / threat family / tags
  reference   TEXT,                     -- link back to the vendor record
  raw         TEXT,
  checked_at  TEXT,
  PRIMARY KEY (indicator, source)
);
CREATE INDEX IF NOT EXISTS idx_intel_checked ON payload_intel(checked_at);

-- Credential pairs with campaign tags.
CREATE TABLE IF NOT EXISTS cred_pairs (
  username     TEXT NOT NULL DEFAULT '',
  password     TEXT NOT NULL DEFAULT '',
  attempts     INTEGER NOT NULL DEFAULT 0,
  successes    INTEGER NOT NULL DEFAULT 0,
  distinct_ips INTEGER NOT NULL DEFAULT 0,
  first_seen   TEXT,
  last_seen    TEXT,
  PRIMARY KEY (username, password)
);
CREATE INDEX IF NOT EXISTS idx_cred_attempts ON cred_pairs(attempts DESC);

CREATE TABLE IF NOT EXISTS cred_pair_tags (
  username  TEXT NOT NULL DEFAULT '',
  password  TEXT NOT NULL DEFAULT '',
  tag       TEXT NOT NULL,
  PRIMARY KEY (username, password, tag)
);
CREATE INDEX IF NOT EXISTS idx_cred_tag ON cred_pair_tags(tag);

-- Per-tag, per-source-IP counts so a campaign can be scoped to infrastructure.
CREATE TABLE IF NOT EXISTS cred_tag_ips (
  tag       TEXT NOT NULL,
  src_ip    TEXT NOT NULL,
  attempts  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tag, src_ip)
);

-- Daily volume spikes with attribution.
CREATE TABLE IF NOT EXISTS spike_annotations (
  day         TEXT PRIMARY KEY,
  events      INTEGER,
  baseline    REAL,
  ratio       REAL,
  zscore      REAL,
  headline    TEXT,
  detail      TEXT,                     -- JSON: movers by ip / asn / eventid / username
  created_at  TEXT
);

-- Composite index that makes the per-eventid time-window scans cheap.
CREATE INDEX IF NOT EXISTS idx_raw_eventid_ts ON raw_events(eventid, ts);

-- Per-day, per-source-IP fact table. Everything ASN-shaped and every spike
-- attribution reads from here instead of scanning raw_events at request time.
CREATE TABLE IF NOT EXISTS asn_ip_daily (
  day        TEXT NOT NULL,
  src_ip     TEXT NOT NULL,
  asn        TEXT,
  org        TEXT,
  country    TEXT,
  events     INTEGER NOT NULL DEFAULT 0,
  sessions   INTEGER NOT NULL DEFAULT 0,
  logins     INTEGER NOT NULL DEFAULT 0,
  successes  INTEGER NOT NULL DEFAULT 0,
  commands   INTEGER NOT NULL DEFAULT 0,
  downloads  INTEGER NOT NULL DEFAULT 0,
  uploads    INTEGER NOT NULL DEFAULT 0,
  tunnels    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, src_ip)
);
CREATE INDEX IF NOT EXISTS idx_asn_daily_asn ON asn_ip_daily(asn, day);
CREATE INDEX IF NOT EXISTS idx_asn_daily_day ON asn_ip_daily(day);

-- Per-day event type counts, used for spike attribution.
CREATE TABLE IF NOT EXISTS eventid_daily (
  day      TEXT NOT NULL,
  eventid  TEXT NOT NULL,
  events   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, eventid)
);

-- Per-session outcome flags, used by the funnel and the silent-session list.
CREATE TABLE IF NOT EXISTS session_facts (
  session     TEXT PRIMARY KEY,
  src_ip      TEXT,
  first_seen  TEXT,
  last_seen   TEXT,
  day         TEXT,
  duration    REAL,
  username    TEXT,
  connected   INTEGER DEFAULT 0,
  attempted   INTEGER DEFAULT 0,
  authed      INTEGER DEFAULT 0,
  commands    INTEGER DEFAULT 0,
  downloads   INTEGER DEFAULT 0,
  uploads     INTEGER DEFAULT 0,
  tunnels     INTEGER DEFAULT 0,
  client      TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_facts_day  ON session_facts(day);
CREATE INDEX IF NOT EXISTS idx_session_facts_ip   ON session_facts(src_ip);
CREATE INDEX IF NOT EXISTS idx_session_facts_flow ON session_facts(authed, commands);

-- direct-tcpip destination rollup.
CREATE TABLE IF NOT EXISTS tunnel_targets (
  day        TEXT NOT NULL,
  dst_ip     TEXT NOT NULL,
  dst_port   INTEGER NOT NULL,
  requests   INTEGER NOT NULL DEFAULT 0,
  sessions   INTEGER NOT NULL DEFAULT 0,
  src_ips    INTEGER NOT NULL DEFAULT 0,
  data_events INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, dst_ip, dst_port)
);
CREATE INDEX IF NOT EXISTS idx_tunnel_port ON tunnel_targets(dst_port);
