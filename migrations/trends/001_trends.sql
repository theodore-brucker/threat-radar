-- Incident trends: disruptive incidents at US organizations, their stated
-- causes, the suppliers they share, and the weekly tables the site reads.
--
-- Applied by bin/trends_worker.py on every run, so every statement is
-- idempotent. Nothing here touches a honeypot table. The file sits outside
-- the top level of migrations/ because the intel worker applies that
-- directory and this one belongs to the trends worker.
--
-- cause_status is one of three values:
--   malicious     a malicious cause was stated
--   undisclosed   no cause, or a vague one, was stated
--   nonmalicious  a non-malicious or precautionary cause was stated

CREATE TABLE IF NOT EXISTS organization (
  id      INTEGER PRIMARY KEY,
  slug    TEXT NOT NULL UNIQUE,
  name    TEXT NOT NULL,
  state   TEXT,
  sector  TEXT
);

CREATE TABLE IF NOT EXISTS vendor (
  id       INTEGER PRIMARY KEY,
  slug     TEXT NOT NULL UNIQUE,
  name     TEXT NOT NULL,
  product  TEXT
);

-- One row per item a collector or the seed loader saw. item_hash is sha256 of
-- the source name and the canonical URL (or the seed file and row key), so a
-- second fetch of the same item is a no-op.
CREATE TABLE IF NOT EXISTS source_item (
  id          INTEGER PRIMARY KEY,
  item_hash   TEXT NOT NULL UNIQUE,
  source      TEXT NOT NULL,
  url         TEXT,
  title       TEXT,
  published   TEXT,
  categories  TEXT,
  status      TEXT CHECK (status IN ('malicious', 'undisclosed', 'nonmalicious')),
  method      TEXT,
  confidence  TEXT NOT NULL DEFAULT 'low',
  fetched_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_source_item_source ON source_item(source, published);

-- kind: org (one organization), national (an outage felt across the country),
-- or vendor (a supplier's own outage reaching its customers).
CREATE TABLE IF NOT EXISTS incident (
  id               INTEGER PRIMARY KEY,
  kind             TEXT NOT NULL CHECK (kind IN ('org', 'national', 'vendor')),
  title            TEXT NOT NULL,
  started          TEXT NOT NULL,
  organization_id  INTEGER REFERENCES organization(id),
  state            TEXT,
  sector           TEXT,
  scope            TEXT,
  cause_status     TEXT NOT NULL CHECK (cause_status IN ('malicious', 'undisclosed', 'nonmalicious')),
  source           TEXT NOT NULL,
  confidence       TEXT NOT NULL DEFAULT 'low',
  source_item_id   INTEGER REFERENCES source_item(id),
  created_at       TEXT NOT NULL,
  rechecked_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_incident_started ON incident(kind, started);
CREATE INDEX IF NOT EXISTS idx_incident_org ON incident(organization_id);

-- A cause stated about an incident, with the date it was stated when the
-- source gives one. Time to cause is the earliest dated row that is not
-- undisclosed, minus the incident's start.
CREATE TABLE IF NOT EXISTS statement (
  id              INTEGER PRIMARY KEY,
  incident_id     INTEGER NOT NULL REFERENCES incident(id),
  source_item_id  INTEGER REFERENCES source_item(id),
  stated_at       TEXT,
  cause_status    TEXT NOT NULL CHECK (cause_status IN ('malicious', 'undisclosed', 'nonmalicious')),
  text            TEXT,
  UNIQUE (incident_id, source_item_id)
);

-- A leak-site claim. Kept apart from statement because a group's claim is
-- not the organization stating a cause.
CREATE TABLE IF NOT EXISTS actor_claim (
  id          INTEGER PRIMARY KEY,
  claim_hash  TEXT NOT NULL UNIQUE,
  actor       TEXT NOT NULL,
  victim      TEXT NOT NULL,
  country     TEXT,
  discovered  TEXT,
  post_url    TEXT,
  source      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve (
  cve_id          TEXT PRIMARY KEY,
  vendor          TEXT,
  product         TEXT,
  kev_added       TEXT,
  ransomware_use  TEXT
);

CREATE TABLE IF NOT EXISTS incident_vendor (
  incident_id  INTEGER NOT NULL REFERENCES incident(id),
  vendor_id    INTEGER NOT NULL REFERENCES vendor(id),
  role         TEXT NOT NULL DEFAULT 'supplier',
  customers    INTEGER,
  note         TEXT,
  PRIMARY KEY (incident_id, vendor_id)
);

CREATE TABLE IF NOT EXISTS incident_cve (
  incident_id  INTEGER NOT NULL REFERENCES incident(id),
  cve_id       TEXT NOT NULL REFERENCES cve(cve_id),
  PRIMARY KEY (incident_id, cve_id)
);

CREATE TABLE IF NOT EXISTS incident_claim (
  incident_id  INTEGER NOT NULL REFERENCES incident(id),
  claim_id     INTEGER NOT NULL REFERENCES actor_claim(id),
  PRIMARY KEY (incident_id, claim_id)
);

-- Worker state.
CREATE TABLE IF NOT EXISTS trend_fetch_state (
  source         TEXT PRIMARY KEY,
  etag           TEXT,
  last_modified  TEXT,
  last_run       TEXT,
  last_status    TEXT,
  last_bytes     INTEGER
);

CREATE TABLE IF NOT EXISTS trend_classify_cache (
  item_hash  TEXT PRIMARY KEY,
  status     TEXT NOT NULL CHECK (status IN ('malicious', 'undisclosed', 'nonmalicious')),
  method     TEXT NOT NULL,
  rubric     TEXT NOT NULL,
  at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trend_write_log (
  day    TEXT PRIMARY KEY,
  bytes  INTEGER NOT NULL DEFAULT 0
);

-- Rollups, rebuilt whole by the daily step. ids columns hold a JSON array of
-- incident ids so every figure on the page can list the rows behind it.
CREATE TABLE IF NOT EXISTS trend_weekly (
  week          TEXT PRIMARY KEY,
  incidents     INTEGER NOT NULL,
  malicious     INTEGER NOT NULL,
  undisclosed   INTEGER NOT NULL,
  nonmalicious  INTEGER NOT NULL,
  fitted        REAL,
  partial       INTEGER NOT NULL DEFAULT 0,
  ids           TEXT NOT NULL,
  undisclosed_ids TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trend_cause_delay (
  incident_id     INTEGER PRIMARY KEY,
  started         TEXT NOT NULL,
  first_cause_at  TEXT NOT NULL,
  days            INTEGER NOT NULL,
  cause_status    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trend_fanout (
  incident_id  INTEGER NOT NULL,
  vendor_id    INTEGER NOT NULL,
  started      TEXT NOT NULL,
  customers    INTEGER,
  linked       INTEGER NOT NULL,
  ids          TEXT NOT NULL,
  PRIMARY KEY (incident_id, vendor_id)
);

CREATE TABLE IF NOT EXISTS trend_cluster (
  first_day  TEXT PRIMARY KEY,
  last_day   TEXT NOT NULL,
  outages    INTEGER NOT NULL,
  ids        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trend_meta (
  key    TEXT PRIMARY KEY,
  value  TEXT
);
