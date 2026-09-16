-- 009_entities.sql
-- Entity drill-down. Additive only.
--
-- Every value on the site becomes a link to a canonical entity page
-- (/ip, /asn, /credential, /hassh, /url, /day). Most pivots already have a
-- daily fact table; the two that do not are credential -> IP and
-- fingerprint -> IP, which without a rollup would each need a raw_events
-- scan with a json_extract per row at request time. Same treatment as
-- client_fp_daily: built once per day by the worker, read forever.

PRAGMA foreign_keys=OFF;

-- Which addresses tried which pair, per day. Feeds /credential/{id} (which
-- IPs pushed this pair) and /ip/{addr} (which pairs this address tried).
CREATE TABLE IF NOT EXISTS cred_ip_daily (
  day        TEXT NOT NULL,
  username   TEXT NOT NULL DEFAULT '',
  password   TEXT NOT NULL DEFAULT '',
  src_ip     TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  successes  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, username, password, src_ip)
);
CREATE INDEX IF NOT EXISTS idx_cred_ip_pair ON cred_ip_daily(username, password);
CREATE INDEX IF NOT EXISTS idx_cred_ip_ip   ON cred_ip_daily(src_ip);

-- Which addresses presented which SSH client fingerprint, per day. Feeds
-- /hassh/{fp} (who used this tool) and /ip/{addr} (what tools this address
-- used). client_fp_daily has the totals but not the address mapping.
CREATE TABLE IF NOT EXISTS hassh_ip_daily (
  day        TEXT NOT NULL,
  hassh      TEXT NOT NULL,
  src_ip     TEXT NOT NULL,
  events     INTEGER NOT NULL DEFAULT 0,
  sessions   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, hassh, src_ip)
);
CREATE INDEX IF NOT EXISTS idx_hassh_ip_fp ON hassh_ip_daily(hassh);
CREATE INDEX IF NOT EXISTS idx_hassh_ip_ip ON hassh_ip_daily(src_ip);

-- Pivot indexes for entity pages over tables that already exist. Each one
-- backs an equality lookup a page makes on every load.
CREATE INDEX IF NOT EXISTS idx_sightings_url    ON payload_sightings(url);
CREATE INDEX IF NOT EXISTS idx_payload_daily_url ON payload_daily(url);
CREATE INDEX IF NOT EXISTS idx_payload_daily_sha ON payload_daily(shasum);
CREATE INDEX IF NOT EXISTS idx_cred_daily_pair  ON cred_pair_daily(username, password);
