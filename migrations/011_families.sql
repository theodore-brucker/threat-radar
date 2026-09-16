-- 011_families.sql  (2026-09-14)
--
-- Derived malware families. The payloads page was showing raw vendor strings,
-- which answer "what did one engine call this" rather than "what families
-- land on this sensor". The derivation is in app/analytics/families.py and is
-- rebuilt whole on every worker pass, so this table is a cache and never a
-- source of truth.

CREATE TABLE IF NOT EXISTS payload_families (
  shasum      TEXT PRIMARY KEY,
  family      TEXT NOT NULL,
  confidence  TEXT NOT NULL,     -- agreed | single-vendor | derived
  basis       TEXT,              -- which vendor offered which tokens
  candidates  TEXT,              -- runners-up, so disagreement stays visible
  derived_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_families_family ON payload_families(family);
