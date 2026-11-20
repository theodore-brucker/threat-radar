-- 015_us_address.sql  (2026-11-20)
--
-- The sensor moved from a European hosting address to a US one. The persona
-- on the host is unchanged, but scanners choose targets partly by address
-- range and geolocation, so a different population reaches the sensor from
-- this day on. Recording the move as an epoch keeps charts and
-- period-over-period comparisons from treating the two addresses as one
-- measurement.
--
-- Boundaries are whole UTC days. The move happened at about 03:00 UTC, so
-- the first day of this epoch includes roughly three hours from the old
-- address.

INSERT OR IGNORE INTO persona_epochs(start_day, name, note, created_at) VALUES
  ('2026-11-20', 'Compute node, US address',
   'Same compute node persona, moved from a European hosting address to a US '
   || 'one. Scanners pick targets partly by address range and location, so '
   || 'counts either side of this day are not the same measurement.',
   '2026-11-20');
