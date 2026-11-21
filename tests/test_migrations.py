"""Migrations are re-run by the worker on every pass, so they must be safe to.

Every migration has to apply to a fresh database and then apply again without
error or change, and every file in migrations/ has to be registered with the
worker, since an unregistered migration never runs and nothing reports it.
That last check exists because it nearly happened: migration 014 was written
before it was added to the list.
"""

import pathlib
import sqlite3
import unittest

from tests import fixtures
from tests.support import DBTestCase, ROOT, worker


def schema(con):
    return sorted(con.execute(
        "SELECT type, name, COALESCE(sql, '') FROM sqlite_master"
        " WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").fetchall())


def apply_all(con):
    with open(pathlib.Path(ROOT) / "schema.sql", encoding="utf-8") as fh:
        con.executescript(fh.read())
    for path in worker.MIGRATIONS:
        with open(path, encoding="utf-8") as fh:
            con.executescript(fh.read())
    con.commit()


class MigrationTests(unittest.TestCase):
    def test_every_migration_file_is_registered_in_order(self):
        on_disk = sorted(p.name for p in (pathlib.Path(ROOT) / "migrations").glob("*.sql"))
        registered = [pathlib.Path(p).name for p in worker.MIGRATIONS]
        self.assertEqual(registered, on_disk)

    def test_a_fresh_database_takes_every_migration(self):
        con = sqlite3.connect(":memory:")
        apply_all(con)
        names = {r[1] for r in schema(con)}
        for required in ("raw_events", "excluded_sources", "payload_sightings",
                         "cred_pair_daily", "v_events", "v_cred_attempts"):
            self.assertIn(required, names)
        self.assertNotIn("idx_events_eventid", names, "migration 014 should have removed it")

    def test_running_everything_again_changes_nothing(self):
        con = sqlite3.connect(":memory:")
        apply_all(con)
        before = schema(con)
        apply_all(con)
        apply_all(con)
        self.assertEqual(schema(con), before)


class MigrationsOverDataTests(DBTestCase):
    def test_rerunning_migrations_keeps_every_row(self):
        fixtures.build(self.con, worker, self.sample_dir)
        tables = [r[0] for r in self.con.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        counts = {t: self.con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
        self.assertGreater(counts["raw_events"], 100)
        worker.ensure_schema(self.con)
        after = {t: self.con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
        self.assertEqual(after, counts)


class EasternDaysMigrationTests(unittest.TestCase):
    """018 removes UTC-keyed day rows that raw events can rebuild, once."""

    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        apply_all(self.con)
        self.con.execute("DELETE FROM insights_state WHERE key = 'day_zone'")
        self.con.execute(
            "INSERT INTO raw_events(line_hash, eventid, session, src_ip, ts, payload)"
            " VALUES('h1', 'cowrie.session.connect', 's', '198.51.100.1',"
            " '2026-11-20T14:06:00.5Z', '{}')")
        for day in ("2026-10-01", "2026-11-20", "2026-11-21"):
            self.con.execute("INSERT INTO eventid_daily(day, eventid, events)"
                             " VALUES(?, 'cowrie.session.connect', 1)", (day,))
        self.con.commit()

    def days(self):
        return [r[0] for r in self.con.execute("SELECT day FROM eventid_daily ORDER BY day")]

    def test_rows_raw_events_cover_are_removed_and_older_ones_kept(self):
        apply_all(self.con)
        self.assertEqual(self.days(), ["2026-10-01"])

    def test_it_runs_once(self):
        apply_all(self.con)
        self.con.execute("INSERT INTO eventid_daily(day, eventid, events)"
                         " VALUES('2026-11-20', 'cowrie.session.connect', 5)")
        apply_all(self.con)
        self.assertEqual(self.days(), ["2026-10-01", "2026-11-20"])


if __name__ == "__main__":
    unittest.main()
