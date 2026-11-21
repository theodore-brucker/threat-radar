"""The status view reports when each stage last ran, in Eastern time.

It makes no judgement about the times, so these tests check that each row
reads the right record, that a stage with no record says so, and that the
clock conversion follows daylight saving.
"""

import datetime as dt
import os
import tempfile
from unittest import mock

from tests.support import DBTestCase
from tests.test_retention import load_prune
from app.analytics import db, health

UTC = dt.timezone.utc


def at(*parts):
    return dt.datetime(*parts, tzinfo=UTC)


def stamp(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class EasternTimeTests(DBTestCase):
    def test_winter_is_est(self):
        self.assertEqual(health.eastern(at(2026, 11, 21, 2, 12)), "2026-11-20 21:12 EST")

    def test_summer_is_edt(self):
        self.assertEqual(health.eastern(at(2026, 7, 4, 16, 5)), "2026-07-04 12:05 EDT")

    def test_midnight_is_hour_zero(self):
        self.assertEqual(health.eastern(at(2026, 11, 20, 5, 0)), "2026-11-20 00:00 EST")

    def test_no_time_is_none(self):
        self.assertIsNone(health.eastern(None))


class StatusTests(DBTestCase):
    def setUp(self):
        super().setUp()
        self.hb = tempfile.mkdtemp(prefix="tr-hb-")
        self.pull_hb = os.path.join(self.hb, ".pulled")
        self.fetch_hb = os.path.join(self.hb, ".fetched")
        for name, path in (("PULL_HEARTBEAT", self.pull_hb), ("FETCH_HEARTBEAT", self.fetch_hb)):
            p = mock.patch.object(health, name, path)
            p.start()
            self.addCleanup(p.stop)

    def beat(self, path, when):
        open(path, "w").close()
        os.utime(path, (when.timestamp(), when.timestamp()))

    def rows(self, **kw):
        return {i["key"]: i for i in health.status(self.con, **kw)["items"]}

    def test_an_empty_install_has_a_row_per_stage_and_no_times(self):
        rows = self.rows()
        self.assertEqual(
            set(rows),
            {"pull", "events", "login_attempt", "login_success", "enrich", "samples",
             "worker", "facts", "intel", "submissions", "trends", "prune"})
        for r in rows.values():
            self.assertIsNone(r["at"], r["key"])
            self.assertIsNone(r["at_local"], r["key"])

    def test_there_is_no_verdict(self):
        out = health.status(self.con)
        self.assertNotIn("status", out)
        self.assertNotIn("message", out)
        self.assertEqual(out["timezone"], "Eastern time")

    def test_heartbeats_fill_pull_and_samples(self):
        self.beat(self.pull_hb, at(2026, 11, 21, 2, 10))
        self.beat(self.fetch_hb, at(2026, 11, 21, 1, 30))
        rows = self.rows()
        self.assertEqual(rows["pull"]["at_local"], "2026-11-20 21:10 EST")
        self.assertEqual(rows["samples"]["at_local"], "2026-11-20 20:30 EST")

    def test_events_and_logins_come_from_raw_events(self):
        self.add_event("cowrie.session.connect", "a", "198.51.100.1", "2026-11-21T02:12:30Z")
        self.add_event("cowrie.login.success", "a", "198.51.100.1", "2026-11-21T01:00:00Z")
        self.add_event("cowrie.login.failed", "b", "198.51.100.2", "2026-11-21T02:05:00Z")
        rows = self.rows()
        self.assertEqual(rows["events"]["at"], "2026-11-21T02:12:30Z")
        self.assertEqual(rows["login_attempt"]["at"], "2026-11-21T02:05:00Z")
        self.assertEqual(rows["login_success"]["at"], "2026-11-21T01:00:00Z")

    def test_cowrie_microsecond_timestamps_parse(self):
        self.add_event("cowrie.session.connect", "a", "198.51.100.1", "2026-11-21T02:12:30.123456Z")
        self.assertEqual(self.rows()["events"]["at_local"], "2026-11-20 21:12 EST")

    def test_worker_and_prune_come_from_state(self):
        db.set_state(self.con, "last_run", "2026-11-21T02:00:00Z")
        db.set_state(self.con, "facts_built_at", "2026-11-21T01:59:00Z")
        db.set_state(self.con, "prune_at", "2026-11-21T01:00:00Z")
        self.con.commit()
        rows = self.rows()
        self.assertEqual(rows["worker"]["at"], "2026-11-21T02:00:00Z")
        self.assertEqual(rows["facts"]["at"], "2026-11-21T01:59:00Z")
        self.assertEqual(rows["prune"]["at"], "2026-11-21T01:00:00Z")

    def test_enrich_reads_the_newest_lookup(self):
        self.con.execute("INSERT INTO sources(ip, enriched_at) VALUES('198.51.100.1', '2026-11-21T00:00:00Z')")
        self.con.execute("INSERT INTO sources(ip, enriched_at) VALUES('198.51.100.2', '2026-11-21T02:00:00Z')")
        self.con.execute("INSERT INTO sources(ip) VALUES('198.51.100.3')")
        self.con.commit()
        self.assertEqual(self.rows()["enrich"]["at"], "2026-11-21T02:00:00Z")

    def test_checked_at_uses_the_clock_given(self):
        out = health.status(self.con, now=at(2026, 11, 21, 2, 15))
        self.assertEqual(out["checked_at"], stamp(at(2026, 11, 21, 2, 15)))
        self.assertEqual(out["checked_at_local"], "2026-11-20 21:15 EST")

    def test_storage_note_passes_through(self):
        db.set_state(self.con, "storage_status", "The database is 5000 MB against a 4096 MB cap.")
        self.con.commit()
        self.assertIn("cap", health.status(self.con)["storage"])

    def test_prune_records_when_it_finished(self):
        prune = load_prune(self.db_path)
        with mock.patch.object(prune, "MAX_DB_MB", 10 ** 9), \
             mock.patch.object(prune.shutil, "disk_usage",
                               return_value=mock.Mock(free=10 ** 13)):
            prune.main()
        self.assertIsNotNone(self.rows()["prune"]["at"])

    def test_the_api_serves_it(self):
        from fastapi.testclient import TestClient
        from app.main import app
        r = TestClient(app).get("/api/v1/health")
        self.assertEqual(r.status_code, 200)
        self.assertIn("items", r.json()["data"])
