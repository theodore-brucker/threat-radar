"""Retention: the lifetime tables must survive raw events ageing out.

The decision is thirty days of raw events and indefinite per-day and lifetime
rollups. The worker used to delete the payload and credential lifetime tables
and refill them from the raw window on every run, so each prune quietly took
history with it. Every test here builds the rollups, deletes the older raw
events the way the pruner does, builds again, and checks that nothing the
first build recorded has gone.

The storage tests cover the other half: the size cap reports instead of
deleting raw events, because deleting them would shorten retention without
anyone deciding to.
"""

import importlib.util
import os
import unittest
from unittest import mock

from tests.support import DBTestCase, ROOT, iso, sha, worker
from app.analytics import db

DOWNLOAD = worker.DOWNLOAD_EVENT


def age_out(con, days):
    """Delete raw events older than `days`, exactly as prune_by_age does."""
    cutoff = iso(days_ago=days)
    con.execute("DELETE FROM raw_events WHERE ts < ?", (cutoff,))
    con.commit()


class PayloadRetentionTests(DBTestCase):
    def setUp(self):
        super().setUp()
        self.old_sha, self.new_sha = sha(1), sha(2)
        # One payload seen only 40 days ago, one seen 40 days ago and again
        # yesterday from a different source.
        self.add_event(DOWNLOAD, "s-old", "198.51.100.1", iso(days_ago=40),
                       shasum=self.old_sha, url="http://a.example/x", destfile="/tmp/x")
        self.add_event(DOWNLOAD, "s-both1", "198.51.100.2", iso(days_ago=40),
                       shasum=self.new_sha, url="http://b.example/y", destfile="/tmp/y")
        self.add_event(DOWNLOAD, "s-both2", "198.51.100.3", iso(days_ago=1),
                       shasum=self.new_sha, url="http://b.example/y", destfile="/tmp/y")

    def lifetime(self):
        return {r["shasum"]: r for r in db.qall(self.con, "SELECT * FROM payloads")}

    def test_payload_seen_only_before_the_window_is_kept(self):
        worker.build_payloads(self.con, backfill_all=True)
        self.assertIn(self.old_sha, self.lifetime())

        age_out(self.con, 30)
        worker.build_payloads(self.con)

        after = self.lifetime()
        self.assertIn(self.old_sha, after, "a payload vanished when its raw events aged out")
        self.assertEqual(after[self.old_sha]["hits"], 1)

    def test_first_seen_and_distinct_counts_survive(self):
        worker.build_payloads(self.con, backfill_all=True)
        before = self.lifetime()[self.new_sha]

        age_out(self.con, 30)
        worker.build_payloads(self.con)
        after = self.lifetime()[self.new_sha]

        self.assertEqual(after["first_seen"], before["first_seen"])
        self.assertEqual(after["hits"], 2)
        self.assertEqual(after["src_ips"], 2)
        self.assertEqual(after["sessions"], 2)

    def test_per_day_rows_outside_the_window_are_kept(self):
        worker.build_payloads(self.con, backfill_all=True)
        old_day = iso(days_ago=40)[:10]
        count = "SELECT COUNT(*) FROM payload_daily WHERE day = ?"
        self.assertEqual(self.con.execute(count, (old_day,)).fetchone()[0], 2)

        age_out(self.con, 30)
        worker.build_payloads(self.con, backfill_all=True)
        self.assertEqual(self.con.execute(count, (old_day,)).fetchone()[0], 2,
                         "a full backfill rebuilt a day it no longer had raw events for")

    def test_rebuilding_is_idempotent(self):
        worker.build_payloads(self.con, backfill_all=True)
        first = self.lifetime()
        worker.build_payloads(self.con)
        worker.build_payloads(self.con)
        self.assertEqual(
            {k: (v["hits"], v["sessions"], v["src_ips"]) for k, v in self.lifetime().items()},
            {k: (v["hits"], v["sessions"], v["src_ips"]) for k, v in first.items()},
        )


class CredentialRetentionTests(DBTestCase):
    def setUp(self):
        super().setUp()
        for session, ip, days_ago, event in (
            ("c1", "198.51.100.10", 40, "cowrie.login.failed"),
            ("c2", "198.51.100.11", 40, "cowrie.login.success"),
            ("c3", "198.51.100.12", 1, "cowrie.login.failed"),
        ):
            self.add_event(event, session, ip, iso(days_ago=days_ago),
                           username="root", password="123456")
        self.add_event("cowrie.login.failed", "c4", "198.51.100.13", iso(days_ago=40),
                       username="olduser", password="oldpass")

    def build(self, backfill_all=False):
        # The order the worker runs them in: entities writes cred_ip_daily,
        # which the credential lifetime tables are derived from.
        worker.build_entities(self.con, backfill_all)
        worker.build_credentials(self.con, backfill_all)

    def pair(self, username, password):
        return db.qone(self.con, "SELECT * FROM cred_pairs WHERE username=? AND password=?",
                       (username, password))

    def test_pair_seen_only_before_the_window_is_kept(self):
        self.build(backfill_all=True)
        self.assertIsNotNone(self.pair("olduser", "oldpass"))

        age_out(self.con, 30)
        self.build()
        self.assertIsNotNone(self.pair("olduser", "oldpass"),
                             "a credential pair vanished when its raw events aged out")

    def test_lifetime_counts_do_not_reset_to_the_raw_window(self):
        self.build(backfill_all=True)
        before = self.pair("root", "123456")
        self.assertEqual((before["attempts"], before["successes"]), (3, 1))

        age_out(self.con, 30)
        self.build()
        after = self.pair("root", "123456")
        self.assertEqual((after["attempts"], after["successes"]), (3, 1))
        self.assertEqual(after["distinct_ips"], 3)
        self.assertEqual(after["first_seen"], iso(days_ago=40)[:10])

    def test_tags_follow_the_lifetime_pairs(self):
        self.build(backfill_all=True)
        age_out(self.con, 30)
        self.build()
        tagged = {(r[0], r[1]) for r in self.con.execute(
            "SELECT username, password FROM cred_pair_tags")}
        # Every tagged pair must still exist in the lifetime table.
        pairs = {(r[0], r[1]) for r in self.con.execute(
            "SELECT username, password FROM cred_pairs")}
        self.assertTrue(tagged <= pairs)


class DaySelectionTests(DBTestCase):
    def test_full_backfill_leaves_a_built_oldest_day_alone(self):
        # The oldest raw day is usually cut in half by the age prune, so
        # rebuilding it would replace a complete count with a partial one.
        self.add_event("cowrie.login.failed", "d1", "198.51.100.20", iso(days_ago=5),
                       username="a", password="b")
        self.add_event("cowrie.login.failed", "d2", "198.51.100.21", iso(days_ago=1),
                       username="a", password="b")
        ts = db.TsExpr(self.con)
        worker.build_credentials(self.con, backfill_all=True)
        oldest = iso(days_ago=5)[:10]
        days = worker.days_to_build(self.con, ts, "cred_pair_daily", backfill_all=True)
        self.assertNotIn(oldest, days)
        self.assertIn(iso(days_ago=1)[:10], days)


def load_prune(db_path):
    with mock.patch.dict(os.environ, {"TR_DB": db_path, "TR_MAX_DB_MB": "0",
                                      "TR_RETAIN_DAYS": "30"}):
        spec = importlib.util.spec_from_file_location(
            "prune_under_test", os.path.join(ROOT, "prune.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    mod.log = lambda *_: None
    # prune derives its database path from TR_BASE at import, so point it at
    # the per-test database directly.
    mod.DB = db_path
    return mod


class StorageGuardTests(DBTestCase):
    def test_over_cap_never_deletes_raw_events_inside_the_window(self):
        for i in range(20):
            self.add_event("cowrie.session.connect", f"g{i}", "198.51.100.30",
                           iso(days_ago=i % 10))
        prune = load_prune(self.db_path)
        before = self.con.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]

        prune.prune_by_age(self.con)
        prune.check_storage(self.con)

        after = self.con.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
        self.assertEqual(after, before, "the storage check deleted raw events")

    def test_over_cap_is_reported_where_health_reads_it(self):
        prune = load_prune(self.db_path)
        prune.check_storage(self.con)
        status = db.get_state(self.con, "storage_status")
        self.assertIsNotNone(status)
        self.assertIn("cap", status)

    def test_report_clears_once_under_cap(self):
        prune = load_prune(self.db_path)
        prune.check_storage(self.con)
        self.assertIsNotNone(db.get_state(self.con, "storage_status"))
        with mock.patch.object(prune, "MAX_DB_MB", 10 ** 9), \
             mock.patch.object(prune.shutil, "disk_usage",
                               return_value=mock.Mock(free=10 ** 13)):
            prune.check_storage(self.con)
        self.assertIsNone(db.get_state(self.con, "storage_status"))


if __name__ == "__main__":
    unittest.main()
