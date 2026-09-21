"""The health view has to notice each way the pipeline fails quietly.

Two of these have happened on this deployment: authentication died for
seventeen days while connections kept arriving, and the sample fetch failed
on every run for a day under a unit that tolerates its failure. The view used
to work at day granularity and had no idea the individual stages existed.
"""

import datetime as dt
import os
import tempfile
from unittest import mock

from tests.support import DBTestCase, iso
from app.analytics import db, exec_view


def minutes_ago(n):
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=n)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class HealthTests(DBTestCase):
    def setUp(self):
        super().setUp()
        self.hb = tempfile.mkdtemp(prefix="tr-hb-")
        self.pull_hb = os.path.join(self.hb, ".pulled")
        self.fetch_hb = os.path.join(self.hb, ".fetched")
        for name, path in (("PULL_HEARTBEAT", self.pull_hb), ("FETCH_HEARTBEAT", self.fetch_hb)):
            p = mock.patch.object(exec_view, name, path)
            p.start()
            self.addCleanup(p.stop)

    def beat(self, path, minutes):
        open(path, "w").close()
        t = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)).timestamp()
        os.utime(path, (t, t))

    def healthy_pipeline(self):
        # A day of normal session facts, so the day-level checks pass, and
        # every stage recently completed.
        self.con.execute(
            "INSERT INTO session_facts(day, session, src_ip, authed, commands)"
            " VALUES(?, 's0', '198.51.100.1', 1, 1)", (iso()[:10],))
        self.con.execute("INSERT INTO asn_ip_daily(day, asn, src_ip, events) VALUES(?, 1, '198.51.100.1', 1)",
                         (iso()[:10],))
        self.con.commit()
        db.set_state(self.con, "last_run", minutes_ago(5))
        self.con.commit()
        self.beat(self.pull_hb, 1)
        self.beat(self.fetch_hb, 10)
        self.add_event("cowrie.session.connect", "a", "198.51.100.1", minutes_ago(2))
        self.add_event("cowrie.login.failed", "a", "198.51.100.1", minutes_ago(2))

    def test_everything_recent_is_ok(self):
        self.healthy_pipeline()
        h = exec_view.health(self.con)
        self.assertEqual(h["status"], "ok", h["message"])
        self.assertEqual(h["stages"]["pull"]["minutes_ago"], 1)

    def test_connections_without_logins_is_the_july_fault(self):
        self.healthy_pipeline()
        for i in range(40):
            self.add_event("cowrie.session.connect", f"c{i}", "198.51.100.2", minutes_ago(30 + i))
        self.con.execute("DELETE FROM raw_events WHERE eventid LIKE 'cowrie.login.%'")
        self.con.commit()
        h = exec_view.health(self.con)
        self.assertEqual(h["status"], "fault")
        self.assertIn("not one login event", h["message"])

    def test_a_stalled_pull_is_reported(self):
        self.healthy_pipeline()
        self.beat(self.pull_hb, 40)
        h = exec_view.health(self.con)
        self.assertEqual(h["status"], "warn")
        self.assertIn("log pull", h["message"])

    def test_a_failing_sample_fetch_is_reported(self):
        # The failure that went unnoticed for a day.
        self.healthy_pipeline()
        self.beat(self.fetch_hb, 60 * 5)
        h = exec_view.health(self.con)
        self.assertEqual(h["status"], "warn")
        self.assertIn("sample fetch", h["message"])

    def test_a_missing_heartbeat_is_unknown_not_stale(self):
        self.healthy_pipeline()
        os.remove(self.fetch_hb)
        h = exec_view.health(self.con)
        self.assertEqual(h["status"], "ok")
        self.assertIsNone(h["stages"]["samples"]["at"])
