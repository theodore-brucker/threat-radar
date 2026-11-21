"""Eastern days and Eastern display times.

The cases that matter are the ones UTC hid: the evening hours that belong to
the previous Eastern day, the two DST change days, and stored times with a
fraction of a second sitting on a day boundary.
"""

import datetime as dt
import sqlite3
import unittest
from unittest import mock

from tests.support import DBTestCase
from app.analytics import clock, db

UTC = dt.timezone.utc


class DayTests(unittest.TestCase):
    def test_evening_utc_belongs_to_the_earlier_eastern_day(self):
        self.assertEqual(clock.day("2026-11-21T03:30:00Z"), "2026-11-20")
        self.assertEqual(clock.day("2026-11-21T05:00:00Z"), "2026-11-21")
        self.assertEqual(clock.day("2026-11-21T04:59:59.999999Z"), "2026-11-20")

    def test_summer_offset_is_four_hours(self):
        self.assertEqual(clock.day("2026-07-04T03:59:59Z"), "2026-07-03")
        self.assertEqual(clock.day("2026-07-04T04:00:00Z"), "2026-07-04")

    def test_epoch_seconds(self):
        t = dt.datetime(2026, 11, 21, 3, 30, tzinfo=UTC).timestamp()
        self.assertEqual(clock.day(t), "2026-11-20")

    def test_a_bare_day_passes_through_and_junk_is_none(self):
        self.assertEqual(clock.day("2026-11-20"), "2026-11-20")
        for junk in (None, "", "yesterday", "2026-13-01", "2026-11-20T99"):
            self.assertIsNone(clock.day(junk), junk)


class BoundsTests(unittest.TestCase):
    def test_standard_and_daylight_days(self):
        self.assertEqual(clock.bounds("2026-11-20"), ("2026-11-20T05:00:00", "2026-11-21T05:00:00"))
        self.assertEqual(clock.bounds("2026-07-04"), ("2026-07-04T04:00:00", "2026-07-05T04:00:00"))

    def test_dst_change_days_are_23_and_25_hours(self):
        lo, hi = clock.epoch_bounds("2026-03-08")
        self.assertEqual(hi - lo, 23 * 3600)
        lo, hi = clock.epoch_bounds("2026-11-01")
        self.assertEqual(hi - lo, 25 * 3600)

    def test_a_fraction_on_the_boundary_lands_inside_the_day(self):
        lo, hi = clock.bounds("2026-11-20")
        self.assertTrue(lo <= "2026-11-20T05:00:00.123Z" < hi)
        self.assertFalse(lo <= "2026-11-20T04:59:59.999Z")

    def test_span(self):
        self.assertEqual(clock.bounds("2026-11-20", 2)[1], "2026-11-22T05:00:00")

    def test_bounds_agree_with_day(self):
        lo, hi = clock.bounds("2026-11-01")  # the fall-back day
        self.assertEqual(clock.day(lo + "Z"), "2026-11-01")
        last = (dt.datetime.fromisoformat(hi).replace(tzinfo=UTC)
                - dt.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(clock.day(last), "2026-11-01")


class NowTests(unittest.TestCase):
    def test_today_and_days_ago_use_the_eastern_date(self):
        fixed = dt.datetime(2026, 11, 21, 3, 30, tzinfo=UTC)
        with mock.patch.object(clock, "now", return_value=fixed):
            self.assertEqual(clock.today(), "2026-11-20")
            self.assertEqual(clock.days_ago(1), "2026-11-19")
            self.assertEqual(db.TsExpr.cutoff_day(1), "2026-11-19")


class DisplayTests(unittest.TestCase):
    def test_fmt(self):
        self.assertEqual(clock.fmt("2026-11-21T02:12:00Z"), "2026-11-20 21:12")
        self.assertEqual(clock.fmt("2026-07-04T16:05:00Z", zone=True), "2026-07-04 12:05 EDT")
        self.assertIsNone(clock.fmt(None))

    def test_iso_keeps_milliseconds_only_when_there_is_a_fraction(self):
        self.assertEqual(clock.iso("2026-11-21T02:12:00Z"), "2026-11-20T21:12:00-05:00")
        self.assertEqual(clock.iso("2026-11-21T02:12:00.123456Z"), "2026-11-20T21:12:00.123-05:00")

    def test_localize_converts_time_keys_only(self):
        stamp = "2026-11-21T02:12:00Z"
        data = {"ts": stamp, "first_seen": stamp, "submitted_at": stamp, "ended": stamp,
                "day": "2026-11-20", "input": stamp, "url": stamp,
                "rows": [{"last_seen": stamp, "password": stamp}]}
        out = clock.localize(data)
        for key in ("ts", "first_seen", "submitted_at", "ended"):
            self.assertEqual(out[key], "2026-11-20T21:12:00-05:00", key)
        self.assertEqual(out["rows"][0]["last_seen"], "2026-11-20T21:12:00-05:00")
        # Attacker-controlled fields and days are left as they were.
        for key in ("day", "input", "url"):
            self.assertEqual(out[key], data[key], key)
        self.assertEqual(out["rows"][0]["password"], stamp)

    def test_localize_is_idempotent(self):
        once = clock.localize({"ts": "2026-11-21T02:12:00Z"})
        self.assertEqual(clock.localize(once), once)


class SqlTests(DBTestCase):
    def test_et_day_is_registered_on_both_connections(self):
        for con in (self.con, db.connect_ro(self.db_path)):
            self.assertEqual(con.execute("SELECT et_day('2026-11-21T03:30:00Z')").fetchone()[0],
                             "2026-11-20")

    def test_a_plain_connection_does_not_have_it(self):
        # Views and migrations must not depend on et_day: the analyst's sqlite3
        # shell and the migration tests open the database without it.
        with self.assertRaises(sqlite3.OperationalError):
            sqlite3.connect(":memory:").execute("SELECT et_day('x')")

    def test_ts_expr_groups_raw_events_by_eastern_day(self):
        self.add_event("cowrie.session.connect", "a", "198.51.100.1", "2026-11-21T03:30:00Z")
        self.add_event("cowrie.session.connect", "b", "198.51.100.1", "2026-11-21T06:00:00Z")
        ts = db.TsExpr(self.con)
        days = [r[0] for r in self.con.execute(
            f"SELECT {ts.day} FROM raw_events ORDER BY ts")]
        self.assertEqual(days, ["2026-11-20", "2026-11-21"])
        lo, hi = ts.day_range("2026-11-20")
        n = self.con.execute("SELECT COUNT(*) FROM raw_events WHERE ts >= ? AND ts < ?",
                             (lo, hi)).fetchone()[0]
        self.assertEqual(n, 1)
