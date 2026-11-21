"""The Summary mode comparisons, on fixed Eastern days.

The route tests build their data from the current time, so whether both
comparison windows hold any days depends on the hour the suite runs. These
tests place rows on known days relative to the Eastern date instead.
"""

from tests.support import DBTestCase
from app.analytics import clock, exec_view


class ComparisonTests(DBTestCase):
    def setUp(self):
        super().setUp()
        # Current window: days 1 to 3 ago. Previous window: days 31 to 33 ago,
        # one of which is inside a login outage.
        self.current = [clock.days_ago(n) for n in (1, 2, 3)]
        self.previous = [clock.days_ago(n) for n in (31, 32, 33)]
        sid = 0
        for day, sessions, authed in ([(d, 4, 2) for d in self.current]
                                      + [(d, 2, 1) for d in self.previous]):
            self.con.execute(
                "INSERT INTO asn_ip_daily(day, asn, src_ip, events) VALUES(?, 1, '198.51.100.1', 1)",
                (day,))
            for i in range(sessions):
                sid += 1
                self.con.execute(
                    "INSERT INTO session_facts(day, session, src_ip, authed, commands, downloads,"
                    " uploads) VALUES(?, ?, '198.51.100.1', ?, ?, ?, 0)",
                    (day, f"s{sid}", int(i < authed), int(i < authed), int(i == 0)))
        self.con.execute(
            "INSERT INTO payloads(shasum, url, direction, last_seen) VALUES('ab', '', 'download', ?)",
            (clock.bounds(self.current[0])[0] + "Z",))
        self.con.execute(
            "INSERT INTO outage_windows(start_day, end_day, scope, reason)"
            " VALUES(?, ?, 'auth', 'test outage')", (self.previous[0], self.previous[0]))
        self.con.execute(
            "INSERT INTO outage_windows(start_day, end_day, scope, reason)"
            " VALUES('not a day', 'x', 'ingest', 'malformed rows are skipped')")
        self.con.commit()

    def test_trends_compare_daily_rates_and_drop_outage_days(self):
        t = exec_view.trends(self.con, 30)
        conn = t["connections"]
        self.assertEqual((conn["current"], conn["current_days"]), (12, 3))
        self.assertEqual((conn["previous"], conn["previous_days"]), (6, 3))
        self.assertEqual(conn["change_pct"], 100.0)
        self.assertEqual(conn["direction"], "up")
        auth = t["authenticated"]
        # The outage day is left out of the previous window for login fields.
        self.assertEqual((auth["current"], auth["previous"], auth["previous_days"]), (6, 2, 2))
        self.assertEqual(t["shell"]["current"], 6)
        self.assertEqual(t["transferred"]["current"], 3)
        self.assertEqual(t["captured"]["current"], 1)
        self.assertIn(self.previous[0], t["excluded_days"])

    def test_odds(self):
        o = exec_view.odds(self.con, 7)
        self.assertEqual(o["connections"], 12)
        self.assertEqual((o["login"], o["shell"], o["malware"]), (2, 2, 4))

    def test_goals_shares_add_up(self):
        for user, tag, n in (("oracle", "database", 3), ("pi", "iot", 1)):
            self.con.execute("INSERT INTO cred_pair_tags(username, password, tag) VALUES(?, 'x', ?)",
                             (user, tag))
            self.con.execute("INSERT INTO cred_pair_daily(day, username, password, attempts)"
                             " VALUES(?, ?, 'x', ?)", (self.current[0], user, n))
        self.con.commit()
        rows = exec_view.goals(self.con, 30)
        self.assertEqual([(r["tag"], r["share_pct"]) for r in rows],
                         [("database", 75.0), ("iot", 25.0)])
