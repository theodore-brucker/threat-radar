"""Contributions analytics: attribution against VirusTotal's first submission
date, detection trajectory, and counts that never mistake a hash a service
already held for one of ours."""

import unittest

from tests.support import DBTestCase, iso, sha
from app.analytics import contributions as contrib


class VerifyFirstTests(unittest.TestCase):
    OURS = "2026-08-24T16:12:59Z"
    OURS_EPOCH = 1787587979

    def test_same_moment_is_confirmed(self):
        self.assertEqual(contrib.verify_first(self.OURS, self.OURS_EPOCH), "confirmed")

    def test_within_tolerance_is_confirmed(self):
        self.assertEqual(contrib.verify_first(self.OURS, self.OURS_EPOCH - 600), "confirmed")

    def test_earlier_than_tolerance_is_preceded(self):
        self.assertEqual(contrib.verify_first(self.OURS, self.OURS_EPOCH - 3600), "preceded")

    def test_missing_data_is_unverified(self):
        self.assertEqual(contrib.verify_first(self.OURS, None), "unverified")
        self.assertEqual(contrib.verify_first(None, self.OURS_EPOCH), "unverified")
        self.assertEqual(contrib.verify_first("garbage", self.OURS_EPOCH), "unverified")


class TrajectoryTests(unittest.TestCase):

    SNAPS = [
        {"fetched_at": "2026-08-20T00:00:00Z", "malicious": 0, "engines": 60},
        {"fetched_at": "2026-08-25T00:00:00Z", "malicious": 1, "engines": 63},
        {"fetched_at": "2026-09-19T00:00:00Z", "malicious": 30, "engines": 66},
    ]

    def test_initial_is_first_snapshot_after_submission(self):
        t = contrib.trajectory(self.SNAPS, "2026-08-24T16:12:59Z")
        self.assertEqual(t["initial"]["malicious"], 1)
        self.assertEqual(t["current"]["malicious"], 30)
        self.assertEqual(t["lift"], 29)
        self.assertEqual(len(t["points"]), 3)

    def test_falls_back_to_earliest(self):
        t = contrib.trajectory(self.SNAPS, "2026-10-01T00:00:00Z")
        self.assertEqual(t["initial"]["at"], "2026-08-20T00:00:00Z")

    def test_order_independent(self):
        t = contrib.trajectory(list(reversed(self.SNAPS)), "2026-08-24T16:12:59Z")
        self.assertEqual(t["current"]["at"], "2026-09-19T00:00:00Z")

    def test_no_snapshots(self):
        self.assertIsNone(contrib.trajectory([], None)["current"])


class ContributionListTests(DBTestCase):

    def snap(self, s, fetched_at, malicious, first=None):
        self.con.execute(
            "INSERT INTO vt_snapshots(sha256,fetched_at,malicious,engines,"
            "first_submission_date) VALUES(?,?,?,?,?)",
            (s, fetched_at, malicious, 63, first))
        self.con.commit()

    def test_duplicates_are_context_not_contributions(self):
        ours, theirs = sha(300), sha(301)
        self.add_submission(ours, "virustotal", "submitted", submitted_at=iso(days_ago=2))
        self.add_submission(theirs, "virustotal", "duplicate")
        self.add_submission(theirs, "malwarebazaar", "duplicate")

        items = contrib.contributions(self.con)
        self.assertEqual([i["sha256"] for i in items], [ours])
        s = contrib.summary(self.con, days=30)
        self.assertEqual(s["contributed_samples"], 1)
        self.assertEqual(s["contributed_window"], 1)
        self.assertEqual(s["by_service"]["virustotal"]["duplicate"], 1)

    def test_multi_service_sample_counts_once(self):
        s = sha(302)
        self.add_submission(s, "virustotal", "submitted", submitted_at=iso(days_ago=3))
        self.add_submission(s, "malwarebazaar", "submitted", submitted_at=iso(days_ago=2))
        items = contrib.contributions(self.con)
        self.assertEqual(len(items), 1)
        self.assertEqual(set(items[0]["services"]), {"virustotal", "malwarebazaar"})
        self.assertEqual(items[0]["first_contributed"][:10], iso(days_ago=3)[:10])

    def test_bazaar_only_contribution_has_no_attribution_claim(self):
        s = sha(303)
        self.add_submission(s, "malwarebazaar", "submitted")
        self.assertIsNone(contrib.contributions(self.con)[0]["attribution"])

    def test_attribution_and_trajectory_from_snapshots(self):
        s = sha(304)
        self.add_submission(s, "virustotal", "submitted",
                            submitted_at="2026-08-24T16:12:59Z")
        self.snap(s, "2026-08-25T00:00:00Z", 1, first=1787587979)
        self.snap(s, "2026-09-19T00:00:00Z", 30, first=1787587979)
        item = contrib.for_sample(self.con, s)
        self.assertEqual(item["attribution"], "confirmed")
        self.assertEqual(item["vt_first_submission"], "2026-08-24T16:12:59Z")
        self.assertEqual(item["detections"]["lift"], 29)
        s2 = contrib.summary(self.con)
        self.assertEqual(s2["confirmed_first"], 1)

    def test_window_excludes_old_contributions(self):
        self.add_submission(sha(305), "virustotal", "submitted", submitted_at=iso(days_ago=40))
        self.assertEqual(contrib.summary(self.con, days=30)["contributed_window"], 0)
        self.assertEqual(contrib.summary(self.con)["contributed_samples"], 1)

    def test_capture_context_comes_from_provenance(self):
        s = sha(306)
        self.add_submission(s, "virustotal", "submitted")
        self.con.execute(
            "INSERT INTO sample_provenance(sha256,first_seen,delivery,source_url,"
            "first_session) VALUES(?,?,?,?,?)",
            (s, "2026-08-24T16:10:00Z", "url", "http://203.0.113.5/x", "sessA"))
        self.con.commit()
        cap = contrib.for_sample(self.con, s)["capture"]
        self.assertEqual(cap["delivery"], "url")
        self.assertEqual(cap["first_session"], "sessA")

    def test_never_uploaded_has_no_record(self):
        s = sha(307)
        self.add_submission(s, "virustotal", "duplicate")
        self.assertIsNone(contrib.for_sample(self.con, s))


if __name__ == "__main__":
    unittest.main()
