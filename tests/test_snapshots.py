"""VirusTotal snapshots: every successful file lookup leaves a row, 404s leave
none, and our own uploads are refreshed daily and looked up first."""

import unittest
from unittest import mock

from tests.support import DBTestCase, iso, is_vt_file, sha, worker
from app.analytics import db


def vt_body(malicious=4, undetected=58, first=1756051945, times=1):
    return (200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0,
                                "undetected": undetected, "harmless": 0},
        "first_submission_date": first,
        "last_submission_date": first + 60,
        "times_submitted": times,
        "popular_threat_classification": {"suggested_threat_label": "trojan.mirai/gafgyt"},
        "type_description": "ELF",
    }}})


class SnapshotTests(DBTestCase):

    def test_lookup_records_snapshot_with_submission_fields(self):
        s = sha(100)
        self.http.on(is_vt_file, vt_body(malicious=7, undetected=55))

        worker.vt_lookup(self.con, s, "sha256")

        rows = db.qall(self.con, "SELECT * FROM vt_snapshots WHERE sha256 = ?", (s,))
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["malicious"], r["engines"]), (7, 62))
        self.assertEqual(r["first_submission_date"], 1756051945)
        self.assertEqual(r["times_submitted"], 1)
        self.assertIn("mirai", r["label"])

    def test_missing_submission_fields_stay_null(self):
        s = sha(101)
        self.http.on(is_vt_file, (200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 1, "undetected": 60}}}}))
        worker.vt_lookup(self.con, s, "sha256")
        r = db.qone(self.con, "SELECT * FROM vt_snapshots WHERE sha256 = ?", (s,))
        self.assertIsNone(r["first_submission_date"])
        self.assertIsNone(r["times_submitted"])

    def test_not_found_leaves_no_snapshot(self):
        s = sha(102)
        self.http.on(is_vt_file, (404, {"error": {"code": "NotFoundError"}}))
        worker.vt_lookup(self.con, s, "sha256")
        self.assertIsNone(db.qone(self.con, "SELECT 1 FROM vt_snapshots WHERE sha256 = ?", (s,)))

    def test_url_lookups_do_not_snapshot(self):
        self.http.on(lambda u, d: "/api/v3/urls/" in u, vt_body())
        worker.vt_lookup(self.con, "http://203.0.113.9/x.sh", "url")
        self.assertIsNone(db.qone(self.con, "SELECT 1 FROM vt_snapshots"))


class RefreshCadenceTests(DBTestCase):

    def test_contributed_hash_goes_stale_after_one_day(self):
        s = sha(110)
        self.add_intel(s, checked_at=iso(days_ago=2))
        self.assertFalse(worker._stale(self.con, s, "virustotal"))
        self.assertTrue(worker._stale(self.con, s, "virustotal", ttl_days=1))

    def test_ttl_override_never_lengthens(self):
        s = sha(111)
        self.add_intel(s, verdict="unknown", malicious=0, checked_at=iso(days_ago=2))
        self.assertTrue(worker._stale(self.con, s, "virustotal", ttl_days=30))

    def test_contributed_hashes_are_looked_up_first(self):
        ours, other = sha(120), sha(121)
        for s in (other, ours):
            self.add_payload(s)
            self.add_intel(s, checked_at=iso(days_ago=10))
        self.add_submission(ours, status="submitted", submitted_at=iso(days_ago=20))
        self.http.on(is_vt_file, vt_body())
        self.http.on(lambda u, d: "urlhaus" in u, (200, {"query_status": "no_results"}))

        with mock.patch.object(worker, "VT_MAX", 1):
            worker.enrich(self.con)

        vt_calls = [c["url"] for c in self.http.calls if is_vt_file(c["url"], None)]
        self.assertEqual(vt_calls, [f"https://www.virustotal.com/api/v3/files/{ours}"])

    def test_contributed_hash_refreshes_even_after_its_events_age_out(self):
        ours = sha(130)  # uploaded long ago; no payloads row any more
        self.add_intel(ours, checked_at=iso(days_ago=3))
        self.add_submission(ours, status="submitted", submitted_at=iso(days_ago=40))
        self.http.on(is_vt_file, vt_body())
        self.http.on(lambda u, d: "urlhaus" in u, (200, {"query_status": "no_results"}))

        worker.enrich(self.con)

        self.assertEqual(self.http.count(lambda u, d: u.endswith(ours)), 1)


if __name__ == "__main__":
    unittest.main()
