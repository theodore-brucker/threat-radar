"""sample_provenance keeps a sample's capture context after the raw events
behind it are pruned, and only ever widens what it knows."""

import unittest

from tests.support import DBTestCase, sha, worker
from app.analytics import db

DL = "cowrie.session.file_download"
UL = "cowrie.session.file_upload"


class ProvenanceTests(DBTestCase):

    def prov(self, s):
        return db.qone(self.con, "SELECT * FROM sample_provenance WHERE sha256 = ?", (s,))

    def test_survives_raw_event_pruning(self):
        s = sha(200)
        self.add_event(DL, "sessA", "198.51.100.7", "2026-08-24T16:10:00Z",
                       shasum=s, url="http://203.0.113.5/bins/x86", destfile="/tmp/x")
        worker.build_payloads(self.con)
        before = self.prov(s)
        self.assertEqual(before["first_session"], "sessA")
        self.assertEqual(before["delivery"], "url")
        self.assertEqual(before["host"], "203.0.113.5")

        self.con.execute("DELETE FROM raw_events")
        self.con.commit()
        worker.build_payloads(self.con)

        self.assertIsNone(db.qone(self.con, "SELECT 1 FROM payloads WHERE shasum = ?", (s,)))
        after = self.prov(s)
        self.assertEqual(after["first_seen"], "2026-08-24T16:10:00Z")
        self.assertEqual(after["first_session"], "sessA")
        self.assertEqual(after["source_url"], "http://203.0.113.5/bins/x86")

    def test_counts_never_shrink(self):
        s = sha(201)
        for i, ip in enumerate(("198.51.100.1", "198.51.100.2", "198.51.100.3")):
            self.add_event(DL, f"s{i}", ip, f"2026-09-0{i + 1}T00:00:00Z",
                           shasum=s, url="http://203.0.113.5/a")
        worker.build_payloads(self.con)
        self.assertEqual(self.prov(s)["src_ips"], 3)

        self.con.execute("DELETE FROM raw_events WHERE session IN ('s0','s1')")
        self.con.commit()
        worker.build_payloads(self.con)

        p = self.prov(s)
        self.assertEqual(p["src_ips"], 3)
        self.assertEqual(p["sessions"], 3)
        self.assertEqual(p["first_seen"], "2026-09-01T00:00:00Z")

    def test_earlier_sighting_replaces_first_fields(self):
        s = sha(202)
        self.add_event(DL, "late", "198.51.100.9", "2026-09-10T00:00:00Z",
                       shasum=s, url="http://203.0.113.5/late")
        worker.build_payloads(self.con)
        self.add_event(DL, "early", "198.51.100.8", "2026-09-01T00:00:00Z",
                       shasum=s, url="http://203.0.113.5/early")
        worker.build_payloads(self.con)

        p = self.prov(s)
        self.assertEqual(p["first_session"], "early")
        self.assertEqual(p["first_src_ip"], "198.51.100.8")
        self.assertEqual(p["source_url"], "http://203.0.113.5/early")
        self.assertEqual(p["last_seen"], "2026-09-10T00:00:00Z")

    def test_delivery_classification(self):
        inband, pushed = sha(203), sha(204)
        self.add_event(DL, "a", "198.51.100.1", "2026-09-01T00:00:00Z",
                       shasum=inband, url="/tmp/.x", destfile="/tmp/.x")
        self.add_event(UL, "b", "198.51.100.2", "2026-09-01T00:00:00Z",
                       shasum=pushed, filename="payload")
        worker.build_payloads(self.con)
        self.assertEqual(self.prov(inband)["delivery"], "inband")
        self.assertIsNone(self.prov(inband)["source_url"])
        self.assertEqual(self.prov(pushed)["delivery"], "upload")

    def test_empty_transfer_is_not_a_sample(self):
        self.add_event(DL, "a", "198.51.100.1", "2026-09-01T00:00:00Z",
                       shasum=worker.EMPTY_SHA256, url="http://203.0.113.5/e")
        worker.build_payloads(self.con)
        self.assertIsNone(self.prov(worker.EMPTY_SHA256))


if __name__ == "__main__":
    unittest.main()
