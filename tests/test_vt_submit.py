"""VirusTotal submission stage: permanent skips stay put, transient skips are
retried, and recording hashes VirusTotal already held never overwrites a row
that says we uploaded the file."""

import unittest

from tests.support import DBTestCase, iso, is_vt_upload, sha, worker


class SizeSkipTests(DBTestCase):

    def test_size_skip_is_not_reevaluated(self):
        s = sha(1)
        self.add_payload(s)
        self.add_intel(s, verdict="unknown", malicious=0)
        old = iso(days_ago=5)
        self.add_submission(s, status="skipped", detail="size 25 out of range",
                            submitted_at=old)

        worker.submit_samples(self.con)

        row = self.submissions("virustotal")[s]
        self.assertEqual(row["status"], "skipped")
        self.assertEqual(row["submitted_at"], old,
                         "a permanent size skip must keep its original timestamp")
        self.assertEqual(self.http.calls, [])

    def test_missing_file_skip_is_retried(self):
        s = sha(2)
        self.add_payload(s)
        self.add_intel(s, verdict="unknown", malicious=0)
        self.add_submission(s, status="skipped", detail="sample file not on this host",
                            submitted_at=iso(days_ago=2))
        self.write_sample(s, size=2048)
        self.http.on(is_vt_upload, (200, {"data": {"id": "analysis-1"}}))

        worker.submit_samples(self.con)

        row = self.submissions("virustotal")[s]
        self.assertEqual(row["status"], "submitted")
        self.assertEqual(row["analysis_id"], "analysis-1")
        self.assertEqual(self.http.count(is_vt_upload), 1)


class KnownBackfillTests(DBTestCase):

    def test_known_hashes_recorded_as_duplicate(self):
        s = sha(3)
        self.add_payload(s)
        self.add_intel(s, verdict="malicious", malicious=12)

        worker.submit_samples(self.con)

        self.assertEqual(self.submissions("virustotal")[s]["status"], "duplicate")

    def test_backfill_never_overwrites_submitted(self):
        s = sha(4)
        self.add_payload(s)
        when = iso(days_ago=3)
        self.add_submission(s, status="submitted", submitted_at=when)
        # VirusTotal now knows the file because we uploaded it.
        self.add_intel(s, verdict="malicious", malicious=20)

        worker.submit_samples(self.con)

        row = self.submissions("virustotal")[s]
        self.assertEqual(row["status"], "submitted")
        self.assertEqual(row["submitted_at"], when)


if __name__ == "__main__":
    unittest.main()
