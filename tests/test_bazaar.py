"""MalwareBazaar stage: account-level refusals stop the run without marking
samples as failed, samples missing from this host are counted, and the gates
for age and detections behave as documented."""

import json
import unittest
from unittest import mock

from tests.support import (DBTestCase, iso, is_mb_lookup, is_mb_upload, sha,
                           worker)
from app.analytics import db

NOT_FOUND = (200, {"query_status": "hash_not_found"})


def eligible(case, n, with_file=True):
    s = sha(n)
    case.add_payload(s, first_seen=iso(days_ago=1))
    case.add_intel(s, verdict="malicious", malicious=5)
    if with_file:
        case.write_sample(s, size=8192)
    return s


class AccountErrorTests(DBTestCase):

    def test_user_unknown_stops_stage_and_records_nothing(self):
        eligible(self, 10)
        eligible(self, 11)
        self.http.on(is_mb_lookup, NOT_FOUND)
        self.http.on(is_mb_upload, (200, {
            "error": "non-json response",
            "raw": "user_unknown: please visit https://bazaar.abuse.ch/login/ first"}))

        with mock.patch.object(worker, "MB_SUBMIT_MAX", 10):
            worker.submit_bazaar(self.con)

        self.assertEqual(self.http.count(is_mb_upload), 1,
                         "the stage must stop after the first account refusal")
        self.assertEqual(self.submissions("malwarebazaar"), {},
                         "an account problem is not a per-sample error")
        self.assertEqual(db.get_state(self.con, "bazaar_blocked"), "user_unknown")

    def test_blocked_state_clears_on_a_clean_run(self):
        db.set_state(self.con, "bazaar_blocked", "user_unknown")
        self.con.commit()
        worker.submit_bazaar(self.con)
        self.assertEqual(db.get_state(self.con, "bazaar_blocked"), "")

    def test_query_status_form_is_also_recognised(self):
        eligible(self, 12)
        self.http.on(is_mb_lookup, NOT_FOUND)
        self.http.on(is_mb_upload, (200, {"query_status": "user_blacklisted"}))
        worker.submit_bazaar(self.con)
        self.assertEqual(db.get_state(self.con, "bazaar_blocked"), "user_blacklisted")
        self.assertEqual(self.submissions("malwarebazaar"), {})


class MissingLocalTests(DBTestCase):

    def test_in_window_hashes_without_files_are_counted(self):
        eligible(self, 20, with_file=False)
        eligible(self, 21, with_file=False)
        eligible(self, 22, with_file=True)
        self.http.on(is_mb_lookup, (200, {"query_status": "ok",
                                          "data": [{"signature": "Mirai"}]}))

        worker.submit_bazaar(self.con)

        self.assertEqual(db.get_state(self.con, "bazaar_missing_local"), "2")
        self.assertEqual(self.http.count(is_mb_lookup), 1,
                         "only the sample on disk should cost a lookup")

    def test_count_is_complete_when_budget_runs_out(self):
        for n in range(30, 34):
            eligible(self, n)
        for n in range(40, 43):
            eligible(self, n, with_file=False)
        self.http.on(is_mb_lookup, (200, {"query_status": "ok", "data": [{}]}))

        with mock.patch.object(worker, "MB_SUBMIT_MAX", 1):
            worker.submit_bazaar(self.con)

        self.assertEqual(self.http.count(is_mb_lookup), 1)
        self.assertEqual(db.get_state(self.con, "bazaar_missing_local"), "3")


class UploadTests(DBTestCase):

    def test_inserted_is_recorded_with_permalink(self):
        s = eligible(self, 50)
        self.http.on(is_mb_lookup, NOT_FOUND)
        self.http.on(is_mb_upload, (200, {"query_status": "inserted"}))

        worker.submit_bazaar(self.con)

        row = self.submissions("malwarebazaar")[s]
        self.assertEqual(row["status"], "submitted")
        self.assertEqual(row["permalink"], f"https://bazaar.abuse.ch/sample/{s}/")

    def test_upload_metadata_is_attributed_and_clean(self):
        eligible(self, 51)
        self.http.on(is_mb_lookup, NOT_FOUND)
        self.http.on(is_mb_upload, (200, {"query_status": "inserted"}))

        worker.submit_bazaar(self.con)

        body = next(c["data"] for c in self.http.calls if is_mb_upload(c["url"], c["data"]))
        start = body.index(b'name="json_data"') + len(b'name="json_data"\r\n\r\n')
        meta = json.loads(body[start:body.index(b"\r\n", start)])
        self.assertEqual(meta["anonymous"], 0)
        self.assertIn("honeypot", meta["tags"])
        self.assertIn("elf", meta["tags"])
        self.assertNotRegex(meta["context"]["comment"], r"\d+\.\d+\.\d+\.\d+",
                            "the public comment must not carry an address")

    def test_known_to_bazaar_is_duplicate_not_ours(self):
        s = eligible(self, 52)
        self.http.on(is_mb_lookup, (200, {"query_status": "ok",
                                          "data": [{"signature": "Gafgyt"}]}))
        worker.submit_bazaar(self.con)
        self.assertEqual(self.submissions("malwarebazaar")[s]["status"], "duplicate")
        self.assertEqual(self.http.count(is_mb_upload), 0)


class GateTests(DBTestCase):

    def test_old_sample_is_skipped_permanently_without_network(self):
        s = sha(60)
        self.add_payload(s, first_seen=iso(days_ago=30))
        self.add_intel(s, malicious=9)
        self.write_sample(s)

        worker.submit_bazaar(self.con)

        row = self.submissions("malwarebazaar")[s]
        self.assertEqual(row["status"], "skipped")
        self.assertIn("window", row["detail"])
        self.assertEqual(self.http.calls, [])

    def test_below_detection_threshold_waits_without_a_row(self):
        s = sha(61)
        self.add_payload(s, first_seen=iso(days_ago=1))
        self.add_intel(s, verdict="undetected", malicious=0)
        self.write_sample(s)

        worker.submit_bazaar(self.con)

        self.assertNotIn(s, self.submissions("malwarebazaar"))
        self.assertEqual(self.http.calls, [])


class DecodeTests(unittest.TestCase):

    def test_non_json_keeps_status_and_raw_text(self):
        status, body = worker._decode(200, b"user_unknown: sign in first")
        self.assertEqual(status, 200)
        self.assertEqual(body["raw"], "user_unknown: sign in first")

    def test_empty_body_is_labelled(self):
        _, body = worker._decode(200, b"")
        self.assertEqual(body["raw"], "(empty body)")

    def test_json_passes_through(self):
        self.assertEqual(worker._decode(201, b'{"a": 1}'), (201, {"a": 1}))


if __name__ == "__main__":
    unittest.main()
