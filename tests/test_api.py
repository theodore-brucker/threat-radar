"""API surface: the contributions endpoint, the payloads response that feeds
the page, and the overview count that used to include duplicates."""

import unittest

from fastapi.testclient import TestClient

from tests.support import DBTestCase, iso, sha


class ApiTests(DBTestCase):

    def setUp(self):
        super().setUp()
        from app.main import app
        self.client = TestClient(app)

    def test_contributions_endpoint(self):
        s = sha(400)
        self.add_submission(s, "virustotal", "submitted")
        self.add_submission(sha(401), "virustotal", "duplicate")

        r = self.client.get("/api/v1/contributions")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["ok"])
        items = body["data"]["contributions"]
        self.assertEqual([i["sha256"] for i in items], [s])
        self.assertEqual(body["data"]["summary"]["contributed_samples"], 1)

    def test_payloads_response_carries_contributions(self):
        self.add_submission(sha(402), "malwarebazaar", "submitted")
        r = self.client.get("/api/v1/payloads?days=30")
        self.assertEqual(r.status_code, 200)
        c = r.json()["data"]["contributions"]
        self.assertEqual(c["summary"]["contributed_window"], 1)
        self.assertEqual(len(c["items"]), 1)
        self.assertNotIn("submissions", r.json()["data"])

    def test_sample_detail_includes_contribution(self):
        s = sha(403)
        self.add_submission(s, "virustotal", "submitted")
        r = self.client.get(f"/api/v1/samples/{s}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["contribution"]["sha256"], s)

    def _seed_mixed_statuses(self):
        self.add_submission(sha(404), "virustotal", "submitted", submitted_at=iso())
        for n in range(405, 410):
            self.add_submission(sha(n), "virustotal", "duplicate", submitted_at=iso())
        self.add_submission(sha(410), "malwarebazaar", "duplicate", submitted_at=iso())

    def test_overview_headline_counts_only_real_uploads(self):
        from app.analytics import overview
        self._seed_mixed_statuses()
        self.assertEqual(overview.headline(self.con, 30)["submitted_samples"], 1)

    def test_escalation_rail_counts_only_real_uploads(self):
        from app.analytics import escalation
        self._seed_mixed_statuses()
        stages = {s["key"]: s["count"] for s in escalation.rail(self.con, 30)["stages"]}
        self.assertEqual(stages["submitted"], 1)


if __name__ == "__main__":
    unittest.main()
