"""Incident trends: fetch, dedupe, cause rules, seed, rollup, API and export.

Each test builds a throwaway database from the trends migration alone, since
the feature reads none of the honeypot tables. No test touches the network:
fetches go through a scripted opener and the model through a scripted run.
"""

import datetime as dt
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import urllib.error
from unittest import mock

import tests.support  # noqa: F401  (sets the environment before app imports)
from app.analytics import clock, db
from app.trends import collectors, classify, fetch, rollup, seed

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATION = os.path.join(ROOT, "migrations", "trends", "001_trends.sql")

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Ransomware attack closes Example County offices</title>
<link>https://news.example/a</link><pubDate>Tue, 17 Nov 2026 12:00:00 GMT</pubDate>
<category>Government</category></item>
<item><title>Example Water Authority reports network outage</title>
<link>https://news.example/b</link><pubDate>Tue, 17 Nov 2026 13:00:00 GMT</pubDate></item>
<item><title>City of South Portland confirms cyberattack</title>
<link>https://news.example/c</link><pubDate>Mon, 16 Nov 2026 09:00:00 GMT</pubDate></item>
<item><title>not https</title><link>http://news.example/d</link></item>
</channel></rss>"""


def fresh_db(test):
    tmp = tempfile.mkdtemp(prefix="tr-trends-")
    test.addCleanup(shutil.rmtree, tmp, True)
    path = os.path.join(tmp, "radar.db")
    con = db.connect_rw(path)
    with open(MIGRATION, encoding="utf-8") as fh:
        con.executescript(fh.read())
    test.addCleanup(con.close)
    return path, con


class FakeResponse(io.BytesIO):
    def __init__(self, body, status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class MigrationTests(unittest.TestCase):
    def test_applies_twice(self):
        _, con = fresh_db(self)
        with open(MIGRATION, encoding="utf-8") as fh:
            con.executescript(fh.read())
        names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("incident", "organization", "vendor", "actor_claim", "cve", "source_item",
                  "statement", "incident_vendor", "incident_cve", "incident_claim"):
            self.assertIn(t, names)


class FetchTests(unittest.TestCase):
    def test_sends_stored_validators_and_reads_304_as_unchanged(self):
        _, con = fresh_db(self)
        fetch.save_state(con, "s", 200, '"abc"', "Tue, 17 Nov 2026 00:00:00 GMT", 10)
        seen = {}

        def opener(req, timeout):
            seen.update(dict(req.header_items()))
            raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", {}, None)

        status, body, _, _ = fetch.get("s", "https://x.example/feed", con, opener=opener)
        self.assertEqual((status, body), (304, None))
        self.assertEqual(seen.get("If-none-match"), '"abc"')
        self.assertIn("If-modified-since", seen)

    def test_refuses_an_oversized_body(self):
        def opener(req, timeout):
            return FakeResponse(b"x" * (fetch.MAX_BYTES + 1))
        with self.assertRaises(fetch.FetchError):
            fetch.get("s", "https://x.example/big", None, opener=opener)

    def test_the_cap_is_per_source(self):
        def opener(req, timeout):
            return FakeResponse(b"x" * (fetch.MAX_BYTES + 1))
        status, body, _, _ = fetch.get("s", "https://x.example/big", None, opener=opener,
                                       max_bytes=fetch.MAX_BYTES * 2)
        self.assertEqual((status, len(body)), (200, fetch.MAX_BYTES + 1))
        for name in ("cisa-kev", "cisa-advisories"):
            self.assertGreater(collectors.SOURCES[name]["max_bytes"], 2 * 1024 * 1024)

    def test_a_304_keeps_the_stored_etag(self):
        _, con = fresh_db(self)
        fetch.save_state(con, "s", 200, '"abc"', None, 10)
        fetch.save_state(con, "s", 304)
        self.assertEqual(con.execute("SELECT etag FROM trend_fetch_state").fetchone()[0], '"abc"')


class FeedDateTests(unittest.TestCase):
    """Feed dates become US Eastern days."""

    def test_rfc822_late_evening_eastern_stays_on_its_day(self):
        self.assertEqual(collectors._day("Sat, 21 Nov 2026 03:30:00 +0000"), "2026-11-20")
        self.assertEqual(collectors._day("Fri, 20 Nov 2026 22:30:00 -0500"), "2026-11-20")

    def test_rfc822_with_no_zone_is_read_as_utc(self):
        self.assertEqual(collectors._day("Sat, 21 Nov 2026 03:30:00 -0000"), "2026-11-20")

    def test_iso_values(self):
        self.assertEqual(collectors._day("2026-11-20"), "2026-11-20")
        self.assertEqual(collectors._day("2026-11-21T03:30:00Z"), "2026-11-20")
        self.assertEqual(collectors._day("2026-11-21T12:00:00+00:00"), "2026-11-21")

    def test_junk_is_none(self):
        for junk in (None, "", "not a date"):
            self.assertIsNone(collectors._day(junk))


class KeywordTests(unittest.TestCase):
    CASES = [
        ("Ransomware attack hits county", "malicious", True),
        ("District reports unauthorized access to email", "malicious", True),
        ("Hospital diverts patients after power failure", "nonmalicious", True),
        ("Courts close systems in precautionary shutdown", "nonmalicious", True),
        ("Network outage at city hall", "undisclosed", True),
        ("City confirms cyberattack", "undisclosed", False),
        ("Systems taken offline as a precaution after ransomware", "undisclosed", False),
    ]

    def test_rules(self):
        for text, status, decided in self.CASES:
            with self.subTest(text=text):
                self.assertEqual(classify.keyword(text), (status, decided))

    def test_word_boundaries(self):
        self.assertEqual(classify.keyword("Superpowered robotics team wins"), ("undisclosed", True))


class ModelTests(unittest.TestCase):
    def test_only_the_three_labels_are_accepted(self):
        text = 'ok [{"id": 1, "label": "malicious"}, {"id": 2, "label": "rm -rf"}, {"id": 9, "label": "malicious"}]'
        self.assertEqual(classify.parse_answer(text, 2), {0: "malicious"})

    def test_ambiguous_items_go_to_the_model_in_batches_and_are_cached(self):
        _, con = fresh_db(self)
        calls = []

        def run(cmd, input, **kw):
            calls.append((cmd, input))
            n = input.count("\n") - classify.RUBRIC.count("\n") - 1
            arr = [{"id": i, "label": "malicious"} for i in range(1, n + 1)]
            return mock.Mock(returncode=0, stdout=json.dumps({"result": json.dumps(arr)}))

        items = [{"item_hash": f"h{i}", "text": f"Town {i} confirms cyberattack"} for i in range(25)]
        items.append({"item_hash": "plain", "text": "Ransomware at the library"})
        out = classify.classify_items(con, items, use_model=True, run=run)
        self.assertEqual(len(calls), 2)
        self.assertIn("--disallowedTools", calls[0][0])
        self.assertEqual(out["plain"], ("malicious", "keyword"))
        self.assertEqual(out["h0"], ("malicious", "model"))
        again = classify.classify_items(con, items, use_model=True, run=run)
        self.assertEqual(len(calls), 2)
        self.assertEqual(again["h3"], ("malicious", "cache"))

    def test_a_failed_model_run_leaves_items_undisclosed(self):
        run = mock.Mock(return_value=mock.Mock(returncode=1, stdout=""))
        out = classify.classify_items(None, [{"item_hash": "a", "text": "breach at clinic"}], run=run)
        self.assertEqual(out["a"], ("undisclosed", "model-no-answer"))


class SeedTests(unittest.TestCase):
    def test_loads_every_row_once_with_low_confidence(self):
        _, con = fresh_db(self)
        with con:
            seed.load(con)
        with con:
            seed.load(con)
        q = lambda sql: con.execute(sql).fetchone()[0]  # noqa: E731
        self.assertEqual(q("SELECT COUNT(*) FROM incident WHERE kind='org'"), 214)
        self.assertEqual(q("SELECT COUNT(*) FROM incident WHERE kind='national'"), 8)
        self.assertEqual(q("SELECT COUNT(*) FROM incident WHERE confidence != 'low'"), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM incident WHERE source != 'seed'"), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM incident_vendor"), 3)
        self.assertEqual(q("SELECT customers FROM incident_vendor iv JOIN vendor v ON v.id=iv.vendor_id "
                           "WHERE v.slug='optimizely'"), 178)
        courts = q("SELECT i.title FROM incident_vendor iv JOIN vendor v ON v.id=iv.vendor_id "
                   "JOIN incident i ON i.id=iv.incident_id WHERE v.slug='journal-technologies'")
        self.assertIn("superior courts", courts)


class CollectorTests(unittest.TestCase):
    def test_rss_parse_keeps_https_items(self):
        rows = collectors.parse_rss(RSS)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["published"], "2026-11-17")
        self.assertEqual(rows[0]["categories"], "Government")

    def test_items_dedupe_and_open_or_join_incidents(self):
        _, con = fresh_db(self)
        with con:
            seed.load(con)
        rows = collectors.parse_rss(RSS)
        with con:
            n1 = collectors.store_items(con, "dysruptionhub", rows, False, True, "2026-11-15")
        with con:
            n2 = collectors.store_items(con, "dysruptionhub", rows, False, True, "2026-11-15")
        self.assertEqual((n1, n2), (3, 0))
        new = con.execute("SELECT title, cause_status FROM incident WHERE source='dysruptionhub' "
                          "ORDER BY title").fetchall()
        self.assertEqual([tuple(r) for r in new], [
            ("Example Water Authority reports network outage", "undisclosed"),
            ("Ransomware attack closes Example County offices", "malicious")])
        # The South Portland headline names a seed organization, so it becomes
        # a statement on the seed incident and opens no incident of its own.
        st = con.execute("SELECT i.source FROM statement s JOIN incident i ON i.id=s.incident_id "
                         "WHERE s.text LIKE '%South Portland%'").fetchone()
        self.assertEqual(st[0], "seed")

    def test_a_feed_with_a_dtd_is_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><rss><channel/></rss>'
        with self.assertRaises(ValueError):
            collectors.parse_rss(bomb)

    def test_claims_join_a_seed_incident(self):
        _, con = fresh_db(self)
        with con:
            seed.load(con)
            n = collectors.store_claims(con, [{"actor": "g", "victim": "City of South Portland",
                                               "country": "US", "discovered": "2026-11-20",
                                               "post_url": None}])
        self.assertEqual(n, 1)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM incident_claim").fetchone()[0], 1)

    def test_kev_and_claims_parse(self):
        kev = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1234", "vendorProject": "V",
                                               "product": "P", "dateAdded": "2026-11-10"},
                                              {"cveID": "junk"}]}).encode()
        self.assertEqual([r["cve_id"] for r in collectors.parse_kev(kev)], ["CVE-2026-1234"])
        claims = json.dumps([{"victim": "Acme", "group": "g", "country": "US",
                              "discovered": "2026-11-12", "url": "https://x/y"},
                             {"victim": "Elsewhere", "group": "g", "country": "FR"}]).encode()
        self.assertEqual(len(collectors.parse_claims(claims)), 1)


class RollupTests(unittest.TestCase):
    def test_least_squares(self):
        slope, intercept = rollup.least_squares([1, 3, 5, 7])
        self.assertAlmostEqual(slope, 2.0)
        self.assertAlmostEqual(intercept, 1.0)
        self.assertIsNone(rollup.least_squares([4]))

    def test_weeks_start_monday_and_include_empty_weeks(self):
        rows = [{"id": 1, "started": "2026-11-02", "cause_status": "malicious"},
                {"id": 2, "started": "2026-11-08", "cause_status": "undisclosed"},
                {"id": 3, "started": "2026-11-17", "cause_status": "undisclosed"}]
        weeks, _ = rollup.weekly(rows, "2026-11-17")
        self.assertEqual([w["week"] for w in weeks], ["2026-11-02", "2026-11-09", "2026-11-16"])
        self.assertEqual([w["incidents"] for w in weeks], [2, 0, 1])
        self.assertEqual([w["partial"] for w in weeks], [0, 0, 1])
        self.assertEqual(weeks[0]["undisclosed_ids"], [2])

    def test_cluster_flag(self):
        days = ["2026-11-01", "2026-11-12", "2026-11-13", "2026-11-16", "2026-11-25", "2026-11-28"]
        out = rollup.clusters([{"id": i, "started": d} for i, d in enumerate(days)])
        self.assertEqual(out, [{"first_day": "2026-11-12", "last_day": "2026-11-16",
                                "outages": 3, "ids": [1, 2, 3]}])
        self.assertEqual(rollup.clusters([{"id": 1, "started": "2026-11-12"},
                                          {"id": 2, "started": "2026-11-17"},
                                          {"id": 3, "started": "2026-11-18"}]), [])

    def test_seed_rollup(self):
        _, con = fresh_db(self)
        with con:
            seed.load(con)
            res = rollup.rebuild(con, "2026-11-17")
        self.assertEqual(res["clusters"], 1)
        self.assertEqual(res["fanouts"], 3)
        total = con.execute("SELECT SUM(incidents) FROM trend_weekly").fetchone()[0]
        self.assertEqual(total, 215)  # 214 seed rows plus the Optimizely outage
        ids = json.loads(con.execute("SELECT ids FROM trend_cluster").fetchone()[0])
        self.assertEqual(len(ids), 8)


class ApiTests(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app.main import app
        path, con = fresh_db(self)
        with con:
            seed.load(con)
            rollup.rebuild(con, "2026-11-17")
        p = mock.patch.object(db, "DB_PATH", path)
        p.start()
        self.addCleanup(p.stop)
        self.client = TestClient(app)
        self.con = con

    def test_summary_envelope(self):
        r = self.client.get("/api/v1/trends/summary?days=30")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["ok"])
        self.assertIn("generated_at", body)
        d = body["data"]
        self.assertTrue(d["built"])
        self.assertEqual(d["totals"]["incidents"], len(d["totals"]["ids"]))
        self.assertEqual(len(d["clusters"]), 1)

    def test_every_week_lists_its_rows(self):
        weeks = self.client.get("/api/v1/trends/summary").json()["data"]["weeks"]
        w = next(x for x in weeks if x["incidents"])
        ids = ",".join(map(str, w["ids"]))
        rows = self.client.get(f"/api/v1/trends/rows?ids={ids}").json()["data"]["rows"]
        self.assertEqual(len(rows), w["incidents"])

    def test_bad_ids_are_a_400(self):
        self.assertEqual(self.client.get("/api/v1/trends/rows?ids=1,x").status_code, 400)

    def test_records_and_exports(self):
        iid = self.con.execute("SELECT id FROM incident WHERE kind='national' LIMIT 1").fetchone()[0]
        self.assertEqual(self.client.get(f"/api/v1/trends/incident/{iid}").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/trends/vendor/optimizely").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/trends/organization/city-of-south-portland").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/trends/vendor/Bad%20Slug").status_code, 400)
        self.assertEqual(self.client.get("/api/v1/trends/incident/999999").status_code, 404)
        md = self.client.get(f"/api/v1/trends/export/incident/{iid}?format=md&download=1")
        self.assertEqual(md.status_code, 200)
        self.assertIn("## Statements", md.text)
        self.assertIn("attachment;", md.headers["content-disposition"])
        js = self.client.get("/api/v1/trends/export/vendor/optimizely").json()
        self.assertEqual(js["data"]["subject"]["type"], "vendor")

    def test_pages_answer_with_the_shell(self):
        for path in ("/trends", "/incident/1", "/vendor/optimizely", "/organization/x"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_an_unbuilt_database_says_so(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        empty = os.path.join(tmp, "empty.db")
        sqlite3.connect(empty).close()
        with mock.patch.object(db, "DB_PATH", empty):
            d = self.client.get("/api/v1/trends/summary").json()["data"]
        self.assertEqual(d, {"built": False})


def load_worker():
    import importlib.util
    spec = importlib.util.spec_from_file_location("trends_worker", os.path.join(ROOT, "bin", "trends_worker.py"))
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    return worker


def fake_get(source, url, con=None, headers=None, opener=None, max_bytes=None):
    if source == "cisa-kev":
        return 200, json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}).encode(), '"k"', None
    if source == "cisa-advisories":
        return 304, None, None, None
    if source == "dysruptionhub":
        return 200, RSS, '"d"', "Tue, 17 Nov 2026 13:00:00 GMT"
    raise fetch.FetchError(f"{source}: refused")


class WorkerRunTests(unittest.TestCase):
    def setUp(self):
        self.worker = load_worker()
        self.path, self.con = fresh_db(self)
        for p in (mock.patch.object(db, "DB_PATH", self.path),
                  mock.patch.object(fetch, "get", side_effect=fake_get),
                  mock.patch.object(classify, "model_available", return_value=False),
                  mock.patch.dict(os.environ, {"TR_RANSOMWARE_LIVE_TOKEN": "t"})):
            p.start()
            self.addCleanup(p.stop)

    def run_main(self, *args):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            code = self.worker.main(list(args))
        return code, out.getvalue()

    def test_a_full_run_loads_collects_and_rolls_up(self):
        code, out = self.run_main()
        self.assertEqual(code, 0)
        q = lambda sql: self.con.execute(sql).fetchone()[0]  # noqa: E731
        self.assertEqual(q("SELECT COUNT(*) FROM incident WHERE kind='org' AND source='seed'"), 214)
        self.assertEqual(q("SELECT COUNT(*) FROM cve"), 1)
        self.assertEqual(q("SELECT COUNT(*) FROM source_item WHERE source='dysruptionhub'"), 3)
        self.assertEqual(q("SELECT last_status FROM trend_fetch_state WHERE source='cisa-advisories'"), "304")
        self.assertEqual(q("SELECT last_status FROM trend_fetch_state WHERE source='ransomware-live'"), "error")
        self.assertGreater(q("SELECT COUNT(*) FROM trend_weekly"), 0)
        self.assertIn("bytes written", out)
        # A second run straight after finds nothing due and leaves the rollup alone.
        built = q("SELECT value FROM trend_meta WHERE key='built_at'")
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertNotIn("dysruptionhub", out)
        self.assertEqual(q("SELECT value FROM trend_meta WHERE key='built_at'"), built)

    def test_one_source_and_a_forced_rollup(self):
        code, out = self.run_main("--source", "dysruptionhub", "--rollup", "--no-model")
        self.assertEqual(code, 0)
        self.assertIn("rollup", out)
        self.assertNotIn("cisa-kev", out)

    def test_every_source_failing_is_a_failed_run(self):
        code, _ = self.run_main("--source", "ransomware-live")
        self.assertEqual(code, 1)

    def test_a_spent_write_budget_skips_collection(self):
        self.con.execute("INSERT INTO trend_write_log(day, bytes) VALUES(?, ?)",
                         (clock.today(), 10 ** 9))
        self.con.commit()
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("write budget", out)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM incident").fetchone()[0], 0)

    def test_dry_run_main_writes_nothing(self):
        self.run_main()
        before = self.con.execute("SELECT COUNT(*) FROM source_item").fetchone()[0]
        with mock.patch.dict(os.environ, {"TR_RANSOMWARE_LIVE_TOKEN": ""}):
            code, out = self.run_main("--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("seed rows", out)
        self.assertIn("is not set", out)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM source_item").fetchone()[0], before)

    def test_recheck_takes_a_later_stated_cause(self):
        self.run_main()
        iid = self.con.execute("SELECT id FROM incident WHERE cause_status='undisclosed' "
                               "AND kind='org' LIMIT 1").fetchone()[0]
        self.con.execute("UPDATE incident SET rechecked_at=NULL WHERE id=?", (iid,))
        self.con.execute("INSERT INTO statement(incident_id, stated_at, cause_status, text) "
                         "VALUES(?, '2026-11-18', 'malicious', 'ransomware confirmed')", (iid,))
        self.con.commit()
        res = self.worker.recheck(self.con, dt.datetime.now(dt.timezone.utc))
        self.assertGreaterEqual(res["changed"], 1)
        self.assertEqual(self.con.execute("SELECT cause_status FROM incident WHERE id=?",
                                          (iid,)).fetchone()[0], "malicious")

    def test_written_bytes_reads_proc(self):
        self.assertIsInstance(self.worker.written_bytes(), int)


class WorkerTests(unittest.TestCase):
    def test_dry_run_writes_nothing(self):
        worker = load_worker()
        path, con = fresh_db(self)
        with mock.patch.object(fetch, "get", return_value=(200, RSS, '"e"', None)):
            res = worker.collect(con, "dysruptionhub", collectors.SOURCES["dysruptionhub"], False, True)
        self.assertEqual(res["rows"], 3)
        self.assertEqual(res["ambiguous"], 1)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM source_item").fetchone()[0], 0)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM trend_fetch_state").fetchone()[0], 0)

    def test_due(self):
        worker = load_worker()
        _, con = fresh_db(self)
        now = dt.datetime(2026, 11, 17, 12, tzinfo=dt.timezone.utc)
        self.assertTrue(worker.due(con, "s", 6, now))
        con.execute("INSERT INTO trend_fetch_state(source, last_run) VALUES('s', '2026-11-17T10:00:00Z')")
        self.assertFalse(worker.due(con, "s", 6, now))
        self.assertTrue(worker.due(con, "s", 2, now))


if __name__ == "__main__":
    unittest.main()
