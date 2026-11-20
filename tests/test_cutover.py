"""bin/cutover.py and the ingest floor it sets.

A purge removes everything dated before the cutover and nothing after it,
keeps the tables that describe samples and the trends feature, and leaves the
lifetime tables to be rebuilt from what remains. The ingest floor stops a
spool rescan from bringing removed events back.
"""

import datetime as dt
import hashlib
import importlib.util
import json
import os
import tempfile
from unittest import mock

from tests import fixtures
from tests.support import DBTestCase, ROOT, sha, worker


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cutover = _load("cutover", "bin/cutover.py")
ingest = _load("ingest_mod", "ingest.py")

TODAY = dt.datetime.now(dt.timezone.utc).date()
OLD_IP, NEW_IP = "192.0.2.50", "198.51.100.60"


def _stamp(day, hour):
    return "%sT%02d:15:30.123456Z" % (day.isoformat(), hour)


class CutoverCase(DBTestCase):
    def event(self, ts, eventid, session, src, **fields):
        body = dict(fields, eventid=eventid, session=session, src_ip=src, timestamp=ts)
        line = json.dumps(body)
        self.con.execute(
            "INSERT INTO raw_events(line_hash,eventid,session,src_ip,ts,payload)"
            " VALUES(?,?,?,?,?,?)",
            (hashlib.sha256(line.encode()).hexdigest(), eventid, session, src, ts, line))
        self.con.execute(
            "INSERT INTO sources(ip, first_seen, last_seen, event_count) VALUES(?,?,?,1)"
            " ON CONFLICT(ip) DO UPDATE SET event_count = event_count + 1,"
            " first_seen = MIN(first_seen, excluded.first_seen),"
            " last_seen = MAX(last_seen, excluded.last_seen)", (src, ts, ts))

    def session(self, day, src, session, user, password, sample):
        ts = _stamp(day, 1)
        self.event(ts, "cowrie.session.connect", session, src, dst_port=22)
        self.event(ts, "cowrie.login.success", session, src, username=user, password=password)
        self.event(_stamp(day, 2), "cowrie.command.input", session, src, input="uname -a")
        self.event(_stamp(day, 3), "cowrie.session.file_download", session, src,
                   shasum=sample, url="http://203.0.113.5/x", destfile="/tmp/x")
        self.event(_stamp(day, 4), "cowrie.session.closed", session, src, duration=4.0)

    def build(self):
        old_day = TODAY - dt.timedelta(days=3)
        self.session(old_day, OLD_IP, "aaaa0001", "oldonly", "oldpass", sha(1))
        self.session(TODAY, NEW_IP, "bbbb0001", "newonly", "newpass", sha(2))
        self.con.commit()
        self.rebuild()
        self.con.execute(
            "INSERT INTO payload_submissions(sha256, service, status, submitted_at)"
            " VALUES(?, 'virustotal', 'submitted', ?)", (sha(1), _stamp(old_day, 5)))
        self.con.execute(
            "INSERT INTO payload_intel(indicator, kind, source, verdict, malicious, checked_at)"
            " VALUES(?, 'sha256', 'virustotal', 'malicious', 12, ?)", (sha(1), _stamp(old_day, 5)))
        self.con.commit()

    def rebuild(self):
        for stage in (worker.build_facts, worker.build_sessions, worker.build_tunnels,
                      worker.build_payloads, worker.build_entities, worker.build_credentials):
            stage(self.con, True)
        worker.escmod.rebuild(self.con)
        worker.escmod.rebuild_daily(self.con, True, worker.RECENT_DAYS)
        self.con.commit()

    def count(self, sql, params=()):
        return self.con.execute(sql, params).fetchone()[0]


class PurgeTests(CutoverCase):
    def test_purge_removes_the_old_period_and_keeps_the_new(self):
        self.build()
        before = TODAY.isoformat()
        self.assertGreater(self.count("SELECT COUNT(*) FROM raw_events WHERE ts < ?", (before,)), 0)

        cutover.purge(self.con, before)

        self.assertEqual(self.count("SELECT COUNT(*) FROM raw_events WHERE ts < ?", (before,)), 0)
        self.assertEqual(self.count("SELECT COUNT(*) FROM raw_events WHERE src_ip = ?",
                                    (NEW_IP,)), 5)
        for table in cutover.DAY_TABLES:
            self.assertEqual(
                self.count(f"SELECT COUNT(*) FROM {table} WHERE day < ?", (before,)), 0, table)
        self.assertGreater(self.count("SELECT COUNT(*) FROM asn_ip_daily"), 0)
        self.assertEqual(self.count("SELECT COUNT(*) FROM payload_sightings WHERE ts < ?",
                                    (before,)), 0)
        for table in cutover.DERIVED_TABLES:
            self.assertEqual(self.count(f"SELECT COUNT(*) FROM {table}"), 0, table)
        self.assertEqual(self.count("SELECT COUNT(*) FROM payload_submissions"), 1)
        self.assertEqual(self.count("SELECT COUNT(*) FROM payload_intel"), 1)
        self.assertEqual(
            [r[0] for r in self.con.execute("SELECT ip FROM sources")], [NEW_IP])
        self.assertEqual(self.count("SELECT event_count FROM sources"), 5)
        self.assertEqual(self.con.execute(
            "SELECT value FROM insights_state WHERE key = 'data_floor'").fetchone()[0], before)

    def test_the_next_worker_pass_rebuilds_from_the_new_period_only(self):
        self.build()
        cutover.purge(self.con, TODAY.isoformat(), vacuum=True)
        self.rebuild()
        users = {r[0] for r in self.con.execute("SELECT username FROM cred_pairs")}
        self.assertEqual(users, {"newonly"})
        self.assertEqual({r[0] for r in self.con.execute("SELECT shasum FROM payloads")},
                         {sha(2)})
        self.assertEqual({r[0] for r in self.con.execute("SELECT src_ip FROM source_stage")},
                         {NEW_IP})

    def test_dry_run_changes_nothing(self):
        self.build()
        before = self.count("SELECT COUNT(*) FROM raw_events")
        with mock.patch("builtins.print"):
            rc = cutover.main(["--db", self.db_path, "purge", "--before", TODAY.isoformat()])
        self.assertEqual(rc, 0)
        self.assertEqual(self.count("SELECT COUNT(*) FROM raw_events"), before)

    def test_apply_through_the_command_line(self):
        self.build()
        with mock.patch("builtins.print"):
            rc = cutover.main(["--db", self.db_path, "purge", "--before",
                               TODAY.isoformat(), "--apply"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.count("SELECT COUNT(*) FROM raw_events WHERE src_ip = ?",
                                    (OLD_IP,)), 0)

    def test_a_future_cutover_is_refused(self):
        self.build()
        tomorrow = (TODAY + dt.timedelta(days=1)).isoformat()
        with mock.patch("builtins.print"):
            rc = cutover.main(["--db", self.db_path, "purge", "--before", tomorrow, "--apply"])
        self.assertEqual(rc, 2)
        self.assertEqual(self.count("SELECT COUNT(*) FROM raw_events WHERE src_ip = ?",
                                    (NEW_IP,)), 5)


class SampleListTests(CutoverCase):
    def test_only_samples_never_sighted_after_the_cutover_are_listed(self):
        self.build()
        for n in (1, 2):
            with open(os.path.join(self.sample_dir, sha(n)), "wb") as fh:
                fh.write(b"x")
        with open(os.path.join(self.sample_dir, ".fetched"), "wb"):
            pass
        listed = cutover.old_samples(self.con, TODAY.isoformat(), self.sample_dir)
        self.assertEqual(listed, [sha(1)])

        out = os.path.join(self.tmp, "old.txt")
        with mock.patch("builtins.print"):
            cutover.main(["--db", self.db_path, "samples", "--before", TODAY.isoformat(),
                          "--sample-dir", self.sample_dir, "--out", out])
        with open(out, encoding="ascii") as fh:
            self.assertEqual(fh.read(), sha(1) + "\n")


class ReportTests(CutoverCase):
    def test_report_covers_every_section_and_writes_both_forms(self):
        fixtures.build(self.con, worker, self.sample_dir)
        out = os.path.join(self.tmp, "report")
        tomorrow = (TODAY + dt.timedelta(days=1)).isoformat()
        with mock.patch("builtins.print"):
            rc = cutover.main(["--db", self.db_path, "report", "--before", tomorrow,
                               "--out", out])
        self.assertEqual(rc, 0)
        files = sorted(os.listdir(out))
        self.assertEqual([f.rsplit(".", 1)[1] for f in files], ["json", "md"])
        with open(os.path.join(out, files[0]), encoding="utf-8") as fh:
            rep = json.load(fh)
        keys = [s["key"] for s in rep["sections"]]
        for key in ("coverage", "by_epoch", "daily", "countries", "pairs", "payloads",
                    "commands", "sequences"):
            self.assertIn(key, keys)
        by_key = {s["key"]: s for s in rep["sections"]}
        self.assertTrue(by_key["commands"]["data"])
        self.assertTrue(by_key["payloads"]["data"])

    def test_attacker_text_reaches_the_report_inert(self):
        fixtures.build(self.con, worker, self.sample_dir)
        tomorrow = (TODAY + dt.timedelta(days=1)).isoformat()
        rep = cutover.build_report(self.con, tomorrow)
        text = cutover.report_markdown(rep)
        for bad in ("\x1b", "\x00", "\x07", "‮", "http://203.0.113"):
            self.assertNotIn(bad, text)
        tag = text.split("Recorded data sits between <", 1)[1].split(">", 1)[0]
        self.assertEqual(text.count("<%s>" % tag), text.count("</%s>" % tag))

    def test_redacted_strings_never_appear(self):
        fixtures.build(self.con, worker, self.sample_dir)
        tomorrow = (TODAY + dt.timedelta(days=1)).isoformat()
        with mock.patch.object(cutover.exportmod, "REDACT", ["jndi"]):
            rep = cutover.build_report(self.con, tomorrow)
        self.assertNotIn("jndi", json.dumps(rep))
        self.assertNotIn("jndi", cutover.report_markdown(rep))

    def test_epochs_split_the_period(self):
        self.con.execute("DELETE FROM persona_epochs")
        self.con.executemany(
            "INSERT INTO persona_epochs(start_day, name) VALUES(?, ?)",
            [("2026-01-10", "First"), ("2026-01-20", "Second")])
        segs = cutover.segments(self.con, "2026-01-01", "2026-02-01")
        self.assertEqual([(s["epoch"], s["from"], s["to"]) for s in segs], [
            ("stock Cowrie profile", "2026-01-01", "2026-01-10"),
            ("First", "2026-01-10", "2026-01-20"),
            ("Second", "2026-01-20", "2026-02-01"),
        ])
        self.assertEqual([s["days"] for s in segs], [9, 10, 12])


class IngestFloorTests(CutoverCase):
    def test_lines_before_the_floor_are_skipped_and_the_offset_still_advances(self):
        old = json.dumps({"eventid": "cowrie.session.connect", "session": "s1",
                          "src_ip": OLD_IP, "timestamp": "2026-01-01T10:00:00.000001Z"})
        new = json.dumps({"eventid": "cowrie.session.connect", "session": "s2",
                          "src_ip": NEW_IP, "timestamp": "2026-02-01T10:00:00.000001Z"})
        junk = "not json at all"
        spool = tempfile.mkdtemp(dir=self.tmp)
        path = os.path.join(spool, "cowrie.json.2026-02-01")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join([old, new, junk]) + "\n")
        self.con.execute("INSERT INTO insights_state(key, value, updated_at)"
                         " VALUES('data_floor', '2026-01-15', '2026-01-15')")
        self.con.commit()

        self.assertEqual(ingest.process_file(self.con, path), 3)
        ips = [r[0] for r in self.con.execute("SELECT src_ip FROM raw_events ORDER BY id")]
        self.assertEqual(ips, [NEW_IP, ""])
        offset = self.count("SELECT byte_offset FROM ingest_state")
        self.assertEqual(offset, os.path.getsize(path))

    def test_no_floor_means_nothing_is_skipped(self):
        self.assertIsNone(ingest.data_floor(self.con))
        self.assertFalse(ingest._before_floor("2020-01-01T00:00:00Z", None))
        self.assertFalse(ingest._before_floor("", "2026-01-15"))
