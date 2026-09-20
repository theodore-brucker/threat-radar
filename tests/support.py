"""Shared fixtures for the test suite.

Everything runs against a throwaway SQLite file built from schema.sql plus the
same migrations the worker applies, so the tests exercise the real schema
rather than a hand-written copy. Network calls are never made: the worker's
_http is replaced with a scripted fake, and time.sleep with a no-op.

Environment is set before anything from the app is imported, because db.py
and the worker read their paths and keys at import time.
"""

import datetime as dt
import importlib.util
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_TMP = tempfile.mkdtemp(prefix="tr-tests-")
os.environ["TR_APP"] = ROOT
os.environ["TR_BASE"] = ROOT
os.environ["TR_DB"] = os.path.join(_TMP, "placeholder.db")
os.environ["TR_VT_API_KEY"] = "test-vt"
os.environ["TR_URLHAUS_AUTH_KEY"] = "test-abuse"
os.environ.setdefault("TR_SAMPLE_DIR", os.path.join(_TMP, "samples"))

import sys  # noqa: E402

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.analytics import db  # noqa: E402


def load_worker():
    spec = importlib.util.spec_from_file_location(
        "intel_worker", os.path.join(ROOT, "bin", "intel_worker.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


worker = load_worker()


def iso(days_ago=0, hours_ago=0):
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago, hours=hours_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def sha(n):
    """A distinct, valid-looking sha256 per integer."""
    return f"{n:064x}"


class FakeHTTP:
    """Scripted stand-in for the worker's _http.

    Each rule is (predicate, response) where predicate sees (url, data) and
    response is a (status, body) tuple or a callable returning one. Every call
    is recorded so a test can assert what was, and was not, sent.
    """

    def __init__(self):
        self.rules = []
        self.calls = []

    def on(self, predicate, response):
        self.rules.append((predicate, response))
        return self

    def __call__(self, url, headers=None, data=None):
        self.calls.append({"url": url, "headers": headers or {}, "data": data})
        for pred, resp in self.rules:
            if pred(url, data):
                return resp(url, data) if callable(resp) else resp
        raise AssertionError(f"unexpected request to {url}")

    def count(self, predicate):
        return sum(1 for c in self.calls if predicate(c["url"], c["data"]))


def is_mb_lookup(url, data):
    return url == worker.MB_API and data is not None and b"query=get_info" in data


def is_mb_upload(url, data):
    return url == worker.MB_API and data is not None and b"json_data" in data


def is_vt_file(url, data):
    return url.startswith("https://www.virustotal.com/api/v3/files/")


def is_vt_upload(url, data):
    return url == "https://www.virustotal.com/api/v3/files"


class DBTestCase(unittest.TestCase):
    """Fresh database and sample directory per test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tr-case-", dir=_TMP)
        self.db_path = os.path.join(self.tmp, "radar.db")
        self.sample_dir = os.path.join(self.tmp, "samples")
        os.makedirs(self.sample_dir)

        con = sqlite3.connect(self.db_path)
        with open(os.path.join(ROOT, "schema.sql"), encoding="utf-8") as fh:
            con.executescript(fh.read())
        con.close()

        self.con = db.connect_rw(self.db_path)
        worker.ensure_schema(self.con)

        self.http = FakeHTTP()
        patches = [
            mock.patch.object(worker, "_http", self.http),
            mock.patch.object(worker.time, "sleep", lambda *_: None),
            mock.patch.object(worker, "SAMPLE_DIR", self.sample_dir),
            mock.patch.object(worker, "DRY_RUN_SUBMIT", False),
            mock.patch.object(worker, "log", lambda *_: None),
            mock.patch.object(db, "DB_PATH", self.db_path),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.con.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- builders -------------------------------------------------------

    def write_sample(self, sha256, size=4096, head=b"\x7fELF"):
        path = os.path.join(self.sample_dir, sha256)
        with open(path, "wb") as fh:
            fh.write(head + b"\x00" * max(0, size - len(head)))
        return path

    def add_payload(self, sha256, first_seen=None, url="", direction="download",
                    host=None):
        first_seen = first_seen or iso(days_ago=1)
        self.con.execute(
            "INSERT OR REPLACE INTO payloads(shasum,url,direction,filename,host,hits,"
            "sessions,src_ips,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (sha256, url, direction, "x", host, 1, 1, 1, first_seen, first_seen))
        self.con.commit()

    def add_intel(self, sha256, verdict="malicious", malicious=3, source="virustotal",
                  checked_at=None):
        self.con.execute(
            "INSERT OR REPLACE INTO payload_intel(indicator,kind,source,verdict,malicious,"
            "suspicious,harmless,undetected,label,reference,raw,checked_at)"
            " VALUES(?,?,?,?,?,0,0,60,NULL,NULL,NULL,?)",
            (sha256, "sha256", source, verdict, malicious,
             checked_at if checked_at is not None else iso()))
        self.con.commit()

    def add_submission(self, sha256, service="virustotal", status="submitted",
                       detail="uploaded", submitted_at=None, permalink=None):
        self.con.execute(
            "INSERT OR REPLACE INTO payload_submissions(sha256,service,status,analysis_id,"
            "permalink,detail,size_bytes,submitted_at) VALUES(?,?,?,?,?,?,?,?)",
            (sha256, service, status, None, permalink, detail, 4096,
             submitted_at or iso()))
        self.con.commit()

    def add_event(self, eventid, session, src_ip, ts, **payload):
        body = dict(payload, eventid=eventid, session=session, src_ip=src_ip,
                    timestamp=ts)
        self.con.execute(
            "INSERT INTO raw_events(line_hash,eventid,session,src_ip,ts,payload)"
            " VALUES(?,?,?,?,?,?)",
            (f"{session}-{ts}-{eventid}-{payload.get('shasum','')}", eventid,
             session, src_ip, ts, json.dumps(body)))
        self.con.commit()

    def submissions(self, service=None):
        sql = "SELECT * FROM payload_submissions"
        params = ()
        if service:
            sql += " WHERE service = ?"
            params = (service,)
        return {r["sha256"]: r for r in db.qall(self.con, sql, params)}
