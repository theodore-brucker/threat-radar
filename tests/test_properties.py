"""Properties that must hold for any input, checked with generated input.

Everything here consumes strings an attacker chose, so the useful question is
not whether a handful of examples work but whether any input at all breaks the
rule. Hypothesis generates inputs, including the awkward ones people forget,
and shrinks any failure to the smallest example that shows it.
"""

import importlib.util
import os
import re
import sqlite3
import tempfile
import unittest

from hypothesis import HealthCheck, given, settings, strategies as st

from app.analytics import credentials, sessions

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


udb = _load("cowrie_userdb", "sensor/bin/cowrie_userdb.py")
ingest = _load("ingest_props", "ingest.py")

text = st.text(max_size=300)
settled = settings(max_examples=400, deadline=None,
                   suppress_health_check=[HealthCheck.too_slow])


class UserdbProperties(unittest.TestCase):
    @settled
    @given(login=text, passwd=text)
    def test_anything_the_generator_accepts_loads_cleanly(self, login, passwd):
        # The invariant that keeps an attacker-built userdb from taking the
        # sensor offline: the generator's rule implies the gate's.
        if udb.literal_pair_problem(login, passwd) is None:
            self.assertIsNone(udb.check_line(udb.format_pair(login, passwd)))
            usable, findings = udb.check_file((udb.format_pair(login, passwd) + "\n").encode("ascii"))
            self.assertEqual((usable, findings), (1, []))

    @settled
    @given(st.binary(max_size=2000))
    def test_the_checker_never_raises_on_any_file(self, data):
        usable, findings = udb.check_file(data)
        self.assertGreaterEqual(usable, 0)
        for number, severity, _text, _why in findings:
            self.assertIn(severity, (udb.FATAL, udb.WARN))


class SampleTextProperties(unittest.TestCase):
    @settled
    @given(st.binary(max_size=3000))
    def test_display_text_is_never_runnable(self, body):
        out = sessions._safe_text(body)
        self.assertIsNone(re.search(r"(?i)\b(?:https?|ftp)://", out))
        self.assertIsNone(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", out))
        bad = [c for c in out if not (c in "\n\t" or 32 <= ord(c) < 127 or ord(c) > 159)]
        self.assertEqual(bad, [])

    @settled
    @given(st.from_regex(r"https?://([a-z0-9-]{1,12}\.){1,3}[a-z]{2,6}(:[0-9]{2,5})?/[a-z0-9./_-]{0,20}",
                         fullmatch=True))
    def test_any_url_comes_back_defanged(self, url):
        out = sessions._safe_text(url.encode())
        self.assertTrue(out.lower().startswith("hxxp"), out)
        host = out.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        self.assertNotIn(".", host.replace("[.]", ""), out)


class CredentialProperties(unittest.TestCase):
    rules = None

    @classmethod
    def setUpClass(cls):
        cls.rules, _ = credentials.load_rules(os.path.join(ROOT, "config", "credential_tags.json"),
                                              extra_path="/nonexistent")

    @settled
    @given(username=text, password=text)
    def test_tagging_never_raises_and_returns_known_tags(self, username, password):
        tags = credentials.tag_pair(username, password, self.rules)
        # Pairs no rule matches get a deliberate fallback so the credentials
        # page still shows them. It stands alone, never beside a real tag.
        known = {r["tag"] for r in self.rules} | set(credentials.STRUCTURAL_TAGS)
        self.assertLessEqual(set(tags), known)
        self.assertTrue(tags, "every pair gets at least one tag")
        if "unclustered" in tags:
            self.assertEqual(tags, ["unclustered"])


class IngestProperties(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="tr-props-")

    def connect(self):
        con = sqlite3.connect(":memory:")
        with open(os.path.join(ROOT, "schema.sql"), encoding="utf-8") as fh:
            con.executescript(fh.read())
        return con

    @settled
    @given(st.text(max_size=500))
    def test_any_line_is_stored_or_ignored_never_raises(self, line):
        con = self.connect()
        ingest.ingest_line(con, line)
        rows = con.execute("SELECT eventid FROM raw_events").fetchall()
        self.assertLessEqual(len(rows), 1)

    @settled
    @given(st.lists(st.binary(min_size=1, max_size=80).filter(lambda b: b"\n" not in b),
                    min_size=1, max_size=20), st.integers(min_value=1, max_value=19))
    def test_offset_always_lands_on_a_line_boundary(self, lines, split):
        # However the file is split between passes, the stored offset must
        # end exactly after the last complete line read.
        path = os.path.join(self.tmp, "cowrie.json")
        data = b"".join(b + b"\n" for b in lines)
        cut = min(split * 7, len(data))
        con = self.connect()
        with open(path, "wb") as fh:
            fh.write(data[:cut])
        ingest.process_file(con, path)
        with open(path, "ab") as fh:
            fh.write(data[cut:])
        ingest.process_file(con, path)
        offset = con.execute("SELECT byte_offset FROM ingest_state").fetchone()[0]
        self.assertEqual(offset, len(data))


if __name__ == "__main__":
    unittest.main()
