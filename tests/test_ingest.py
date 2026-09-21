"""Ingest must keep its byte offset exactly in step with the spool file.

The pull appends raw bytes to the spool and ingest resumes from a stored
offset, so an offset that drifts even by one byte makes the next pass start
inside a line. The earlier text-mode reader decoded each line and advanced by
the re-encoded length, which is longer than the original whenever the line
held an invalid byte, so one such byte cost the next line that arrived.
"""

import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_ingest():
    spec = importlib.util.spec_from_file_location("ingest_under_test", os.path.join(ROOT, "ingest.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def event(n, **extra):
    body = {"eventid": "cowrie.login.failed", "session": "s%d" % n,
            "src_ip": "198.51.100.%d" % (n % 250 + 1),
            "timestamp": "2026-09-21T12:00:%02d.000000Z" % (n % 60)}
    body.update(extra)
    return json.dumps(body).encode() + b"\n"


class IngestOffsetTests(unittest.TestCase):
    def setUp(self):
        self.ingest = load_ingest()
        self.tmp = tempfile.mkdtemp(prefix="tr-ingest-")
        self.spool_file = os.path.join(self.tmp, "cowrie.json")
        self.conn = sqlite3.connect(os.path.join(self.tmp, "radar.db"))
        with open(os.path.join(ROOT, "schema.sql"), encoding="utf-8") as fh:
            self.conn.executescript(fh.read())

    def tearDown(self):
        self.conn.close()

    def append(self, data):
        with open(self.spool_file, "ab") as fh:
            fh.write(data)

    def events(self):
        return [r[0] for r in self.conn.execute(
            "SELECT session FROM raw_events WHERE eventid != 'radar.unparsed' ORDER BY session")]

    def offset(self):
        return self.conn.execute("SELECT byte_offset FROM ingest_state").fetchone()[0]

    def test_invalid_byte_does_not_cost_the_next_line(self):
        # A username field holding a byte that is not valid UTF-8, which
        # attacker input can produce, followed by ordinary events.
        bad = event(1)[:-3] + b'\xff"}\n'
        self.append(bad + event(2) + event(3))
        self.ingest.process_file(self.conn, self.spool_file)
        self.assertEqual(self.offset(), os.path.getsize(self.spool_file))

        self.append(event(4))
        self.ingest.process_file(self.conn, self.spool_file)
        self.assertEqual(self.offset(), os.path.getsize(self.spool_file))
        self.assertIn("s4", self.events(), "the line after an invalid byte was lost")
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM raw_events WHERE eventid = 'radar.unparsed'").fetchone()[0],
            0, "a pass started inside a line and recorded it as unparsed")

    def test_partial_last_line_is_held_back(self):
        whole = event(5)
        self.append(event(6) + whole[:20])
        self.ingest.process_file(self.conn, self.spool_file)
        self.assertEqual(self.events(), ["s6"])
        self.append(whole[20:])
        self.ingest.process_file(self.conn, self.spool_file)
        self.assertEqual(self.events(), ["s5", "s6"])


if __name__ == "__main__":
    unittest.main()
