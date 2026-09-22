"""The userdb generator, end to end, against the kind of data it really gets.

This script's output decides whether the sensor can authenticate anyone. An
earlier version wrote a line with an empty password and the sensor answered
no one for seventeen days. Every test here builds a database of observed
logins, including the hostile ones an attacker can spray into the top of the
list, runs the real script, and reads the file back through the same checker
the sensor's start-up gate uses.
"""

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "bin", "build_userdb.py")
spec = importlib.util.spec_from_file_location("cowrie_userdb", os.path.join(ROOT, "sensor", "bin", "cowrie_userdb.py"))
udb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(udb)

# Pairs Cowrie would misread, each sprayed often enough to reach the top.
HOSTILE = [("root2", ""), ("user", "   "), ("user", "/[/"), ("user", "/.*/"), ("*", "x"),
           ("user", "*"), ("user", "!QAZ2wsx"), ("colon:in", "pw"), ("user", "pässword"),
           ("#admin", "pw"), ("user", "two\nlines"), ("has space", "pw"), ("user", "trailing ")]
GOOD = [("ubuntu", "ubuntu"), ("oracle", "oracle123"), ("git", "a/b"), ("test", "two words"),
        ("pi", "raspberry")]


class BuildUserdbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tr-userdb-")
        self.db = os.path.join(self.tmp, "radar.db")
        con = sqlite3.connect(self.db)
        with open(os.path.join(ROOT, "schema.sql"), encoding="utf-8") as fh:
            con.executescript(fh.read())
        con.executescript("CREATE VIEW IF NOT EXISTS v_events AS SELECT * FROM raw_events;")
        n = 0
        for weight, pairs in ((50, HOSTILE), (20, GOOD), (80, [("root", "123456"), ("admin", "admin")])):
            for user, pw in pairs:
                for _ in range(weight):
                    n += 1
                    con.execute(
                        "INSERT INTO raw_events(line_hash,eventid,session,src_ip,ts,payload)"
                        " VALUES(?,?,?,?,?,?)",
                        ("h%d" % n, "cowrie.login.failed", "s%d" % n, "192.0.2.1",
                         "2026-09-20T00:00:00Z", json.dumps({"username": user, "password": pw})))
        con.commit()
        con.close()
        self.out = os.path.join(self.tmp, "userdb.txt")

    def run_script(self, *extra):
        return subprocess.run([sys.executable, SCRIPT, "--db", self.db, "--top", "100",
                               "--out", self.out, *extra], capture_output=True, text=True)

    def written(self):
        with open(self.out, "rb") as fh:
            return fh.read()

    def test_the_file_loads_cleanly_whatever_attackers_sprayed(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        usable, findings = udb.check_file(self.written())
        self.assertEqual(findings, [], "the generator wrote a line the gate objects to")
        self.assertGreater(usable, len(GOOD))

    def test_no_hostile_pair_is_written(self):
        self.run_script()
        lines = self.written().decode("ascii").splitlines()
        for user, pw in HOSTILE:
            self.assertNotIn(udb.format_pair(user, pw), lines, (user, pw))

    def test_ordinary_observed_pairs_are_kept(self):
        self.run_script()
        lines = self.written().decode("ascii").splitlines()
        for user, pw in GOOD:
            self.assertIn(udb.format_pair(user, pw), lines)

    def test_root_and_admin_are_denied_unless_allowed(self):
        self.run_script()
        lines = self.written().decode("ascii").splitlines()
        self.assertIn(udb.format_deny("root"), lines)
        self.assertIn(udb.format_deny("admin"), lines)
        self.assertNotIn(udb.format_pair("root", "123456"), lines)

        self.run_script("--allow-root")
        lines = self.written().decode("ascii").splitlines()
        self.assertNotIn(udb.format_deny("root"), lines)
        self.assertIn(udb.format_pair("root", "123456"), lines)

    def test_install_is_a_rename_and_leaves_nothing_behind(self):
        with open(self.out, "w") as fh:
            fh.write("previous contents\n")
        before = os.stat(self.out).st_ino
        self.run_script()
        self.assertNotEqual(os.stat(self.out).st_ino, before, "the file was rewritten in place")
        self.assertEqual([f for f in os.listdir(self.tmp) if f.endswith(".tmp")], [])

    def test_main_in_process(self):
        # The same run in this process, so coverage sees the generator.
        spec = importlib.util.spec_from_file_location("build_userdb", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        argv = ["build_userdb.py", "--db", self.db, "--top", "100", "--out", self.out]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stderr"):
            self.assertEqual(mod.main(), 0)
        self.assertEqual(udb.check_file(self.written())[1], [])

    def test_stdout_mode_writes_the_same_file(self):
        r = subprocess.run([sys.executable, SCRIPT, "--db", self.db, "--top", "100"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.run_script()
        self.assertEqual(r.stdout.encode(), self.written())


if __name__ == "__main__":
    unittest.main()
