"""The userdb rules, tested against what Cowrie does rather than what the
format looks like.

Every case here is either a real incident on this sensor or a way Cowrie reads
a field as something other than literal text. The file is built from strings
attackers chose, so each of these is reachable by spraying the right
credential often enough to reach the top of the observed list.

The last test cross-checks the module against Cowrie's own parser when Cowrie
is importable, which is the case on the sensor and in CI once the package is
installed. It is skipped elsewhere rather than asserting nothing.
"""

import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.path.join(os.path.dirname(HERE), "sensor", "bin", "cowrie_userdb.py")
_spec = importlib.util.spec_from_file_location("cowrie_userdb", MODULE)
udb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(udb)


class DecodeTests(unittest.TestCase):
    def test_ascii_file_decodes(self):
        lines, why = udb.decode_file(b"alice:x:hunter2\n")
        self.assertIsNone(why)
        self.assertEqual(lines, ["alice:x:hunter2"])

    def test_one_non_ascii_byte_kills_the_whole_file(self):
        # Cowrie reads the file with encoding="ascii", so this is not one bad
        # entry, it is every entry in the file.
        data = "alice:x:hunter2\nbob:x:pässword\ncarol:x:letmein\n".encode("utf-8")
        lines, why = udb.decode_file(data)
        self.assertIsNone(lines)
        self.assertIn("ascii", why)

    def test_check_file_reports_a_decode_failure_as_fatal(self):
        usable, findings = udb.check_file("a:x:é\n".encode("utf-8"))
        self.assertEqual(usable, 0)
        self.assertEqual([f[1] for f in findings], [udb.FATAL])
        self.assertEqual(findings[0][0], 0)


class FatalLineTests(unittest.TestCase):
    def fatal_reason(self, line):
        hit = udb.check_line(line)
        self.assertIsNotNone(hit, "expected a finding for %r" % line)
        self.assertEqual(hit[0], udb.FATAL, "expected FATAL for %r: %r" % (line, hit))
        return hit[1]

    def test_empty_password_is_the_2026_07_31_outage(self):
        self.assertIn("2026-07-31", self.fatal_reason("alice:x:"))

    def test_whitespace_only_password_is_the_same_fault(self):
        # Cowrie strips the password before reading passwd[0], so a field of
        # spaces reaches adduser as empty. The previous validator called this
        # a warning and would have let the sensor start with auth dead.
        self.assertIn("IndexError", self.fatal_reason("alice:x:   "))

    def test_uncompilable_regex_password_aborts_the_load(self):
        self.assertIn("does not compile", self.fatal_reason("alice:x:/[/"))

    def test_uncompilable_regex_login_aborts_the_load(self):
        self.assertIn("does not compile", self.fatal_reason("/([/:x:hunter2"))


class WarnLineTests(unittest.TestCase):
    def warn_reason(self, line):
        hit = udb.check_line(line)
        self.assertIsNotNone(hit, "expected a finding for %r" % line)
        self.assertEqual(hit[0], udb.WARN, "expected WARN for %r: %r" % (line, hit))
        return hit[1]

    def test_wildcard_password_accepts_anything(self):
        self.assertIn("identifies the honeypot", self.warn_reason("alice:x:*"))

    def test_wildcard_login_matches_every_account(self):
        self.assertIn("every account", self.warn_reason("*:x:hunter2"))

    def test_valid_regex_is_not_the_literal_it_looks_like(self):
        self.assertIn("regular expression", self.warn_reason("alice:x:/.*/"))

    def test_leading_bang_is_a_deny_rule(self):
        # 25 entries in the live file are this: an observed password that
        # happens to start with "!", loaded as a rule denying the rest.
        self.assertIn("denying", self.warn_reason("alice:x:!QAZ2wsx"))

    def test_extra_field_truncates_the_password(self):
        # Cowrie takes field 2 and ignores the rest, so "pw:extra" loads as
        # "pw" and the entry quietly means something narrower than it reads.
        self.assertIn("truncated", self.warn_reason("alice:x:pw:extra"))

    def test_short_line_is_skipped_not_fatal(self):
        # The previous validator called this FATAL. Cowrie catches the
        # IndexError and moves on, so refusing to start was wrong.
        self.assertIn("skips this line", self.warn_reason("alice:x"))

    def test_whitespace_in_password_that_survives_stripping(self):
        self.assertIsNone(udb.check_line("alice:x:two words"))


class AcceptedLineTests(unittest.TestCase):
    def test_ordinary_pairs_pass(self):
        for line in ("alice:x:hunter2", "svc_backup:x:Passw0rd!", "u:x:1",
                     "alice:x:with spaces inside", "alice:x:a/b"):
            self.assertIsNone(udb.check_line(line), line)

    def test_deny_all_entry_passes(self):
        self.assertIsNone(udb.check_line("root:x:!*"))
        self.assertIsNone(udb.check_line(udb.format_deny("admin")))

    def test_comments_and_blanks_pass(self):
        for line in ("# generated by build_userdb.py", "", "   "):
            self.assertIsNone(udb.check_line(line))

    def test_usable_count_excludes_comments_and_blanks(self):
        data = b"# header\n\nalice:x:hunter2\nbob:x:letmein\n"
        usable, findings = udb.check_file(data)
        self.assertEqual((usable, findings), (2, []))


class GeneratorRuleTests(unittest.TestCase):
    """literal_pair_problem is stricter: anything not a literal is rejected."""

    def test_rejects_every_field_cowrie_reads_as_special(self):
        cases = [
            ("", "hunter2"),
            ("alice", ""),
            ("alice", "   "),
            ("alice", "trailing "),
            ("alice", "/regex/"),
            ("/regex/", "hunter2"),
            ("alice", "*"),
            ("*", "hunter2"),
            ("alice", "!denied"),
            ("alice", "colon:inside"),
            ("colon:inside", "hunter2"),
            ("alice", "pässword"),
            ("alice", "two\nlines"),
            ("alice", "vertical\vtab"),
            ("alice", "file\x1cseparator"),
            ("has space", "hunter2"),
            ("has/slash", "hunter2"),
            ("userdb.txt", "hunter2"),
        ]
        for login, passwd in cases:
            self.assertIsNotNone(
                udb.literal_pair_problem(login, passwd),
                "should have been rejected: %r %r" % (login, passwd),
            )

    def test_accepts_ordinary_observed_credentials(self):
        for login, passwd in (("root2", "123456"), ("ubuntu", "ubuntu"),
                              ("svc_backup", "P@ssw0rd"), ("a", "b"),
                              ("oracle", "two words"), ("git", "a/b")):
            self.assertIsNone(
                udb.literal_pair_problem(login, passwd),
                "should have been accepted: %r %r" % (login, passwd),
            )

    def test_anything_the_generator_accepts_is_safe_to_load(self):
        # The two rule sets have to agree in one direction: a pair the
        # generator writes must never produce a finding when the gate reads
        # the file back.
        pairs = [("root2", "123456"), ("ubuntu", "ubuntu"), ("a", "b"),
                 ("svc", "P@ssw0rd"), ("test", "test123"), ("git", "a/b"),
                 ("oracle", "two words"), ("user", "!"), ("user", "a*b"),
                 ("user", "/notaregex"), ("user", "sl/ash")]
        rendered = "\n".join(
            udb.format_pair(u, p) for u, p in pairs
            if udb.literal_pair_problem(u, p) is None
        ) + "\n"
        usable, findings = udb.check_file(rendered.encode("ascii"))
        self.assertEqual(findings, [])
        self.assertGreater(usable, 5)


class AgainstCowrieItselfTests(unittest.TestCase):
    """Cross-check against the real parser where it is installed."""

    @classmethod
    def setUpClass(cls):
        try:
            from cowrie.core import auth  # noqa: F401
        except Exception as exc:  # pragma: no cover, environment dependent
            raise unittest.SkipTest("cowrie is not importable here: %s" % exc)
        cls.auth = auth

    def adduser_raises(self, login, passwd):
        db = self.auth.UserDB.__new__(self.auth.UserDB)
        db.userdb = {}
        try:
            db.adduser(login.encode(), passwd.strip().encode())
        except Exception:
            return True
        return False

    def test_fatal_cases_really_do_raise(self):
        for line in ("alice:x:", "alice:x:   ", "alice:x:/[/"):
            login, _, passwd = line.split(":", 2)
            self.assertTrue(self.adduser_raises(login, passwd), line)

    def test_accepted_cases_really_do_load(self):
        for login, passwd in (("root2", "123456"), ("svc", "P@ssw0rd"),
                              ("user", "two words")):
            self.assertFalse(self.adduser_raises(login, passwd))


if __name__ == "__main__":
    unittest.main()
