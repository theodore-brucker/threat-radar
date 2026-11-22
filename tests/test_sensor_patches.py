"""The Cowrie patches in sensor/patches, checked against the release the
sensor runs.

The first class needs nothing but the patch files. The others copy the
installed Cowrie, apply the patches and drive the result, so they skip where
Cowrie is not installed. CI installs it in the parity job, which fails if
these skip. Every expected value below was produced by bash 5.2 for the same
input.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import sensor_shell  # noqa: E402

PATCHES = sorted((ROOT / "sensor" / "patches").glob("*.patch"))
HAVE_COWRIE = sensor_shell.installed_cowrie() is not None and shutil.which("git")

# Expression, then what `echo $((expression))` prints in bash.
ARITHMETIC = [
    ("604*861+7", "520051"), ("1+2", "3"), ("7/2", "3"), ("7/-2", "-3"),
    ("-7%3", "-1"), ("2**10", "1024"), ("2**3**2", "512"), ("-2**2", "4"),
    ("(1+2)*3", "9"), ("1 + (2*3)", "7"), ("((2))", "2"),
    ("( (1+2) * (3+4) )", "21"), ("1<<4|1", "17"), ("-8>>1", "-4"),
    ("1<<64", "1"), ("9223372036854775807+1", "-9223372036854775808"),
    ("2**64", "0"), ("-9223372036854775808/-1", "-9223372036854775808"),
    ("0x1F", "31"), ("010", "8"), ("16#ff", "255"), ("64#@_", "4031"),
    ("1++2", "3"), ("1--2", "3"), ("+-+-3", "3"), ("!5", "0"), ("~0", "-1"),
    ("3>2>1", "0"), ("1<2 == 2>1", "1"), ("6 & 3 | 8 ^ 1", "11"),
    ("1 ? 2 : 1/0", "2"), ("0 && 1/0", "0"), ("1 || 1/0", "1"),
    ("0 ? 1 : 0 ? 2 : 3", "3"), ("1,2", "2"), ("", "0"), ("  ", "0"),
    ("unset_name", "0"), ("unset_name + 5", "5"),
]
# Expression, then the message bash writes after its "bash: " prefix.
ARITHMETIC_ERRORS = [
    ("1/0", '1/0: division by 0 (error token is "0")'),
    ("5 % 0", '5 % 0: division by 0 (error token is "0")'),
    ("1/0+3", '1/0+3: division by 0 (error token is "0+3")'),
    ("1+", '1+: syntax error: operand expected (error token is "+")'),
    ("3 +* 2", '3 +* 2: syntax error: operand expected (error token is "* 2")'),
    ("5 5", '5 5: syntax error in expression (error token is "5")'),
    ("echo hi", 'echo hi: syntax error in expression (error token is "hi")'),
    ("2**-1", '2**-1: exponent less than 0 (error token is "1")'),
    ("08", '08: value too great for base (error token is "08")'),
    ("12ab", '12ab: value too great for base (error token is "12ab")'),
    ("1.5", '1.5: syntax error: invalid arithmetic operator (error token is ".5")'),
    ("1?2", "1?2: `:' expected for conditional expression (error token is \"2\")"),
    ("1 = 2", '1 = 2: attempted assignment to non-variable (error token is "= 2")'),
]
# One session each: the commands, then everything the session prints.
SESSIONS = {
    "variables in arithmetic": (
        ["x=5; echo $((x*2)) $(($x+1)) $((${x}0+1))",
         'y="1+2"; echo $((y*2))',
         "i=3; echo $((i++)) $i $((i+=10)) $i $((--i))",
         "echo $((z = 4, z * z)) $z"],
        "10 6 51\n6\n3 4 14 14 13\n16 4\n"),
    "arithmetic among other expansions": (
        ['echo "$((1+2))" \'$((1+2))\' a$((2*3))b',
         "echo $(( $(echo 4) * 2 )) $((`echo 4`+1)) $(echo $((2+2)))",
         "for n in $((1+1)) $((2+2)); do echo v$n; done",
         "i=0; while [ $i -lt 3 ]; do i=$((i+1)); done; echo $i",
         "case $((1+1)) in 2) echo two;; esac",
         "if [ $((5%2)) -eq 1 ]; then echo odd; fi"],
        "3 $((1+2)) a6b\n8 5 4\nv2\nv4\n3\ntwo\nodd\n"),
    "a subshell pair is still a command substitution": (
        ["echo $((echo a); (echo b))", "echo $( (echo c) )"],
        "a\nb\nc\n"),
    "an arithmetic error skips the command": (
        ["echo before; echo $((1/0)); echo status=$?"],
        'before\n-bash: 1/0: division by 0 (error token is "0")\nstatus=1\n'),
    "process id": (
        ["echo $$ $(echo $$) \"$$\"", "ps | grep bash", "sh -c 'echo $$'",
         "sh -c 'echo $$'"],
        "5673 5673 5673\n5673 pts/0       0:00 -bash\n5680\n5681\n"),
    "positional parameters": (
        ['echo "$#|$1|$@|"',
         'set -- arg1 arg2; printf "%s|%s|%s\\n" "$#" "$1" "$2"',
         'echo "$@" $*; shift; echo "$#:$1"; shift 5; echo $?; shift; echo "$#:$1:"',
         'set -- x y z; f() { echo "$#:$1:$@"; }; f a b; echo "$#:$1:$@"',
         "sh -c 'echo $#:$1:'; echo $#",
         "set a b; echo $2; set --; echo $#"],
        "0|||\n2|arg1|arg2\narg1 arg2 arg1 arg2\n1:arg2\n1\n0::\n"
        "2:a:a b\n3:x:x y z\n0::\n3\nb\n0\n"),
    "set with options prints nothing": (
        ["set -e; set -o pipefail; set +x; set -euo pipefail; echo quiet",
         "set -- p; set | grep -c '^[0-9#@*]'"],
        "quiet\n0\n"),
    "printf with arguments": (
        ["printf 'check_ab12_lit=%s\\n' ok",
         "printf '%s|%s|%s\\n' a b c d",
         "printf '%5d|%-5d|%05d|%+d|%x|%X|%o|%#x\\n' 42 42 42 42 255 255 8 255",
         "printf '%5s|%-5s|%.2s|\\n' ab ab abcdef",
         "printf '%d %s\\n' 1 x 2 y 3",
         "printf '%.3f %e\\n' 3.14159 1234.5",
         "printf '%b|%c|%%|%d\\n' 'a\\tb' xyz 0x1f",
         "printf '%s\\n' one two > /tmp/out; cat /tmp/out",
         "for i in 1 2 3; do printf '%02d ' $i; done; echo",
         "printf '%d\\n' abc; echo $?"],
        "check_ab12_lit=ok\na|b|c\nd||\n   42|42   |00042|+42|ff|FF|10|0xff\n"
        "   ab|ab   |ab|\n1 x\n2 y\n3 \n3.142 1.234500e+03\na\tb|x|%|31\n"
        "one\ntwo\n01 02 03 \n0\n-bash: printf: abc: invalid number\n1\n"),
    "printf with one argument is unchanged": (
        ["printf '\\x41\\x42\\n'", "printf 'plain\\n'"],
        "AB\nplain\n"),
    "printf caps its field width": (
        ["printf '%99999999d' 1 | wc -c"],
        "1024\n"),
    "grep options": (
        ["grep -i ROOT /etc/passwd", "grep -c root /etc/passwd",
         "cat /etc/passwd | grep -ci ROOT",
         "grep -q root /etc/passwd && echo found",
         "grep -q nosuchuser /etc/passwd || echo missing",
         "echo abc | grep -v b; echo $?", "printf 'a\\nb\\n' | grep -v a",
         "printf 'a\\nb\\n' | grep -vc a"],
        "root:x:0:0:root:/root:/bin/bash\n1\n1\nfound\nmissing\n1\nb\n1\n"),
    "head and tail with a bare count": (
        ["head -1 /etc/passwd", "cat /etc/passwd | head -2 | tail -1",
         "head -n 1 /etc/passwd"],
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"
        "root:x:0:0:root:/root:/bin/bash\n"),
}
# The probe a campaign runs before it commits a payload: each check twice,
# through `sh -c` and directly, with printf and then with echo.
PROBE = [
    "printf 'check_9f_lit=%s\\n' ok",
    "printf 'check_9f_arith=%s\\n' \"$((604*861+7))\"",
    "printf 'check_9f_pid=%s\\n' \"$$\"",
    "set -- arg1 arg2; printf 'check_9f_pos=%s|%s|%s\\n' \"$#\" \"$1\" \"$2\"",
    "probe() { printf 'check_9f_fn=%s\\n' \"$1\"; }; probe called",
    "echo \"check_9f_arith=$((604*861+7))\"",
    "set -- arg1 arg2; echo \"check_9f_pos=$#|$1|$2\"",
]
PROBE_OUTPUT = [
    "check_9f_lit=ok\n", "check_9f_arith=520051\n", None,
    "check_9f_pos=2|arg1|arg2\n", "check_9f_fn=called\n",
    "check_9f_arith=520051\n", "check_9f_pos=2|arg1|arg2\n",
]


class PatchFiles(unittest.TestCase):
    def test_each_patch_changes_only_cowrie_source(self):
        self.assertGreaterEqual(len(PATCHES), 9)
        for patch in PATCHES:
            paths = re.findall(r"^diff --git a/(\S+) b/(\S+)$", patch.read_text(), re.M)
            self.assertTrue(paths, patch.name)
            for old, new in paths:
                self.assertEqual(old, new, patch.name)
                self.assertRegex(new, r"\Asrc/cowrie/[\w/]+\.py\Z", patch.name)

    def test_no_patch_reaches_an_interpreter_or_a_process(self):
        # The patched code handles attacker text. None of it may evaluate
        # that text or start a program.
        banned = re.compile(r"\b(eval|exec|compile|__import__|os\.system|subprocess|popen)\s*\(")
        for patch in PATCHES:
            added = [line[1:] for line in patch.read_text().splitlines()
                     if line.startswith("+") and not line.startswith("+++")]
            code = [line.split("#", 1)[0] for line in added]
            hits = [line for line in code if banned.search(line)
                    and "re.compile(" not in line]
            self.assertEqual(hits, [], patch.name)


@unittest.skipUnless(HAVE_COWRIE, "needs Cowrie from requirements-cowrie.txt and git")
class PatchedShell(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sensor-patched-")
        cls.tree = sensor_shell.build(Path(cls.tmp))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_patches_apply_together_and_one_at_a_time(self):
        # upgrade-cowrie.sh applies them in one call, and its --check tests
        # each against the untouched source.
        for patch in PATCHES:
            with tempfile.TemporaryDirectory() as tmp:
                sensor_shell.build(Path(tmp), None)
                subprocess.run(
                    ["git", "apply", "--check", str(patch)], cwd=tmp, check=True)

    def test_arithmetic_matches_bash(self):
        commands = [f"echo $(({expression}))" for expression, _ in ARITHMETIC]
        outputs = sensor_shell.run(self.tree, [commands])[0]
        for (expression, expected), output in zip(ARITHMETIC, outputs, strict=True):
            self.assertEqual(output, expected + "\n", expression)

    def test_arithmetic_errors_match_bash(self):
        commands = [f"echo $(({expression}))" for expression, _ in ARITHMETIC_ERRORS]
        outputs = sensor_shell.run(self.tree, [commands])[0]
        for (expression, expected), output in zip(ARITHMETIC_ERRORS, outputs, strict=True):
            self.assertEqual(output, f"-bash: {expected}\n", expression)

    def test_sessions(self):
        names = list(SESSIONS)
        outputs = sensor_shell.run(self.tree, [SESSIONS[name][0] for name in names])
        for name, output in zip(names, outputs, strict=True):
            self.assertEqual("".join(output), SESSIONS[name][1], name)

    def test_the_fidelity_probe_gets_the_answers_a_real_shell_gives(self):
        nested = ["sh -c '" + line.replace("'", "'\\''") + "'" for line in PROBE]
        direct, through_sh = sensor_shell.run(self.tree, [PROBE, nested])
        for outputs in (direct, through_sh):
            for line, expected, output in zip(PROBE, PROBE_OUTPUT, outputs, strict=True):
                if expected is None:
                    self.assertRegex(output, r"\Acheck_9f_pid=\d{3,7}\n\Z", line)
                else:
                    self.assertEqual(output, expected, line)
        # A new `sh` is a new process and reports a different id.
        self.assertNotEqual(direct[2], through_sh[2])

    def test_no_expression_costs_more_than_a_fixed_amount_of_work(self):
        cases = {
            "(" * 40 + "1" + ")" * 40: "recursion level exceeded",
            "-" * 1500 + "1": "1",
            "+".join(["1"] * 1500): "1500",
            "+".join(["1"] * 9000): "expression too long",
            "x": "recursion level exceeded",       # x holds "x"
            "v0": "recursion level exceeded",      # see the child script
            "v30 == 1024": "1",
            "2**999999999999": "0",
        }
        started = time.monotonic()
        outputs = sensor_shell.run_script(
            self.tree, ROOT / "tests" / "sensor_arithmetic_child.py",
            json.dumps(list(cases)))
        self.assertLess(time.monotonic() - started, 20)
        for (expression, expected), output in zip(cases.items(), outputs, strict=True):
            self.assertIn(expected, output, expression[:40])

    def test_unpatched_release_still_has_the_gap(self):
        # When this fails the release has caught up, and shell-arithmetic.patch
        # can be dropped.
        with tempfile.TemporaryDirectory() as tmp:
            tree = sensor_shell.build(Path(tmp), None)
            output = sensor_shell.run(tree, [["echo $((2+3))"]])[0][0]
        self.assertIn("command not found", output)


@unittest.skipUnless(HAVE_COWRIE, "needs Cowrie from requirements-cowrie.txt and git")
class ImplantedKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sensor-patched-")
        tree = sensor_shell.build(Path(cls.tmp))
        cls.seen = sensor_shell.run_script(tree, ROOT / "tests" / "sensor_keys_child.py")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    FAILED = ["ConchError", "cowrie.client.fingerprint", "cowrie.login.failed"]

    def test_key_is_refused_until_the_session_that_wrote_it_closes(self):
        self.assertEqual(self.seen["before close"], self.FAILED)
        self.assertEqual(self.seen["redirect targets"], ["/root/.ssh/authorized_keys"])

    def test_client_is_told_the_key_is_acceptable_then_must_sign(self):
        self.assertEqual(self.seen["asks first"],
                         ["ValidPublicKey", "cowrie.client.fingerprint"])
        self.assertEqual(self.seen["signed"],
                         ["root", "cowrie.client.fingerprint", "cowrie.login.success"])
        self.assertEqual(self.seen["success event"], {
            "eventid": "cowrie.login.success", "username": "root",
            "type": "ssh-ed25519", "implanted": True})
        self.assertEqual(self.seen["rsa signed"][0], "ubuntu")

    def test_wrong_signature_account_or_key_is_refused(self):
        for case in ("wrong signature", "other account", "unknown key"):
            self.assertEqual(self.seen[case], self.FAILED, case)

    def test_hostile_file_content_yields_only_the_real_key(self):
        self.assertEqual(self.seen["hostile added"], 1)
        self.assertEqual(self.seen["hostile again"], 0)
        self.assertEqual(self.seen["not a key file"], [0, 0, 0, 0])

    def test_store_is_capped_and_damage_refuses_without_raising(self):
        self.assertEqual(self.seen["kept"], 5)
        self.assertEqual(self.seen["damaged store"], self.FAILED)
        self.assertEqual(self.seen["no state directory"], [0, *self.FAILED])

    def test_setting_switches_it_off(self):
        self.assertEqual(self.seen["on"], "root")
        self.assertEqual(self.seen["off"], ["ConchError", 0])


if __name__ == "__main__":
    unittest.main()
