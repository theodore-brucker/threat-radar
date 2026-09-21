"""The pull protocol, end to end, with the real scripts on both sides.

pull.sh runs against sensor/bin/pull-logs.sh through the transport hook, so
the requests and answers are exactly what they would be over ssh, only
without the network. A temporary directory stands in for the sensor's log
directory and another for the collector's spool.

What is being defended: the collector ends up with byte-identical copies of
every log the sensor offers, it only ever transfers bytes it lacks, rotation
and missed days lose nothing, and nothing a hostile sensor returns can write
outside the spool or make the wrapper run something it should not.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import datetime as dt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRAPPER = os.path.join(ROOT, "sensor", "bin", "pull-logs.sh")
PULL = os.path.join(ROOT, "pull.sh")
FETCH = os.path.join(ROOT, "bin", "fetch_samples.sh")


def day(offset):
    return (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=offset)).isoformat()


def lines(n, tag):
    return "".join('{"eventid":"x","n":%d,"tag":"%s"}\n' % (i, tag) for i in range(n))


class ProtocolCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tr-pull-")
        self.logdir = os.path.join(self.tmp, "sensor-logs")
        self.dldir = os.path.join(self.tmp, "sensor-downloads")
        self.base = os.path.join(self.tmp, "collector")
        self.spool = os.path.join(self.base, "spool")
        self.run_dir = os.path.join(self.tmp, "run")
        for d in (self.logdir, self.dldir, self.spool, self.run_dir):
            os.makedirs(d)
        self.bytes_log = os.path.join(self.tmp, "bytes-sent")
        # The transport counts what the sensor sends, so a test can assert
        # that only the missing bytes crossed the wire.
        self.transport = os.path.join(self.tmp, "transport.sh")
        with open(self.transport, "w") as fh:
            fh.write("#!/bin/bash\nset -o pipefail\n"
                     "PULL_LOGDIR=%r PULL_DLDIR=%r %r | tee >(wc -c >> %r)\n"
                     % (self.logdir, self.dldir, WRAPPER, self.bytes_log))
        os.chmod(self.transport, os.stat(self.transport).st_mode | stat.S_IXUSR)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, text, mode="w"):
        with open(os.path.join(self.logdir, name), mode) as fh:
            fh.write(text)

    def env(self):
        return dict(os.environ, TR_BASE=self.base, TR_PULL_TRANSPORT=self.transport,
                    RUNTIME_DIRECTORY=self.run_dir, TR_SPOOL_RETAIN_DAYS="8",
                    TR_PULL_ENV="/nonexistent")

    def pull(self):
        if os.path.exists(self.bytes_log):
            os.remove(self.bytes_log)
        r = subprocess.run([PULL], env=self.env(), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def sent(self):
        """Bytes the chunk requests carried in the last pull, manifest excluded."""
        if not os.path.exists(self.bytes_log):
            return 0
        counts = [int(x) for x in open(self.bytes_log).read().split()]
        return sum(counts[1:])   # the first request of every pull is the manifest

    def assert_mirrors(self, *names):
        for name in names:
            with open(os.path.join(self.logdir, name), "rb") as a, \
                 open(os.path.join(self.spool, name), "rb") as b:
                self.assertEqual(a.read(), b.read(), "%s differs from the sensor copy" % name)


class PullTests(ProtocolCase):
    def test_first_pull_mirrors_every_file(self):
        self.write("cowrie.json", lines(50, "live"))
        self.write("cowrie.json." + day(1), lines(80, "yesterday"))
        self.pull()
        self.assert_mirrors("cowrie.json", "cowrie.json." + day(1))

    def test_second_pull_sends_only_the_new_bytes(self):
        self.write("cowrie.json", lines(50, "live"))
        self.write("cowrie.json." + day(1), lines(500, "yesterday"))
        self.pull()
        added = lines(3, "more")
        self.write("cowrie.json", added, mode="a")
        self.pull()
        self.assertEqual(self.sent(), len(added.encode()),
                         "the rotated file or old bytes were sent again")
        self.assert_mirrors("cowrie.json")

    def test_nothing_new_sends_nothing(self):
        self.write("cowrie.json", lines(50, "live"))
        self.pull()
        self.pull()
        self.assertEqual(self.sent(), 0)

    def test_rotation_loses_nothing(self):
        self.write("cowrie.json", lines(50, "before"))
        self.pull()
        # Events written after the last pull, then the sensor rotates.
        self.write("cowrie.json", lines(7, "unpulled"), mode="a")
        os.rename(os.path.join(self.logdir, "cowrie.json"),
                  os.path.join(self.logdir, "cowrie.json." + day(0)))
        self.write("cowrie.json", lines(2, "after"))
        self.pull()
        self.assert_mirrors("cowrie.json", "cowrie.json." + day(0))

    def test_a_missed_week_is_recovered(self):
        for offset in range(1, 7):
            self.write("cowrie.json." + day(offset), lines(10, "d%d" % offset))
        self.write("cowrie.json", lines(5, "live"))
        self.pull()
        self.assert_mirrors("cowrie.json", *["cowrie.json." + day(o) for o in range(1, 7)])

    def test_files_older_than_retention_are_not_requested(self):
        # Otherwise a file the prune deleted would be fetched again, deleted
        # again, and fetched again for as long as the sensor keeps it.
        self.write("cowrie.json." + day(9), lines(10, "old"))
        self.write("cowrie.json", lines(5, "live"))
        self.pull()
        self.assertFalse(os.path.exists(os.path.join(self.spool, "cowrie.json." + day(9))))

    def test_a_large_file_arrives_in_order_across_chunks(self):
        self.write("cowrie.json", lines(20000, "big"))
        self.pull()
        self.assert_mirrors("cowrie.json")


class HostileSensorTests(ProtocolCase):
    def fake_sensor(self, manifest, chunk=b""):
        # The answers go through files rather than being quoted into the
        # script, so newlines and bytes arrive exactly as a sensor would send
        # them. An earlier version quoted them and the manifest arrived as one
        # malformed line, which made both tests below pass without testing
        # anything. The request log proves the chunk path is really reached.
        answers = os.path.join(self.tmp, "answers")
        os.makedirs(answers, exist_ok=True)
        with open(os.path.join(answers, "manifest"), "w") as fh:
            fh.write(manifest)
        with open(os.path.join(answers, "chunk"), "wb") as fh:
            fh.write(chunk)
        self.requests = os.path.join(self.tmp, "requests")
        with open(self.transport, "w") as fh:
            fh.write("#!/bin/bash\n"
                     "echo \"$SSH_ORIGINAL_COMMAND\" >> %r\n"
                     "case \"$SSH_ORIGINAL_COMMAND\" in\n"
                     "  manifest) cat %r ;;\n"
                     "  chunk*) cat %r ;;\n"
                     "esac\n" % (self.requests, os.path.join(answers, "manifest"),
                                  os.path.join(answers, "chunk")))

    def requested(self):
        if not os.path.exists(self.requests):
            return []
        return open(self.requests).read().splitlines()

    def test_manifest_names_cannot_escape_the_spool(self):
        outside = os.path.join(self.tmp, "escaped")
        self.fake_sensor("../escaped 10\n/etc/passwd 10\ncowrie.json/../../x 5\n"
                         "cowrie.json 10\n", chunk=b"0123456789")
        self.pull()
        self.assertFalse(os.path.exists(outside))
        self.assertEqual(os.listdir(self.spool), ["cowrie.json"])
        # Only the one valid name was ever asked for.
        chunks = [r for r in self.requested() if r.startswith("chunk")]
        self.assertEqual(chunks, ["chunk cowrie.json 0 10"])

    def test_oversized_chunk_is_discarded_every_time(self):
        # An answer longer than the request is a protocol violation, and the
        # outcome must not depend on whether the sender finished writing
        # before the reader closed the pipe, so this runs repeatedly.
        self.fake_sensor("cowrie.json 4\n", chunk=b"ABCDEFGHIJ")
        for _ in range(20):
            r = self.pull()
            self.assertIn("chunk cowrie.json 0 4", self.requested(),
                          "the chunk path was never reached")
            self.assertFalse(os.path.exists(os.path.join(self.spool, "cowrie.json")))
            self.assertTrue("more than requested" in r.stderr or "failed" in r.stderr,
                            r.stderr)


class WrapperTests(ProtocolCase):
    def ask(self, request):
        env = dict(os.environ, SSH_ORIGINAL_COMMAND=request,
                   PULL_LOGDIR=self.logdir, PULL_DLDIR=self.dldir)
        return subprocess.run([WRAPPER], env=env, capture_output=True)

    def test_refuses_what_it_should(self):
        self.write("cowrie.json", lines(3, "x"))
        for request in ("chunk ../../etc/passwd 0 10", "chunk cowrie.json -1 10",
                        "chunk cowrie.json 0 1e9", "chunk cowrie.json 99999 10",
                        "chunk cowrie.json 0", "chunk * 0 10", "samples-get ../x",
                        "samples-get " + "g" * 64, "manifest extra", "rm -rf /",
                        "logs; id", "$(id)"):
            r = self.ask(request)
            self.assertNotEqual(r.returncode, 0, "accepted: %r" % request)

    def test_chunk_is_exact(self):
        self.write("cowrie.json", "0123456789")
        self.assertEqual(self.ask("chunk cowrie.json 3 4").stdout, b"3456")
        self.assertEqual(self.ask("chunk cowrie.json 8 100").stdout, b"89")

    def test_manifest_lists_only_log_files(self):
        self.write("cowrie.json", "a")
        self.write("cowrie.json." + day(1), "bb")
        self.write("cowrie.log", "ccc")
        self.write("notes.txt", "d")
        out = self.ask("manifest").stdout.decode().split("\n")
        self.assertEqual([x for x in out if x],
                         sorted(["cowrie.json 1", "cowrie.json.%s 2" % day(1)]))


class SampleFetchTests(ProtocolCase):
    def test_fetches_and_verifies_by_hash(self):
        import hashlib
        body = b"\x7fELF" + b"\x00" * 100
        good = hashlib.sha256(body).hexdigest()
        with open(os.path.join(self.dldir, good), "wb") as fh:
            fh.write(body)
        # A capture whose content does not match its name is discarded.
        liar = "a" * 64
        with open(os.path.join(self.dldir, liar), "wb") as fh:
            fh.write(b"not what the name says")
        dest = os.path.join(self.base, "samples")
        env = dict(self.env(), TR_SAMPLE_DIR=dest, SENSOR_TS_IP="192.0.2.1")
        r = subprocess.run([FETCH], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(os.listdir(dest)), [good])
        self.assertIn("1 new", r.stdout)

    def test_refuses_to_run_without_the_sensor_address(self):
        # The failure that went unnoticed: the address vanished and the
        # script failed on every run under a unit that tolerates its failure.
        env = dict(self.env(), TR_SAMPLE_DIR=os.path.join(self.base, "samples"))
        env.pop("SENSOR_TS_IP", None)
        r = subprocess.run([FETCH], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SENSOR_TS_IP", r.stderr)


if __name__ == "__main__":
    unittest.main()
