"""Guards on the browser side that no other test reaches.

The dashboard renders attacker strings, so the only safe way to put them on a
page is as text. These checks keep the code from ever growing an HTML sink,
and prove that the policy the page is served with actually covers the inline
script it contains: a mismatch there would not be a vulnerability, but it
would break the page for every reader under the policy the site depends on.
"""

import base64
import hashlib
import pathlib
import re
import unittest

from fastapi.testclient import TestClient

from tests.support import DBTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent
JS = ROOT / "app" / "static" / "js"

# Code patterns, not words: comments that explain why these are absent are fine.
SINKS = [
    re.compile(r"\.(inner|outer)HTML\s*[+]?="),
    re.compile(r"\binsertAdjacentHTML\s*\("),
    re.compile(r"\bdocument\.write(ln)?\s*\("),
    re.compile(r"(?<![\w.])eval\s*\("),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\bset(Timeout|Interval)\s*\(\s*['\"`]"),
    re.compile(r"\bcreateContextualFragment\s*\("),
    re.compile(r"\bouterHTML\b|\binnerHTML\s*\("),
]


class FrontendTests(DBTestCase):
    def test_no_html_sinks_in_the_spa(self):
        hits = []
        for path in JS.rglob("*.js"):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("//", 1)[0] if "://" not in line else line
                if code.lstrip().startswith(("*", "/*")):
                    continue
                for sink in SINKS:
                    if sink.search(code):
                        hits.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:80]}")
        self.assertEqual(hits, [])

    def test_the_served_page_hashes_every_inline_script(self):
        from app.main import app
        r = TestClient(app).get("/")
        csp = r.headers["content-security-policy"]
        script_src = next(d for d in csp.split(";") if d.strip().startswith("script-src"))
        inline = re.findall(r"<script>(.*?)</script>", r.text, re.S)
        self.assertTrue(inline, "expected the theme bootstrap script")
        for body in inline:
            digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
            self.assertIn(f"'sha256-{digest}'", script_src,
                          "an inline script is not covered by the policy it is served with")

    def test_external_scripts_are_modules_from_this_origin(self):
        from app.main import app
        page = TestClient(app).get("/").text
        for src in re.findall(r"<script[^>]+src=\"([^\"]+)\"", page):
            self.assertFalse(src.startswith(("http:", "https:", "//")), src)


if __name__ == "__main__":
    unittest.main()
