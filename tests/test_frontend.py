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
STATIC = ROOT / "app" / "static"
JS = STATIC / "js"
CSS = STATIC / "css"

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



class NotFoundTests(DBTestCase):
    """A path that is not a page answers 404, and only page paths get the shell."""

    def setUp(self):
        super().setUp()
        from app.main import app
        self.client = TestClient(app)

    def test_an_unknown_page_is_a_404_that_still_carries_the_site(self):
        r = self.client.get("/no-such-page")
        self.assertEqual(r.status_code, 404)
        self.assertIn("text/html", r.headers["content-type"])
        self.assertIn("boot.js", r.text)
        self.assertIn("content-security-policy", r.headers)

    def test_api_and_static_misses_stay_plain(self):
        r = self.client.get("/api/v1/no-such-route")
        self.assertEqual(r.status_code, 404)
        self.assertIn("application/json", r.headers["content-type"])
        r = self.client.get("/static/no-such-file.css")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("boot.js", r.text)

    def test_known_pages_and_the_icons_still_answer_200(self):
        for path in ("/", "/sources", "/method", "/static/favicon.svg",
                     "/static/favicon-32.png", "/static/apple-touch-icon.png"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)


class DesignSystemTests(unittest.TestCase):
    """DESIGN.md's rules, checked where a check is cheap.

    Colours, radii and the label style live in tokens.css; the component and
    shell stylesheets only refer to them. A literal colour or a second radius
    in a component is how a design system quietly stops being one.
    """

    SHEETS = ("app.css", "components.css")

    def test_component_sheets_use_tokens_for_colour(self):
        for name in self.SHEETS:
            text = re.sub(r"/\*.*?\*/", "", (CSS / name).read_text(), flags=re.S)
            with self.subTest(sheet=name):
                self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b", text), [])
                self.assertEqual(re.findall(r"rgba?\(", text), [])

    def test_one_corner_radius(self):
        allowed = {"var(--radius)", "50%", "0"}
        for name in self.SHEETS:
            text = re.sub(r"/\*.*?\*/", "", (CSS / name).read_text(), flags=re.S)
            for value in re.findall(r"border(?:-[a-z]+)*-radius:\s*([^;]+);", text):
                parts = set(value.split())
                with self.subTest(sheet=name, value=value):
                    self.assertTrue(parts <= allowed, value)

    def test_no_all_caps_labels(self):
        for name in self.SHEETS:
            text = (CSS / name).read_text()
            with self.subTest(sheet=name):
                self.assertNotIn("text-transform: uppercase;\n", text.replace("::first-letter { text-transform: uppercase; }", ""))

    def test_every_icon_the_code_asks_for_exists(self):
        table = (JS / "icons.js").read_text()
        known = set(re.findall(r'^  "([a-z0-9-]+)":', table, re.M))
        used = set()
        for path in list(JS.rglob("*.js")):
            used |= set(re.findall(r'\bicon\(\s*"([a-z0-9-]+)"', path.read_text()))
            used |= set(re.findall(r'(?:iconName|ICON\[[^\]]+\])\s*[:=]\s*"([a-z0-9-]+)"', path.read_text()))
        self.assertTrue(used, "expected icon() calls")
        self.assertEqual(sorted(used - known), [])


if __name__ == "__main__":
    unittest.main()
