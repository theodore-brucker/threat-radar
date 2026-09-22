"""Every API route, discovered from the application rather than listed here.

Routes are found by walking the app's routers, so a route added later is
covered without anyone remembering to add it. Against a fixture built through
the real pipeline, with hostile strings in every attacker-controlled field,
each route must:

  - answer its documented envelope when given valid input
  - never answer 5xx, nor leak a database error or a traceback, whatever is
    put in its path and query parameters
  - never return sample bytes, and never return a text sample's URLs live
  - carry the security headers, including a script policy with no inline
    allowance
"""

import base64
import json

import httpx
from fastapi.testclient import TestClient

from tests import fixtures
from tests.support import DBTestCase, worker

ERROR_SIGNS = ("Traceback", "sqlite3", "OperationalError", "syntax error", "no such column")


def b64u(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def api_routes(app):
    def walk(routes):
        for r in routes:
            inner = getattr(getattr(r, "original_router", None), "routes", None)
            if inner is not None:
                yield from walk(inner)
            else:
                yield r
    return [r for r in walk(app.routes) if getattr(r, "path", "").startswith("/api/")]


class RouteCase(DBTestCase):
    def setUp(self):
        super().setUp()
        from app.main import app
        from app.analytics import sessions
        self.app = app
        self.client = TestClient(app)
        self.shas = fixtures.build(self.con, worker, self.sample_dir)
        from unittest import mock
        p = mock.patch.object(sessions, "SAMPLE_DIR", self.sample_dir)
        p.start()
        self.addCleanup(p.stop)
        self.routes = api_routes(app)

    def valid_path(self, route):
        values = {
            "ip": "192.0.2.10",
            "tag": "admin-generic",
            "shasum": self.shas["binary"],
            "session": "%08x%04x" % (0, 0),
        }
        if route.path == "/api/v1/entity/{etype}/{value}":
            return None
        path = route.path
        for p in route.dependant.path_params:
            path = path.replace("{%s}" % p.name, values[p.name])
        return path

    def entity_paths(self):
        return [
            "/api/v1/entity/ip/192.0.2.10",
            "/api/v1/entity/day/" + fixtures._ts(30)[:10],
            "/api/v1/entity/credential/" + b64u("root\x00" + fixtures.HOSTILE[0]),
            "/api/v1/entity/hassh/" + "%032x" % 0,
            "/api/v1/entity/url/" + b64u("http://203.0.113.50/" + fixtures.HOSTILE[0][:60]),
        ]

    def get(self, path, **params):
        return self.client.get(path, params=params or None)


class ContractTests(RouteCase):
    def test_the_route_list_is_what_the_tests_expect(self):
        # A route that is not GET or the cards POST needs its own test.
        methods = {m for r in self.routes for m in r.methods}
        self.assertLessEqual(methods, {"GET", "POST"})
        self.assertGreaterEqual(len(self.routes), 20)

    def test_every_get_route_answers_the_envelope(self):
        paths = [self.valid_path(r) for r in self.routes if "GET" in r.methods]
        for path in [p for p in paths if p] + self.entity_paths():
            with self.subTest(path=path):
                r = self.get(path)
                self.assertEqual(r.status_code, 200, r.text[:200])
                self.assertIn("application/json", r.headers["content-type"])
                body = r.json()
                self.assertIs(body["ok"], True)
                self.assertIn("generated_at", body)
                self.assertIn("data", body)

    def test_windowed_routes_report_their_window(self):
        for r in self.routes:
            if "GET" in r.methods and any(q.name == "days" for q in r.dependant.query_params):
                path = self.valid_path(r)
                if not path:
                    continue
                with self.subTest(path=path):
                    self.assertEqual(self.get(path, days=7).json().get("window_days"), 7)

    def test_cards_answer_for_every_entity_type(self):
        url = "http://203.0.113.50/" + fixtures.HOSTILE[0][:60]
        wanted = {
            "ip": "192.0.2.10",
            "credential": b64u("root\x00" + fixtures.HOSTILE[0]),
            "hassh": "%032x" % 0,
            "url": b64u(url),
            "day": fixtures._ts(30)[:10],
            "session": "%08x%04x" % (0, 0),
            "sample": self.shas["binary"],
        }
        items = [{"type": t, "value": v} for t, v in wanted.items()] + [{"type": "asn", "value": "64496"}]
        r = self.client.post("/api/v1/cards", json={"items": items})
        self.assertEqual(r.status_code, 200)
        cards = r.json()["data"]["cards"]
        for t, v in wanted.items():
            self.assertIn("%s:%s" % (t, v), cards, "no card for a %s the fixture contains" % t)

    def test_cards_accepts_a_batch_and_ignores_junk(self):
        items = [{"type": "ip", "value": "192.0.2.10"}] + [
            {"type": t, "value": v} for t in ("ip", "asn", "credential", "url", "nonsense")
            for v in fixtures.HOSTILE[:5]]
        r = self.client.post("/api/v1/cards", json={"items": items})
        self.assertEqual(r.status_code, 200)
        self.assertIn("cards", r.json()["data"])


class HostileInputTests(RouteCase):
    def assert_contained(self, r, where):
        self.assertLess(r.status_code, 500, where)
        for sign in ERROR_SIGNS:
            self.assertNotIn(sign, r.text, where)

    def hostile_values(self):
        return fixtures.HOSTILE + ["-1", "0", "99999999999999999999", "1e9", "", " ", "%00"]

    def test_hostile_path_parameters(self):
        for route in self.routes:
            for p in route.dependant.path_params:
                for value in self.hostile_values():
                    path = route.path
                    for q in route.dependant.path_params:
                        path = path.replace("{%s}" % q.name,
                                            value if q.name == p.name else "ip" if q.name == "etype" else "x")
                    try:
                        r = self.client.request(sorted(route.methods)[0], path)
                    except (httpx.InvalidURL, UnicodeEncodeError):
                        continue  # the client refuses to send it, so no server can see it
                    self.assert_contained(r, "%s %r" % (route.path, value[:40]))

    def test_hostile_query_parameters(self):
        for route in self.routes:
            if "GET" not in route.methods:
                continue
            path = self.valid_path(route) or "/api/v1/entity/ip/192.0.2.10"
            for q in route.dependant.query_params:
                for value in self.hostile_values():
                    try:
                        r = self.get(path, **{q.name: value})
                    except (httpx.InvalidURL, UnicodeEncodeError):
                        continue
                    self.assert_contained(r, "%s ?%s=%r" % (path, q.name, value[:40]))

    def test_hostile_entity_tokens(self):
        for etype in ("ip", "asn", "day", "credential", "hassh", "url", "nonsense"):
            for value in self.hostile_values() + [b64u(v) for v in fixtures.HOSTILE]:
                try:
                    r = self.get("/api/v1/entity/%s/%s" % (etype, value))
                except (httpx.InvalidURL, UnicodeEncodeError):
                    continue
                self.assert_contained(r, "%s %r" % (etype, value[:40]))

    def test_hostile_cards_bodies(self):
        for body in ({"items": "not a list"}, {"items": [1, 2, 3]}, {"items": [{"type": "ip"}]},
                     {"items": [{"type": "ip", "value": v} for v in fixtures.HOSTILE] * 60},
                     [], {"nope": True}):
            r = self.client.post("/api/v1/cards", content=json.dumps(body),
                                 headers={"content-type": "application/json"})
            self.assert_contained(r, repr(body)[:60])


class SampleBytesTests(RouteCase):
    FORBIDDEN_TEXT = ("203.0.113.50/bins/x86", "drop.example.com/stage2.sh")

    def all_responses(self):
        for route in self.routes:
            if "GET" not in route.methods:
                continue
            paths = [self.valid_path(route)] if self.valid_path(route) else self.entity_paths()
            if "{shasum}" in route.path:
                paths = [route.path.replace("{shasum}", s) for s in self.shas.values()]
            for path in paths:
                yield path, self.get(path)

    def test_no_route_returns_binary_sample_bytes(self):
        marker = fixtures.BINARY_MARKER[8:24]
        forms = [marker, marker.hex().encode(), base64.b64encode(marker)[:16],
                 marker.decode("latin-1").encode("utf-8")]
        for path, r in self.all_responses():
            for form in forms:
                self.assertNotIn(form, r.content, "%s leaked sample bytes" % path)

    def test_no_route_returns_a_text_sample_live(self):
        for path, r in self.all_responses():
            for live in self.FORBIDDEN_TEXT:
                self.assertNotIn(live, r.text, "%s returned %s undefanged" % (path, live))

    def test_the_text_sample_is_still_readable_defanged(self):
        r = self.get("/api/v1/samples/%s" % self.shas["text"])
        self.assertIn("203[.]0[.]113[.]50/bins/x86", r.json()["data"]["text"])


class HeaderTests(RouteCase):
    def test_every_response_carries_the_security_headers(self):
        paths = ["/", "/method", "/static/js/core.js"] + [
            self.valid_path(r) for r in self.routes if "GET" in r.methods and self.valid_path(r)]
        for path in paths:
            with self.subTest(path=path):
                h = self.get(path).headers
                csp = h.get("content-security-policy", "")
                script = next((d for d in csp.split(";") if d.strip().startswith("script-src")), "")
                self.assertTrue(script, "no script-src on %s" % path)
                self.assertNotIn("unsafe-inline", script)
                self.assertNotIn("unsafe-eval", script)
                self.assertEqual(h.get("x-content-type-options"), "nosniff")
                self.assertEqual(h.get("x-frame-options"), "DENY")
