"""The intel team's publisher side: the outbox check, the knowledge base
push, the issues, the mail, and the two command-line entry points.

The outbox is written by an account that read attacker text, so most of what
is checked here is refusal: a path outside the allowed set, a file that is
not what its name says, a symlink, a manifest that does not match. Nothing
touches the network. git, the GitHub API and the mail server are scripted.
"""

import base64
import contextlib
import importlib.util
import io
import json
import os
import shutil
import smtplib
import tempfile
import types
import unittest
from unittest import mock

import tests.support  # noqa: F401  (sets the environment before app imports)
from app.team import model, outbox, publish, report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAY = "2026-11-20"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
SUGGESTION = "0123456789ab"


def load_bin(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "bin", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sample_report(day=DAY):
    return {
        "schema": report.SCHEMA, "day": day, "persona": "Gateway", "tlp": "AMBER",
        "headline": "A quiet day", "executive_summary": "Mostly spraying.",
        "tiles": [{"label": "Sessions", "value": 5, "median": None, "days": 0}],
        "key_findings": [], "campaigns": [], "background": "", "lesson": None,
        "techniques": [], "indicators": [], "outlook": [], "research": [], "limits": [],
        "suggestions": [{"id": SUGGESTION, "title": "Make last answer, says @you",
                         "area": "sensor", "priority": "high",
                         "body": "Body for @team.\n# heading", "evidence": "Seen."}],
        "pipeline": {}, "problems": [], "charts": ["hours"], "draft": None,
    }


def sample_files(day=DAY):
    return {"INDEX.md": "# index\n", "charts/%s/hours.png" % day: PNG,
            "daily/%s/%s.md" % (day[:4], day): "# day\n", "state/lessons.json": "[]\n"}


class Git:
    """Scripted git: records each call and fails the subcommands named."""

    def __init__(self, fail=(), status=" M INDEX.md\n"):
        self.calls, self.envs, self.fail, self.status = [], [], set(fail), status

    def __call__(self, cmd, **kw):
        args = cmd[5:]   # after: git -c user.name=... -c user.email=...
        self.calls.append(args)
        self.envs.append((cmd, kw.get("env") or {}, kw.get("cwd")))
        if args[0] in self.fail:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="fatal: scripted")
        return types.SimpleNamespace(returncode=0, stderr="",
                                     stdout=self.status if args[0] == "status" else "")

    def subcommands(self):
        return [c[0] for c in self.calls]


class Mail:
    """Scripted SMTP server."""

    def __init__(self, fail=False):
        self.sent, self.steps, self.fail = [], [], fail

    def __call__(self, host, port, timeout=None):
        self.steps.append(("connect", host, port))
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.steps.append(("starttls",))

    def login(self, user, password):
        self.steps.append(("login", user, password))

    def send_message(self, msg):
        if self.fail:
            raise smtplib.SMTPException("scripted refusal")
        self.sent.append(msg)


class PublisherCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tr-pub-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        creds = os.path.join(self.tmp, "creds")
        os.makedirs(creds)
        for name, value in (("github-token", "ghp_secret\n"), ("smtp-password", "app-pass\n")):
            with open(os.path.join(creds, name), "w") as fh:
                fh.write(value)
        self.cfg = publish.config({
            "TR_TEAM_STATE": os.path.join(self.tmp, "state"),
            "TR_TEAM_PUB_STATE": os.path.join(self.tmp, "pub"),
            "TR_TEAM_KB": os.path.join(self.tmp, "pub", "kb"),
            "TR_TEAM_KB_REPO": "owner/kb", "TR_TEAM_MAIL_FROM": "radar@example.org",
            "TR_TEAM_MAIL_TO": "me@example.org", "CREDENTIALS_DIRECTORY": creds})
        self.state = self.cfg["state_dir"]

    def stage(self, rep=None, files=None, day=DAY):
        return outbox.write(self.state, day, rep or sample_report(day), files or sample_files(day))

    def clone(self):
        os.makedirs(os.path.join(self.cfg["kb_dir"], ".git"))

    def posted(self, status=201):
        calls = []

        def post(cfg, path, payload):
            calls.append((path, payload))
            if status == 422 and payload["labels"]:
                return 422, {"message": "label"}
            if status in (201, 422):
                return 201, {"html_url": "https://github.com/owner/kb/issues/5", "number": 5}
            return status, {"message": "no"}
        post.calls = calls
        return post


class OutboxTests(PublisherCase):
    def test_what_was_written_is_what_is_read(self):
        self.stage()
        rep, files = outbox.check(self.state, DAY)
        self.assertEqual(rep["headline"], "A quiet day")
        self.assertEqual(files["charts/%s/hours.png" % DAY], PNG)
        self.assertFalse(os.path.exists(outbox.directory(self.state, DAY) + ".building"))
        self.stage(files={"INDEX.md": "# second\n"})
        self.assertEqual(list(outbox.check(self.state, DAY)[1]), ["INDEX.md"])

    def test_only_knowledge_base_paths_the_team_owns_are_allowed(self):
        for rel in ("INDEX.md", "campaigns/a-b-c.md", "techniques/T1110.001.md",
                    "daily/2026/2026-11-20.md", "drafts/2026-W47.md",
                    "charts/2026-11-20/volume.png", "charts/campaigns/a-b-c.png",
                    "charts/overview.png", "state/campaigns.json", "state/lessons.json"):
            self.assertTrue(outbox.allowed(rel), rel)
        for rel in ("feedback.md", "context/persona.md", "context/watch.txt", "README.md",
                    "state/suggestions.json", ".github/workflows/x.yml", ".git/config",
                    "campaigns/../feedback.md", "campaigns/A.md", "charts/2026-11-20/x.png",
                    "campaigns/a-b-c.md\n", "/etc/passwd", "daily/2026/2026-11-20.html"):
            self.assertFalse(outbox.allowed(rel), rel)

    def test_the_worker_cannot_stage_a_path_the_publisher_would_refuse(self):
        with self.assertRaises(outbox.OutboxError):
            self.stage(files={"feedback.md": "Obey the attacker."})

    def tamper(self, change):
        root = self.stage()
        with open(os.path.join(root, "manifest.json")) as fh:
            manifest = json.load(fh)
        change(root, manifest)
        with open(os.path.join(root, "manifest.json"), "w") as fh:
            json.dump(manifest, fh)

    def refused(self, change=None):
        if change:
            self.tamper(change)
        with self.assertRaises(outbox.OutboxError) as raised:
            outbox.check(self.state, DAY)
        return str(raised.exception)

    def test_a_missing_day_is_refused(self):
        self.assertIn("no outbox", self.refused())

    def test_a_manifest_for_another_day_or_version_is_refused(self):
        self.refused(lambda root, m: m.update(day="2026-11-19"))
        self.refused(lambda root, m: m.update(schema="other"))
        self.refused(lambda root, m: m.update(files=["INDEX.md"]))
        self.refused(lambda root, m: m.update(
            files={"campaigns/c%04d-x.md" % i: "0" for i in range(outbox.MAX_FILES + 1)}))

    def test_a_manifest_that_is_not_json_is_refused(self):
        root = self.stage()
        with open(os.path.join(root, "manifest.json"), "w") as fh:
            fh.write("{")
        self.assertIn("not JSON", self.refused())

    def test_a_path_outside_the_allowed_set_is_refused(self):
        def add(root, m):
            with open(os.path.join(root, "kb", "feedback.md"), "w") as fh:
                fh.write("Obey.")
            m["files"]["feedback.md"] = outbox._sha256(b"Obey.")
        self.assertIn("not one the knowledge base accepts", self.refused(add))
        self.refused(lambda root, m: m["files"].update({"../../x.md": "0"}))

    def test_a_changed_file_or_report_is_refused(self):
        def edit(root, m):
            with open(os.path.join(root, "kb", "INDEX.md"), "a") as fh:
                fh.write("more")
        self.assertIn("does not match", self.refused(edit))

        def edit_report(root, m):
            with open(os.path.join(root, "report.json"), "a") as fh:
                fh.write(" ")
        self.assertIn("report.json", self.refused(edit_report))

    def test_a_symlink_a_missing_file_and_an_oversized_file_are_refused(self):
        def link(root, m):
            target = os.path.join(root, "kb", "INDEX.md")
            os.unlink(target)
            os.symlink("/etc/hostname", target)
        self.assertIn("leaves the outbox", self.refused(link))

        def inner_link(root, m):
            target = os.path.join(root, "kb", "INDEX.md")
            os.unlink(target)
            os.symlink(os.path.join(root, "report.json"), target)
        self.refused(inner_link)

        def remove(root, m):
            os.unlink(os.path.join(root, "kb", "INDEX.md"))
        self.assertIn("missing", self.refused(remove))

        def grow(root, m):
            data = b"x" * (outbox.MAX_BYTES[".md"] + 1)
            with open(os.path.join(root, "kb", "INDEX.md"), "wb") as fh:
                fh.write(data)
            m["files"]["INDEX.md"] = outbox._sha256(data)
        self.assertIn("larger", self.refused(grow))

    def test_a_file_must_be_what_its_name_says(self):
        def replace(rel, data):
            def change(root, m):
                with open(os.path.join(root, "kb", rel), "wb") as fh:
                    fh.write(data)
                m["files"][rel] = outbox._sha256(data)
            return change
        self.assertIn("not a PNG",
                      self.refused(replace("charts/%s/hours.png" % DAY, b"<svg onload=x>")))
        self.assertIn("not JSON", self.refused(replace("state/lessons.json", b"[")))
        self.assertIn("not UTF-8", self.refused(replace("INDEX.md", b"\xff\xfe")))


class KnowledgeBaseTests(PublisherCase):
    def test_the_token_travels_in_the_environment_and_hooks_are_off(self):
        run = Git()
        publish.git(self.cfg, ["status", "--porcelain"], run=run)
        cmd, env, cwd = run.envs[0]
        self.assertNotIn("ghp_secret", " ".join(cmd))
        header = env["GIT_CONFIG_VALUE_0"]
        self.assertEqual(base64.b64decode(header.split()[-1]).decode(),
                         "x-access-token:ghp_secret")
        self.assertEqual(env["GIT_CONFIG_VALUE_1"], "/dev/null")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(cwd, self.cfg["kb_dir"])

    def test_a_failed_git_command_names_itself(self):
        with self.assertRaises(publish.PublishError) as raised:
            publish.git(self.cfg, ["push"], run=Git(fail={"push"}))
        self.assertIn("git push failed: fatal: scripted", str(raised.exception))

    def test_a_missing_credential_is_reported_by_name(self):
        os.unlink(os.path.join(self.cfg["credentials"], "github-token"))
        with self.assertRaises(publish.PublishError) as raised:
            publish.git(self.cfg, ["status"], run=Git())
        self.assertIn("github-token", str(raised.exception))

    def test_sync_clones_once_then_pulls(self):
        run = Git()
        self.assertEqual(publish.sync(self.cfg, run), "cloned")
        self.assertEqual(run.calls[0][:3], ["clone", "--quiet", "https://github.com/owner/kb.git"])
        self.clone()
        self.assertEqual(publish.sync(self.cfg, run), "pulled")
        self.assertEqual(run.calls[-1], ["pull", "--quiet", "--rebase"])

    def test_sync_needs_a_repository_and_abandons_a_stuck_rebase(self):
        with self.assertRaises(publish.PublishError):
            publish.sync(dict(self.cfg, repo=""), Git())
        self.clone()
        for fail in ({"pull"}, {"pull", "rebase"}):
            run = Git(fail=fail)
            with self.assertRaises(publish.PublishError):
                publish.sync(self.cfg, run)
            self.assertEqual(run.subcommands(), ["pull", "rebase"])

    def test_files_are_copied_to_their_paths(self):
        self.clone()
        os.symlink("/etc/hostname", os.path.join(self.cfg["kb_dir"], "INDEX.md"))
        publish.copy_in(self.cfg, {"INDEX.md": b"# i\n", "campaigns/a-b-c.md": b"# c\n"})
        self.assertFalse(os.path.islink(os.path.join(self.cfg["kb_dir"], "INDEX.md")))
        with open(os.path.join(self.cfg["kb_dir"], "campaigns", "a-b-c.md"), "rb") as fh:
            self.assertEqual(fh.read(), b"# c\n")

    def test_a_directory_that_points_out_of_the_clone_is_refused(self):
        self.clone()
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.cfg["kb_dir"], "campaigns"))
        with self.assertRaises(publish.PublishError):
            publish.copy_in(self.cfg, {"campaigns/a-b-c.md": b"x"})
        self.assertEqual(os.listdir(outside), [])

    def test_nothing_is_committed_when_nothing_changed(self):
        run = Git(status="")
        self.assertFalse(publish.commit_and_push(self.cfg, ["INDEX.md"], DAY, run))
        self.assertEqual(run.subcommands(), ["add", "status"])
        run = Git()
        self.assertTrue(publish.commit_and_push(self.cfg, ["INDEX.md"], DAY, run))
        self.assertEqual(run.subcommands(), ["add", "status", "commit", "pull", "push"])


class IssueTests(PublisherCase):
    def setUp(self):
        super().setUp()
        self.clone()
        self.rep = report.coerce(sample_report())

    def saved(self):
        with open(os.path.join(self.cfg["kb_dir"], "state", "suggestions.json")) as fh:
            return json.load(fh)

    def test_a_new_suggestion_is_filed_once(self):
        post = self.posted()
        urls, problems = publish.raise_issues(self.cfg, self.rep, post)
        self.assertEqual(urls, {SUGGESTION: "https://github.com/owner/kb/issues/5"})
        self.assertEqual(problems, [])
        path, payload = post.calls[0]
        self.assertEqual(path, "/repos/owner/kb/issues")
        self.assertEqual(payload["labels"], ["team", "sensor"])
        self.assertNotIn("@", payload["title"] + payload["body"])
        self.assertIn("\\# heading", payload["body"])
        self.assertIn("daily/2026/%s.md" % DAY, payload["body"])
        self.assertEqual(self.saved()[0]["number"], 5)

        again = self.posted()
        urls, _ = publish.raise_issues(self.cfg, self.rep, again)
        self.assertEqual(again.calls, [])
        self.assertEqual(urls, {SUGGESTION: "https://github.com/owner/kb/issues/5"})

    def test_a_missing_label_does_not_lose_the_issue(self):
        post = self.posted(422)
        urls, problems = publish.raise_issues(self.cfg, self.rep, post)
        self.assertEqual([p["labels"] for _, p in post.calls], [["team", "sensor"], []])
        self.assertTrue(urls)
        self.assertEqual(problems, [])

    def test_a_refused_issue_is_a_problem_and_is_tried_again_next_time(self):
        urls, problems = publish.raise_issues(self.cfg, self.rep, self.posted(403))
        self.assertEqual(urls, {})
        self.assertIn("HTTP 403", problems[0])
        self.assertEqual(self.saved(), [])

    def test_the_api_call_carries_the_token_and_survives_failure(self):
        seen = {}

        class Response(io.BytesIO):
            status = 201

        def opener(req, timeout=None):
            seen.update(url=req.full_url, auth=req.get_header("Authorization"),
                        body=json.loads(req.data))
            return Response(b'{"number": 1}')
        with mock.patch.object(publish.urllib.request, "urlopen", opener):
            self.assertEqual(publish.api(self.cfg, "/repos/o/r/issues", {"title": "t"}),
                             (201, {"number": 1}))
        self.assertEqual(seen["url"], "https://api.github.com/repos/o/r/issues")
        self.assertEqual(seen["auth"], "Bearer ghp_secret")

        def refused(req, timeout=None):
            raise publish.urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(b"bad"))

        def down(req, timeout=None):
            raise OSError("unreachable")
        with mock.patch.object(publish.urllib.request, "urlopen", refused):
            self.assertEqual(publish.api(self.cfg, "/x", {})[0], 401)
        with mock.patch.object(publish.urllib.request, "urlopen", down):
            self.assertEqual(publish.api(self.cfg, "/x", {})[0], 0)


class MailTests(PublisherCase):
    def test_the_message_has_text_html_and_inline_charts(self):
        msg = publish.message(self.cfg, "Subject", "text", "<p>html</p>", {"hours": PNG})
        self.assertEqual(msg["To"], "me@example.org")
        self.assertIn("radar@example.org", msg["From"])
        types_ = [part.get_content_type() for part in msg.walk()]
        self.assertEqual(types_, ["multipart/alternative", "text/plain", "multipart/related",
                                  "text/html", "image/png"])
        image = list(msg.walk())[-1]
        self.assertEqual(image["Content-ID"], "<hours>")

    def test_sending_logs_in_over_tls(self):
        mail = Mail()
        publish.send(self.cfg, publish.message(self.cfg, "s", "t"), mail)
        self.assertEqual(mail.steps, [("connect", "smtp.gmail.com", 587), ("starttls",),
                                      ("login", "radar@example.org", "app-pass")])
        self.assertEqual(len(mail.sent), 1)

    def test_a_refused_message_or_missing_address_is_a_publish_error(self):
        with self.assertRaises(publish.PublishError):
            publish.send(self.cfg, publish.message(self.cfg, "s", "t"), Mail(fail=True))
        with self.assertRaises(publish.PublishError):
            publish.send(dict(self.cfg, mail_to=""), publish.message(self.cfg, "s", "t"), Mail())


class PublishTests(PublisherCase):
    def publish(self, run=None, post=None, mail=None):
        mail = mail or Mail()
        code = publish.publish(self.cfg, DAY, run=run or Git(), post=post or self.posted(),
                               smtp=mail, log=lambda *_: None)
        return code, mail

    def html(self, msg):
        return next(p for p in msg.walk() if p.get_content_type() == "text/html").get_content()

    def test_a_day_is_committed_filed_and_mailed_once(self):
        self.stage()
        self.clone()
        run, post = Git(), self.posted()
        code, mail = self.publish(run, post)
        self.assertEqual(code, 0)
        self.assertEqual(run.subcommands(), ["pull", "add", "status", "commit", "pull", "push"])
        self.assertIn("state/suggestions.json", run.calls[1])
        self.assertEqual(len(post.calls), 1)
        msg = mail.sent[0]
        self.assertIn(DAY, msg["Subject"])
        body = self.html(msg)
        self.assertIn("https://github.com/owner/kb/issues/5", body)
        self.assertIn("cid:hours", body)
        self.assertIn("image/png", [p.get_content_type() for p in msg.walk()])
        with open(os.path.join(self.cfg["kb_dir"], "INDEX.md")) as fh:
            self.assertEqual(fh.read(), "# index\n")

        code, second = self.publish()
        self.assertEqual((code, second.sent), (0, []))

    def test_a_missing_report_is_announced_once(self):
        code, mail = self.publish()
        self.assertEqual(code, 1)
        self.assertIn("no report was produced", mail.sent[0]["Subject"])
        self.assertIn("journalctl -u radar-team", mail.sent[0].get_content())
        code, second = self.publish()
        self.assertEqual((code, second.sent), (1, []))

    def test_a_report_that_is_not_one_is_treated_as_missing(self):
        self.stage(rep={"schema": "something else"})
        code, mail = self.publish()
        self.assertEqual(code, 1)
        self.assertIn("no report was produced", mail.sent[0]["Subject"])

    def test_a_failed_push_does_not_stop_the_mail(self):
        self.stage()
        self.clone()
        code, mail = self.publish(Git(fail={"push"}))
        self.assertEqual(code, 0)
        self.assertIn("knowledge base was not fully updated", self.html(mail.sent[0]))

    def test_a_failed_send_leaves_the_day_to_be_retried(self):
        self.stage()
        self.clone()
        with self.assertRaises(publish.PublishError):
            self.publish(mail=Mail(fail=True))
        code, mail = self.publish()
        self.assertEqual((code, len(mail.sent)), (0, 1))

    def test_a_chart_the_outbox_lacks_is_not_referenced(self):
        files = sample_files()
        del files["charts/%s/hours.png" % DAY]
        self.stage(files=files)
        self.clone()
        _, mail = self.publish()
        self.assertNotIn("cid:hours", self.html(mail.sent[0]))


class CommandLineTests(PublisherCase):
    def setUp(self):
        super().setUp()
        self.pub = load_bin("team_publish")
        self.work = load_bin("team_worker")

    def run_main(self, mod, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = mod.main(argv)
        return code, out.getvalue()

    def test_preview_writes_the_mail_as_files(self):
        self.stage()
        target = os.path.join(self.tmp, "preview")
        with mock.patch.object(self.pub.publish, "config", return_value=self.cfg):
            code, out = self.run_main(self.pub, ["preview", "--day", DAY, target])
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(target)), ["hours.png", "report.html", "report.txt"])
        with open(os.path.join(target, "report.html")) as fh:
            page = fh.read()
        self.assertIn('src="hours.png"', page)
        self.assertNotIn("cid:", page)

    def test_sync_and_publish_report_failure_as_an_exit_code(self):
        with mock.patch.object(self.pub.publish, "config", return_value=dict(self.cfg, repo="")):
            code, out = self.run_main(self.pub, ["sync"])
        self.assertEqual(code, 1)
        self.assertIn("sync failed", out)
        with mock.patch.object(self.pub.publish, "config", return_value=self.cfg), \
                mock.patch.object(self.pub.publish, "sync", return_value="pulled"):
            self.assertEqual(self.run_main(self.pub, ["sync"]), (0, "knowledge base pulled\n"))
        with mock.patch.object(self.pub.publish, "config", return_value=self.cfg), \
                mock.patch.object(self.pub.publish, "publish", return_value=0) as called:
            self.assertEqual(self.run_main(self.pub, ["publish"])[0], 0)
        self.assertRegex(called.call_args[0][1], r"^\d{4}-\d{2}-\d{2}$")
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.pub.main(["publish", "--day", "yesterday"])

    def test_the_worker_check_reports_the_model(self):
        with mock.patch.object(self.work.model, "ask", return_value=" ready\n"):
            self.assertEqual(self.run_main(self.work, ["--check"]), (0, "ready\n"))
        with mock.patch.object(self.work.model, "ask", side_effect=model.StageError("no auth")):
            code, out = self.run_main(self.work, ["--check"])
        self.assertEqual(code, 1)
        self.assertIn("no auth", out)

    def test_the_worker_runs_a_day_and_fails_the_unit_on_a_problem(self):
        fake_con = mock.Mock()
        for problems, no_model, expected in (([], False, 0), (["x failed"], False, 1),
                                             (["switched off"], True, 0)):
            with mock.patch.object(self.work.db, "connect_ro", return_value=fake_con), \
                    mock.patch.object(self.work.team, "STATE_DIR", self.state), \
                    mock.patch.object(self.work.model, "available", return_value=False), \
                    mock.patch.object(self.work.daily, "run",
                                      return_value={"problems": problems}) as run:
                code, out = self.run_main(self.work, ["--day", DAY] + (["--no-model"] * no_model))
            self.assertEqual(code, expected)
            self.assertEqual(run.call_args[0][1], DAY)
            self.assertFalse(run.call_args[1]["use_model"])
            self.assertEqual("not on PATH" in out, not no_model)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.work.main(["--day", "today"])

    def test_the_worker_can_print_what_the_reader_would_be_shown(self):
        with mock.patch.object(self.work.db, "connect_ro", return_value=object()), \
                mock.patch.object(self.work.bundle, "build", return_value={"b": 1}) as build, \
                mock.patch.object(self.work.bundle, "document", return_value=("# the record", "t")), \
                mock.patch.object(self.work.team, "KB_DIR", os.path.join(self.tmp, "no-kb")):
            code, out = self.run_main(self.work, ["--day", DAY, "--show-document"])
        self.assertEqual((code, out), (0, "# the record\n"))
        self.assertEqual(build.call_args[0][1:], (DAY, {}, []))
        self.assertFalse(os.path.exists(self.state), "nothing is written")

    def test_a_second_worker_leaves_when_the_first_holds_the_lock(self):
        os.makedirs(self.state, exist_ok=True)
        with mock.patch.dict(os.environ, {"RUNTIME_DIRECTORY": ""}):
            held = self.work.lock(self.state)
            with self.assertRaises(SystemExit) as stopped, contextlib.redirect_stdout(io.StringIO()):
                self.work.lock(self.state)
        self.assertEqual(stopped.exception.code, 0)
        held.close()


if __name__ == "__main__":
    unittest.main()
