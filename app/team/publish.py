"""The publisher: the only part of the team that holds credentials.

It runs as its own account after the worker and does three things with a
checked outbox. It copies the day's files into its clone of the knowledge
base and pushes them, files each new suggestion as an issue on that
repository, and mails the report. The three are independent: a failed push
does not stop the mail, and the mail says what failed.

It runs no model and executes nothing it is handed. What the worker wrote
reaches it only through outbox.check() and report.coerce().

Secrets come from the unit's credentials directory (systemd LoadCredential),
which no other unit can read:

  github-token    a fine-grained token for the knowledge base repository
                  only, with contents and issues read and write
  smtp-password   the mail account's app password
"""

import base64
import json
import os
import smtplib
import ssl
import subprocess
import urllib.error
import urllib.request
from email.message import EmailMessage

from . import outbox, report as reportmod
from .kb import md_text, one_line

API = "https://api.github.com"
TIMEOUT = 30


class PublishError(RuntimeError):
    """One of the three jobs failed. The message goes into the mail."""


def config(env=None):
    env = os.environ if env is None else env
    return {
        "state_dir": env.get("TR_TEAM_STATE", "/var/lib/radar-team"),
        "pub_dir": env.get("TR_TEAM_PUB_STATE", "/var/lib/radar-team-pub"),
        "kb_dir": env.get("TR_TEAM_KB", "/var/lib/radar-team-pub/kb"),
        "repo": env.get("TR_TEAM_KB_REPO", ""),
        "mail_from": env.get("TR_TEAM_MAIL_FROM", ""),
        "mail_to": env.get("TR_TEAM_MAIL_TO", ""),
        "smtp_host": env.get("TR_TEAM_SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": int(env.get("TR_TEAM_SMTP_PORT", "587")),
        "smtp_user": env.get("TR_TEAM_SMTP_USER", "") or env.get("TR_TEAM_MAIL_FROM", ""),
        "git_name": env.get("TR_TEAM_GIT_NAME", "Threat Radar team"),
        "git_email": env.get("TR_TEAM_GIT_EMAIL", "threat-radar-team@users.noreply.github.com"),
        "credentials": env.get("CREDENTIALS_DIRECTORY", ""),
    }


def secret(cfg, name):
    try:
        with open(os.path.join(cfg["credentials"], name), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        raise PublishError("the %s credential is not loaded into this unit" % name)


def kb_url(cfg):
    return "https://github.com/%s" % cfg["repo"] if cfg["repo"] else ""


# ---------------------------------------------------------------------------
# knowledge base
# ---------------------------------------------------------------------------

def git(cfg, args, cwd=None, run=subprocess.run):
    """Run git against the knowledge base with the token in the environment,
    where it does not show in a process listing or land in .git/config."""
    basic = base64.b64encode(("x-access-token:" + secret(cfg, "github-token")).encode()).decode()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": cfg["pub_dir"],
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic " + basic,
        # Nothing in a clone gets to run during a git command.
        "GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": "/dev/null",
    }
    cmd = ["git", "-c", "user.name=" + cfg["git_name"], "-c", "user.email=" + cfg["git_email"]]
    proc = run(cmd + list(args), cwd=cwd or cfg["kb_dir"], env=env,
               capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise PublishError("git %s failed: %s"
                           % (args[0], (proc.stderr or proc.stdout).strip()[-300:]))
    return proc.stdout


def sync(cfg, run=subprocess.run):
    """Bring the clone up to date, cloning it on first use. The worker reads
    the operator's feedback from this clone, so this runs before the worker."""
    if not cfg["repo"]:
        raise PublishError("TR_TEAM_KB_REPO is not set")
    if not os.path.isdir(os.path.join(cfg["kb_dir"], ".git")):
        os.makedirs(os.path.dirname(cfg["kb_dir"]), exist_ok=True)
        git(cfg, ["clone", "--quiet", kb_url(cfg) + ".git", cfg["kb_dir"]],
            cwd=os.path.dirname(cfg["kb_dir"]), run=run)
        return "cloned"
    try:
        git(cfg, ["pull", "--quiet", "--rebase"], run=run)
    except PublishError:
        # A rebase that stopped part way would block every later run.
        try:
            git(cfg, ["rebase", "--abort"], run=run)
        except PublishError:
            pass
        raise
    return "pulled"


def copy_in(cfg, files):
    """Write checked files into the clone at their knowledge base paths."""
    root = os.path.realpath(cfg["kb_dir"])
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not (os.path.realpath(os.path.dirname(path)) + os.sep).startswith(root + os.sep):
            raise PublishError("a directory in the clone points outside it: %s" % rel)
        if os.path.islink(path):
            os.unlink(path)
        with open(path, "wb") as fh:
            fh.write(data)


def commit_and_push(cfg, paths, day, run=subprocess.run):
    git(cfg, ["add", "--"] + sorted(paths), run=run)
    if not git(cfg, ["status", "--porcelain"], run=run).strip():
        return False
    git(cfg, ["commit", "--quiet", "-m", "Daily intel for %s" % day], run=run)
    git(cfg, ["pull", "--quiet", "--rebase"], run=run)
    git(cfg, ["push", "--quiet", "origin", "HEAD"], run=run)
    return True


# ---------------------------------------------------------------------------
# issues
# ---------------------------------------------------------------------------

def api(cfg, path, payload):
    """POST to the GitHub API. Answers (status, parsed body)."""
    req = urllib.request.Request(
        API + path, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Authorization": "Bearer " + secret(cfg, "github-token"),
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "threat-radar-team"})
    try:
        # API is a constant https URL, and path is built here from the
        # configured repository name.
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # nosec B310
            return resp.status, json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {"message": exc.read().decode("utf-8", "replace")[:300]}
    except (OSError, ValueError) as exc:
        return 0, {"message": str(exc)}


def issue_body(suggestion, day, url):
    """An issue's text. The words came from a model that read attacker text,
    so they go through md_text(), and an @ cannot notify anyone."""
    def text(value, limit):
        return md_text(value, limit).replace("@", "(at)")
    lines = ["Area: %s" % suggestion["area"], "",
             text(suggestion["body"], 2000), ""]
    if suggestion["evidence"]:
        lines += ["Evidence from the record:", "", text(suggestion["evidence"], 800), ""]
    lines += ["Raised by the report for %s%s." % (
        day, " ([daily note](%s/blob/main/daily/%s/%s.md))" % (url, day[:4], day) if url else ""),
        "If this is wrong or not wanted, close it and add a line to feedback.md, "
        "which every run reads."]
    return "\n".join(lines)


def raise_issues(cfg, report, post=api):
    """File each suggestion not raised before. Answers ({id: issue url},
    problems) and updates state/suggestions.json in the clone."""
    path = os.path.join(cfg["kb_dir"], "state", "suggestions.json")
    try:
        with open(path, encoding="utf-8") as fh:
            state = [s for s in json.load(fh) if isinstance(s, dict)]
    except (OSError, ValueError):
        state = []
    known = {s.get("id"): s for s in state}
    urls, problems = {}, []
    for s in report["suggestions"]:
        if s["id"] in known:
            if known[s["id"]].get("url"):
                urls[s["id"]] = known[s["id"]]["url"]
            continue
        payload = {"title": one_line(s["title"], 120).replace("@", "(at)"),
                   "body": issue_body(s, report["day"], kb_url(cfg)),
                   "labels": ["team", s["area"]]}
        status, body = post(cfg, "/repos/%s/issues" % cfg["repo"], payload)
        if status == 422:
            # A label that does not exist on the repository refuses the issue.
            status, body = post(cfg, "/repos/%s/issues" % cfg["repo"],
                                dict(payload, labels=[]))
        entry = {"id": s["id"], "title": s["title"], "area": s["area"], "day": report["day"]}
        if status == 201 and isinstance(body.get("html_url"), str):
            entry.update(number=body.get("number"), url=body["html_url"])
            urls[s["id"]] = body["html_url"]
        else:
            problems.append("The suggestion \"%s\" was not filed as an issue (HTTP %s)."
                            % (s["title"], status))
            continue
        state.append(entry)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1)
        fh.write("\n")
    return urls, problems


# ---------------------------------------------------------------------------
# mail
# ---------------------------------------------------------------------------

def message(cfg, subject, text, html=None, images=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "Threat Radar <%s>" % cfg["mail_from"]
    msg["To"] = cfg["mail_to"]
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
        part = msg.get_payload()[1]
        for name, data in (images or {}).items():
            part.add_related(data, "image", "png", cid="<%s>" % name,
                             filename="%s.png" % name, disposition="inline")
    return msg


def send(cfg, msg, smtp=smtplib.SMTP):
    if not cfg["mail_from"] or not cfg["mail_to"]:
        raise PublishError("TR_TEAM_MAIL_FROM and TR_TEAM_MAIL_TO are not both set")
    password = secret(cfg, "smtp-password")
    try:
        with smtp(cfg["smtp_host"], cfg["smtp_port"], timeout=TIMEOUT) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(cfg["smtp_user"], password)
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise PublishError("the mail was not sent: %s" % str(exc)[:200])


# ---------------------------------------------------------------------------
# one day
# ---------------------------------------------------------------------------

def _marker(cfg, day, kind):
    return os.path.join(cfg["pub_dir"], "sent", "%s.%s" % (day, kind))


def _mark(cfg, day, kind):
    os.makedirs(os.path.dirname(_marker(cfg, day, kind)), exist_ok=True)
    with open(_marker(cfg, day, kind), "w", encoding="utf-8") as fh:
        fh.write("")


def publish(cfg, day, run=subprocess.run, post=api, smtp=smtplib.SMTP, log=print):
    """Publish one day. Answers a process exit code.

    Each day is mailed once: a marker file records the send, so a retry
    after a failure does the missing work and a second run does nothing.
    """
    if os.path.exists(_marker(cfg, day, "sent")):
        log("the report for %s was already sent" % day)
        return 0
    try:
        raw, files = outbox.check(cfg["state_dir"], day)
        report = reportmod.coerce(raw)
    except ValueError as exc:   # OutboxError is a ValueError
        log("no usable outbox for %s: %s" % (day, exc))
        if not os.path.exists(_marker(cfg, day, "noticed")):
            send(cfg, message(
                cfg, "Threat Radar %s: no report was produced" % day,
                "The team produced no report for %s.\n\nReason: %s\n\n"
                "On the Pi, the worker's log is in:\n\n"
                "    journalctl -u radar-team -n 80\n" % (day, exc)), smtp)
            _mark(cfg, day, "noticed")
        return 1

    problems, issues = [], {}
    try:
        sync(cfg, run)
        copy_in(cfg, files)
        issues, failed = raise_issues(cfg, report, post)
        problems += failed
        commit_and_push(cfg, list(files) + ["state/suggestions.json"], day, run)
    except (PublishError, OSError) as exc:
        log("knowledge base: %s" % exc)
        problems.append("The knowledge base was not fully updated: %s" % exc)

    report["problems"] += problems
    images = {name: files["charts/%s/%s.png" % (day, name)] for name in report["charts"]
              if "charts/%s/%s.png" % (day, name) in files}
    report["charts"] = [name for name in report["charts"] if name in images]
    send(cfg, message(cfg, reportmod.subject(report), reportmod.email_text(report),
                      reportmod.email_html(report, kb_url(cfg), issues), images), smtp)
    _mark(cfg, day, "sent")
    log("sent the report for %s%s" % (day, " with %d problems" % len(problems)
                                       if problems else ""))
    return 0
