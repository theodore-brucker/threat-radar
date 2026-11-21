#!/usr/bin/env python3
"""Threat intel team publisher: the outbox to the knowledge base and the mail.

Runs as the radar-team-pub account, which holds the GitHub token and the mail
password and reads nothing an attacker wrote except the checked outbox.

    team_publish.py sync                 refresh the knowledge base clone
    team_publish.py publish              publish the day that ended at the last
                                         Eastern midnight
    team_publish.py publish --day D      publish that day
    team_publish.py preview --day D DIR  write the mail as files into DIR and
                                         send nothing
"""

import argparse
import os
import sys

APP_DIR = os.environ.get("TR_APP", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, APP_DIR)

from app.analytics import clock  # noqa: E402
from app.team import kb, outbox, publish, report as reportmod  # noqa: E402


def preview(cfg, day, out_dir):
    """The mail a publish would send, as report.html, report.txt and the
    chart files, so it can be read before any credential is configured."""
    raw, files = outbox.check(cfg["state_dir"], day)
    report = reportmod.coerce(raw)
    os.makedirs(out_dir, exist_ok=True)
    html = reportmod.email_html(report, publish.kb_url(cfg))
    for name in report["charts"]:
        data = files.get("charts/%s/%s.png" % (day, name))
        if data:
            with open(os.path.join(out_dir, name + ".png"), "wb") as fh:
                fh.write(data)
            html = html.replace("cid:%s" % name, name + ".png")
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><meta charset=utf-8><title>%s</title>\n%s\n"
                 % (reportmod.subject(report).replace("<", ""), html))
    with open(os.path.join(out_dir, "report.txt"), "w", encoding="utf-8") as fh:
        fh.write(reportmod.email_text(report))
    print("wrote %s" % os.path.join(out_dir, "report.html"))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Threat intel team publisher")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("sync")
    pub = sub.add_parser("publish")
    pub.add_argument("--day")
    pre = sub.add_parser("preview")
    pre.add_argument("--day")
    pre.add_argument("out_dir")
    args = ap.parse_args(argv)

    cfg = publish.config()
    try:
        if args.command == "sync":
            print("knowledge base %s" % publish.sync(cfg))
            return 0
        day = args.day or clock.days_ago(1)
        if not kb.DAY_RE.match(day):
            ap.error("--day takes YYYY-MM-DD")
        if args.command == "preview":
            return preview(cfg, day, args.out_dir)
        return publish.publish(cfg, day)
    except (publish.PublishError, outbox.OutboxError) as exc:
        print("%s failed: %s" % (args.command, exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
