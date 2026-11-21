#!/usr/bin/env python3
"""Threat intel team worker: one Eastern day from the database to the outbox.

Runs from radar-team.timer each morning as the radar-team account, after
radar-team-sync has refreshed the knowledge base clone it reads. It opens
the collector database read-only and holds no credential except the model
token. bin/team_publish.py, under another account, sends what this leaves.

    team_worker.py                   the day that ended at the last Eastern midnight
    team_worker.py --day 2026-11-21  that day
    team_worker.py --no-model        numbers, charts and campaign counts only
    team_worker.py --show-document   print what the reader stage would be shown
    team_worker.py --check           one small model call with the stages' flags
"""

import argparse
import fcntl
import os
import sys

APP_DIR = os.environ.get("TR_APP", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, APP_DIR)

from app import team  # noqa: E402
from app.analytics import clock, db  # noqa: E402
from app.team import bundle, daily, kb, model  # noqa: E402


def lock(state_dir):
    run_dir = os.environ.get("RUNTIME_DIRECTORY") or state_dir
    fh = open(os.path.join(run_dir, "team.lock"), "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another team run holds the lock, exiting")
        sys.exit(0)
    return fh


def main(argv=None):
    ap = argparse.ArgumentParser(description="Threat intel team worker")
    ap.add_argument("--day", help="Eastern day to cover, YYYY-MM-DD")
    ap.add_argument("--no-model", action="store_true")
    ap.add_argument("--show-document", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)

    if args.check:
        try:
            print(model.ask("Answer with the single word: ready", "Are you there?").strip())
        except model.StageError as exc:
            print("model check failed: %s" % exc)
            return 1
        return 0

    day = args.day or clock.days_ago(1)
    if not kb.DAY_RE.match(day):
        ap.error("--day takes YYYY-MM-DD")
    con = db.connect_ro()
    if args.show_document:
        known = kb.load(team.KB_DIR)
        text, _tag = bundle.document(bundle.build(con, day, kb.known_shapes(known),
                                                  known["watch"]))
        print(text)
        return 0

    os.makedirs(team.STATE_DIR, exist_ok=True)
    held = lock(team.STATE_DIR)
    use_model = not args.no_model and model.available()
    if not args.no_model and not use_model:
        print("the claude CLI is not on PATH, running without the model stages")
    report = daily.run(con, day, team.KB_DIR, team.STATE_DIR, use_model=use_model)
    con.close()
    held.close()
    # The outbox was written either way. A failed stage is in the report and
    # also fails the unit, so it shows in systemctl.
    return 1 if report["problems"] and not args.no_model else 0


if __name__ == "__main__":
    sys.exit(main())
