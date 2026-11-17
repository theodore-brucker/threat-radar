#!/usr/bin/env python3
"""Incident trends worker: migrate, load the seed, collect, classify, roll up.

Runs from radar-trends.timer every two hours as the radar user. Each source is
fetched only when its own interval has passed, so most runs touch one feed.
The rollup runs when the last one is more than a day old.

Writes are budgeted. The kernel's count of bytes this process wrote
(/proc/self/io) is added to trend_write_log after every run, and a run that
finds 50 MB already logged for the day skips collection.

    trends_worker.py                 one normal run
    trends_worker.py --dry-run       fetch and parse every source, write nothing
    trends_worker.py --source NAME   only that source, ignoring its interval
    trends_worker.py --no-model      keyword rules only
    trends_worker.py --rollup        rebuild the weekly tables now
"""

import argparse
import datetime as dt
import fcntl
import os
import sys

APP_DIR = os.environ.get("TR_APP", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, APP_DIR)

from app.analytics import db  # noqa: E402
from app.trends import MIGRATION, collectors, classify, fetch, rollup, seed  # noqa: E402

DAILY_WRITE_CAP = int(os.environ.get("TR_TRENDS_WRITE_CAP", str(50 * 1024 * 1024)))
RECHECK_DAYS = 7


def written_bytes():
    """Bytes this process has caused to be written to storage, or 0 where
    /proc is not available."""
    try:
        with open("/proc/self/io") as fh:
            for line in fh:
                if line.startswith("write_bytes:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def lock():
    run_dir = os.environ.get("RUNTIME_DIRECTORY") or os.path.dirname(db.DB_PATH)
    fh = open(os.path.join(run_dir, "trends.lock"), "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another trends run holds the lock, exiting")
        sys.exit(0)
    return fh


def migrate(con):
    with open(MIGRATION, encoding="utf-8") as fh:
        con.executescript(fh.read())


def meta(con, key):
    row = con.execute("SELECT value FROM trend_meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def due(con, name, every_hours, now):
    row = con.execute("SELECT last_run FROM trend_fetch_state WHERE source=?", (name,)).fetchone()
    if not row or not row[0]:
        return True
    last = dt.datetime.strptime(row[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    # Ten minutes of slack so a timer that fires a little early still counts.
    return now - last >= dt.timedelta(hours=every_hours, minutes=-10)


def seed_until(con):
    row = con.execute("SELECT MAX(started) FROM incident WHERE source='seed' AND kind='org'").fetchone()
    return row[0] or "0000-00-00"


def collect(con, name, spec, use_model, dry_run):
    headers = {}
    if spec.get("token_env"):
        token = os.environ.get(spec["token_env"])
        if not token:
            return {"source": name, "skipped": f"{spec['token_env']} is not set"}
        headers[spec["header"]] = token
    status, body, etag, last_mod = fetch.get(name, spec["url"], con, headers)
    result = {"source": name, "http": status, "bytes_fetched": len(body or b"")}
    if status == 304:
        result["rows"] = 0
        if not dry_run:
            fetch.save_state(con, name, status)
        return result
    rows = spec["parse"](body)
    result["rows"] = len(rows)
    if dry_run:
        if name in ("dysruptionhub", "cisa-advisories"):
            labels = [classify.keyword(f"{r['title']}. {r.get('categories') or ''}") for r in rows]
            result["ambiguous"] = sum(1 for _, decided in labels if not decided)
        return result
    with con:
        if name == "cisa-kev":
            result["new"] = collectors.store_kev(con, rows)
        elif name == "ransomware-live":
            result["new"] = collectors.store_claims(con, rows)
        else:
            result["new"] = collectors.store_items(
                con, name, rows, use_model, opens_incidents=(name == "dysruptionhub"),
                seed_until=seed_until(con))
        fetch.save_state(con, name, status, etag, last_mod, len(body))
    return result


def recheck(con, now):
    """Undisclosed incidents whose statements now include a stated cause take
    the earliest one. Each incident is looked at once a week."""
    cutoff = (now - dt.timedelta(days=RECHECK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = db.qall(con, """
        SELECT id FROM incident WHERE cause_status='undisclosed'
           AND (rechecked_at IS NULL OR rechecked_at < ?)""", (cutoff,))
    changed = 0
    with con:
        for r in rows:
            st = con.execute("""SELECT cause_status FROM statement WHERE incident_id=?
                AND cause_status != 'undisclosed' ORDER BY stated_at IS NULL, stated_at LIMIT 1""",
                (r["id"],)).fetchone()
            if st:
                con.execute("UPDATE incident SET cause_status=? WHERE id=?", (st[0], r["id"]))
                changed += 1
            con.execute("UPDATE incident SET rechecked_at=? WHERE id=?", (db.utcnow(), r["id"]))
    return {"rechecked": len(rows), "changed": changed}


def logged_today(con, today):
    row = con.execute("SELECT bytes FROM trend_write_log WHERE day=?", (today,)).fetchone()
    return row[0] if row else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Incident trends worker")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--source", choices=sorted(collectors.SOURCES))
    ap.add_argument("--no-model", action="store_true")
    ap.add_argument("--rollup", action="store_true")
    args = ap.parse_args(argv)
    now = dt.datetime.now(dt.timezone.utc)
    today = now.date().isoformat()
    start_bytes = written_bytes()

    if args.dry_run:
        con = db.connect_ro() if os.path.exists(db.DB_PATH) else None
        if con is not None and not db.table_exists(con, "trend_fetch_state"):
            con.close()
            con = None
        print(f"seed rows: {seed.plan()}")
        names = [args.source] if args.source else list(collectors.SOURCES)
        for name in names:
            try:
                print(collect(con, name, collectors.SOURCES[name], False, True))
            except (fetch.FetchError, ValueError) as exc:
                print({"source": name, "error": str(exc)})
        print(f"bytes written: {written_bytes() - start_bytes}")
        return 0

    held = lock()
    con = db.connect_rw()
    migrate(con)
    if logged_today(con, today) >= DAILY_WRITE_CAP:
        print(f"write budget for {today} is spent, skipping collection")
        return 0

    if meta(con, "seed_hash") != seed.files_hash():
        with con:
            print(f"seed: {seed.load(con)} incidents from the seed")

    use_model = not args.no_model and classify.model_available()
    names = [args.source] if args.source else [
        n for n, s in collectors.SOURCES.items() if due(con, n, s["every_hours"], now)]
    failed = 0
    for name in names:
        try:
            print(collect(con, name, collectors.SOURCES[name], use_model, False))
        except (fetch.FetchError, ValueError) as exc:
            failed += 1
            print({"source": name, "error": str(exc)})
            with con:
                fetch.save_state(con, name, "error")

    print(recheck(con, now))
    built = meta(con, "built_at")
    stale = not built or now - dt.datetime.strptime(built, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc) >= dt.timedelta(hours=23)
    if args.rollup or stale:
        with con:
            print({"rollup": rollup.rebuild(con, today)})

    used = written_bytes() - start_bytes
    with con:
        con.execute("INSERT INTO trend_write_log(day, bytes) VALUES(?,?) "
                    "ON CONFLICT(day) DO UPDATE SET bytes = bytes + excluded.bytes", (today, used))
    print(f"bytes written: {used}")
    con.close()
    held.close()
    # A failed source is reported in its state row and the log; the run as a
    # whole still succeeded if anything else did.
    return 1 if names and failed == len(names) else 0


if __name__ == "__main__":
    sys.exit(main())
