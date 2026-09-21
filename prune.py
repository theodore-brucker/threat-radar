#!/usr/bin/env python3
"""Threat Radar retention pruner.

Retention is decided by age, and storage is watched rather than enforced:

  1. AGE      drop raw_events older than TR_RETAIN_DAYS.
  2. STORAGE  report, never delete, when the database exceeds TR_MAX_DB_MB
              or the disk lacks room for a VACUUM. The report lands in
              insights_state where the health view shows it.
  3. ROLLUPS  drop per-day fact rows older than TR_ROLLUP_RETAIN_DAYS, which
              the unit sets far enough out to mean "keep".

The storage step used to delete the oldest raw events until the database fit.
That was a safety net when the per-day tables were small, and a quiet threat
to the retention decision once they were kept indefinitely: every megabyte
they grew would have come out of the raw window, with nothing reporting it.

The per-day fact tables outlive the events they were built from, and that is
the point: they are the only reason a window wider than TR_RETAIN_DAYS shows
anything at all. Pruning them on the raw boundary would silently reduce "all
time" to one month.

Aggregate counters in `sources` are deliberately NOT deleted with the raw
events, so long-run totals and first_seen survive pruning. Sources whose
events are all gone AND that haven't been seen within the retention window
are dropped too, to stop unbounded growth of that table.

Spool files and their ingest_state rows are pruned on the same schedule.

Run from a systemd timer. Safe to run repeatedly.
"""
import glob
import os
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone

BASE = os.environ.get("TR_BASE", "/opt/threat-radar")
DB = os.path.join(BASE, "data", "radar.db")
SPOOL = os.path.join(BASE, "spool")

RETAIN_DAYS = int(os.environ.get("TR_RETAIN_DAYS", "30"))
MAX_DB_MB = int(os.environ.get("TR_MAX_DB_MB", "2048"))
SPOOL_RETAIN_DAYS = int(os.environ.get("TR_SPOOL_RETAIN_DAYS", "3"))
# Per-day fact tables. Long by design (see the module docstring): these carry
# the history that raw_events no longer holds, so this is the real limit on
# how far back the site can look.
ROLLUP_RETAIN_DAYS = int(os.environ.get("TR_ROLLUP_RETAIN_DAYS", "365"))
BATCH = 20000
# Never let the size cap empty the database entirely; if the cap is set
# smaller than this many events occupy, stop and warn instead.


def log(msg: str) -> None:
    print(f"[prune] {msg}", flush=True)


def db_size_mb(conn, used_only: bool = False) -> float:
    """Database size in MB.

    used_only=True subtracts freelist pages. DELETE does not shrink
    page_count (freed pages are only returned to the OS by VACUUM), so the
    size-cap loop MUST measure used pages or it never observes progress and
    deletes every row in the table.
    """
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    if used_only:
        pages -= conn.execute("PRAGMA freelist_count").fetchone()[0]
    return pages * page_size / (1024 * 1024)


def prune_by_age(conn) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETAIN_DAYS)).isoformat()
    total = 0
    while True:
        cur = conn.execute(
            "DELETE FROM raw_events WHERE id IN ("
            "  SELECT id FROM raw_events WHERE ts < ? LIMIT ?)",
            (cutoff, BATCH),
        )
        conn.commit()
        if not cur.rowcount:
            break
        total += cur.rowcount
    if total:
        log(f"age: removed {total} events older than {RETAIN_DAYS}d")
    return total


def check_storage(conn) -> int:
    """Report when the database outgrows its cap, without shortening retention.

    This used to enforce TR_MAX_DB_MB by deleting the oldest raw events until
    the database fit. Raw events are the only table it could delete from, and
    the per-day tables are kept indefinitely, so as they grew the cap would
    have eaten into the thirty days of raw events an hour at a time and said
    nothing. Raw retention is the age cap's decision alone now. When the
    database is over its cap, or the disk no longer has room for a VACUUM,
    that is recorded where the health view reads it and stays visible until
    someone decides what to change.

    Returns 0, because nothing is deleted here. It keeps the shape of the
    other prune steps so main() reads the same.
    """
    used = db_size_mb(conn, used_only=True)
    free_disk = shutil.disk_usage(os.path.dirname(os.path.abspath(DB))).free / (1024 * 1024)

    problems = []
    if used > MAX_DB_MB:
        problems.append(
            f"The database is {used:.0f} MB against a {MAX_DB_MB} MB cap. Raw "
            f"events are still kept for {RETAIN_DAYS} days; decide whether to "
            f"raise TR_MAX_DB_MB or trim what the rollups keep."
        )
    # VACUUM writes a complete copy of the database, so it needs at least that
    # much free space plus headroom for the WAL it leaves behind.
    if free_disk < used * 2:
        problems.append(
            f"Only {free_disk:.0f} MB free on the data volume for a {used:.0f} MB "
            f"database, too little for VACUUM to complete."
        )

    if problems:
        message = " ".join(problems)
        conn.execute(
            "INSERT INTO insights_state(key, value, updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
            "updated_at=excluded.updated_at",
            ("storage_status", message,
             datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        )
        log(f"storage: {message}")
    else:
        conn.execute("DELETE FROM insights_state WHERE key = 'storage_status'")
    conn.commit()
    return 0


def prune_sources(conn) -> int:
    """Drop source rows with no surviving events and no recent activity."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETAIN_DAYS)).isoformat()
    cur = conn.execute(
        "DELETE FROM sources WHERE last_seen < ?"
        " AND ip NOT IN (SELECT DISTINCT src_ip FROM raw_events WHERE src_ip != '')",
        (cutoff,),
    )
    conn.commit()
    if cur.rowcount:
        log(f"sources: removed {cur.rowcount} stale entries")
    return cur.rowcount


def prune_spool(conn) -> int:
    """Delete old spool files and their ingest_state rows."""
    cutoff = time.time() - (SPOOL_RETAIN_DAYS * 86400)
    removed = 0
    current = os.path.join(SPOOL, "cowrie.json")
    for path in glob.glob(os.path.join(SPOOL, "cowrie.json*")):
        if path == current:
            continue  # never delete the live file the puller writes
        try:
            if os.path.getmtime(path) < cutoff:
                name = os.path.basename(path)
                os.remove(path)
                conn.execute("DELETE FROM ingest_state WHERE filename = ?", (name,))
                removed += 1
        except OSError as e:
            log(f"spool: could not remove {path}: {e}")
    # Drop ingest_state rows whose files no longer exist
    for (name,) in conn.execute("SELECT filename FROM ingest_state").fetchall():
        if not os.path.exists(os.path.join(SPOOL, name)):
            conn.execute("DELETE FROM ingest_state WHERE filename = ?", (name,))
    conn.commit()
    if removed:
        log(f"spool: removed {removed} ingested files")
    return removed


def prune_rollups(conn) -> int:
    """Drop per-day fact rows past the rollup horizon.

    Every table here is keyed by a YYYY-MM-DD 'day' column, so the cutoff is
    a plain string comparison. Tables are skipped when absent rather than
    listed conditionally, so a database that predates a migration prunes
    cleanly instead of raising.

    session_facts is included even though it is keyed by session: it carries
    a 'day' column and is the largest of these tables by row count.
    """
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=ROLLUP_RETAIN_DAYS)).strftime("%Y-%m-%d")
    tables = (
        "asn_ip_daily", "eventid_daily", "session_facts", "tunnel_targets",
        "cred_pair_daily", "payload_daily", "source_stage_daily",
        "client_fp_daily", "cred_ip_daily", "hassh_ip_daily",
        "spike_annotations",
    )
    total = 0
    for t in tables:
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (t,)
        ).fetchone()
        if not exists:
            continue
        cur = conn.execute(f"DELETE FROM {t} WHERE day < ?", (cutoff,))
        if cur.rowcount > 0:
            total += cur.rowcount
    conn.commit()
    if total:
        log(f"rollups: removed {total} fact rows older than {ROLLUP_RETAIN_DAYS}d")
    return total


def main() -> int:
    if not os.path.exists(DB):
        log(f"no database at {DB}")
        return 0
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA busy_timeout=30000")
    before = db_size_mb(conn)

    dropped = prune_by_age(conn) + check_storage(conn)
    prune_sources(conn)
    prune_spool(conn)
    dropped += prune_rollups(conn)

    if dropped:
        # VACUUM rewrites the whole DB through the WAL, so on a ~2GB database it
        # costs ~6 min of exclusive access and leaves a WAL as large as the DB.
        # Running it hourly to reclaim ~8MB caused the ingest/enrich lock storms
        # and is why the WAL never shrank. Gate it on reclaimable space, and
        # TRUNCATE *after* the rewrite rather than before it.
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        free_mb = (conn.execute("PRAGMA freelist_count").fetchone()[0]
                   * page_size / (1024 * 1024))
        min_free = float(os.environ.get("TR_VACUUM_MIN_FREE_MB", "256"))
        if free_mb >= min_free:
            conn.execute("VACUUM")
            busy = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
            if busy:
                log("checkpoint blocked by an open reader; WAL not truncated")
            after = db_size_mb(conn)
            log(f"db {before:.1f}MB -> {after:.1f}MB (reclaimed {free_mb:.1f}MB)")
        else:
            busy = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
            log(f"db {before:.1f}MB, {free_mb:.1f}MB free below {min_free:.0f}MB "
                f"threshold, VACUUM skipped (checkpoint busy={busy})")
    else:
        log(f"nothing to prune (db {before:.1f}MB, cap {MAX_DB_MB}MB, "
            f"retain {RETAIN_DAYS}d)")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
