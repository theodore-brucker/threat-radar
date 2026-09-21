#!/usr/bin/env python3
"""Threat Radar ingester.

Scans the spool directory for Cowrie JSON logs pulled from the sensor,
parses new lines into SQLite. Idempotent two ways: per-file byte offsets,
plus a UNIQUE hash on every raw line, so re-pulls and offset resets never
duplicate data. All attacker-controlled fields are stored as data only
(parameterized SQL); rendering is escaped at the dashboard layer.
"""
import glob
import hashlib
import json
import os
import sqlite3
import time

BASE = os.environ.get("TR_BASE", "/opt/threat-radar")
DB = os.path.join(BASE, "data", "radar.db")
SPOOL = os.path.join(BASE, "spool")
INTERVAL = int(os.environ.get("TR_INGEST_INTERVAL", "30"))


def db_connect():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=300000")
    with open(os.path.join(BASE, "schema.sql")) as f:
        conn.executescript(f.read())
    return conn


def ingest_line(conn, line: str) -> None:
    line = line.strip()
    if not line:
        return
    h = hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()
    try:
        ev = json.loads(line)
        if not isinstance(ev, dict):
            raise ValueError("not an object")
    except (json.JSONDecodeError, ValueError):
        ev = {"eventid": "radar.unparsed"}
    eventid = str(ev.get("eventid", ""))[:128]
    session = str(ev.get("session", ""))[:64]
    src_ip = str(ev.get("src_ip", ""))[:64]
    ts = str(ev.get("timestamp", ""))[:40]
    cur = conn.execute(
        "INSERT OR IGNORE INTO raw_events (line_hash, eventid, session, src_ip, ts, payload)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (h, eventid, session, src_ip, ts, line),
    )
    if cur.rowcount and src_ip:
        conn.execute(
            "INSERT INTO sources (ip, first_seen, last_seen, event_count)"
            " VALUES (?, ?, ?, 1)"
            " ON CONFLICT(ip) DO UPDATE SET"
            "   last_seen = MAX(last_seen, excluded.last_seen),"
            "   first_seen = MIN(first_seen, excluded.first_seen),"
            "   event_count = event_count + 1",
            (src_ip, ts, ts),
        )


def process_file(conn, path: str) -> int:
    name = os.path.basename(path)
    row = conn.execute(
        "SELECT byte_offset FROM ingest_state WHERE filename = ?", (name,)
    ).fetchone()
    offset = row[0] if row else 0
    size = os.path.getsize(path)
    if size < offset:  # file rotated or re-pulled smaller: rescan (hash dedupes)
        offset = 0
    if size == offset:
        return 0
    n = 0
    # Bytes, not text. The offset has to track the file exactly, because the
    # pull appends raw bytes and the next pass resumes from here. Text mode
    # advanced by the re-encoded length of each decoded line, which overshoots
    # whenever a line holds an invalid byte, so the next pass started inside a
    # line and lost it. Decoding with "replace" afterwards keeps the line hash
    # identical to what text mode produced, so deduplication still matches.
    with open(path, "rb") as f:
        f.seek(offset)
        for raw in f:
            if not raw.endswith(b"\n"):
                break  # partial trailing line; pick it up next pass
            ingest_line(conn, raw.decode("utf-8", "replace"))
            offset += len(raw)
            n += 1
    conn.execute(
        "INSERT INTO ingest_state (filename, byte_offset) VALUES (?, ?)"
        " ON CONFLICT(filename) DO UPDATE SET byte_offset = excluded.byte_offset",
        (name, offset),
    )
    conn.commit()
    return n


def main():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    os.makedirs(SPOOL, exist_ok=True)
    conn = db_connect()
    print(f"[ingest] watching {SPOOL} -> {DB}", flush=True)
    while True:
        total = 0
        for path in sorted(glob.glob(os.path.join(SPOOL, "cowrie.json*"))):
            try:
                total += process_file(conn, path)
            except OSError as e:
                print(f"[ingest] error on {path}: {e}", flush=True)
        if total:
            print(f"[ingest] +{total} events", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
