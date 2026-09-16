"""SQLite helpers shared by the insights analytics modules.

Read paths open the database read-only (same convention as the dashboard and
chat endpoints). Only the intel worker opens read-write.
"""

import datetime as dt
import os
import sqlite3

DB_PATH = os.environ.get("TR_DB", "/opt/threat-radar/data/radar.db")


def connect_ro(path: str = None) -> sqlite3.Connection:
    p = path or DB_PATH
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=15000")
    return con


def connect_rw(path: str = None) -> sqlite3.Connection:
    p = path or DB_PATH
    con = sqlite3.connect(p, timeout=120)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=120000")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def qall(con, sql, params=()):
    return [dict(r) for r in con.execute(sql, params).fetchall()]


def qone(con, sql, params=()):
    r = con.execute(sql, params).fetchone()
    return dict(r) if r else None


def table_exists(con, name) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name=?", (name,)
    ).fetchone()
    return row is not None


class TsExpr:
    """raw_events.ts is written by the ingest as ISO text, but older rows on
    some sensors landed as epoch floats. Sample one row and pick the matching
    SQL expressions instead of assuming."""

    def __init__(self, con):
        row = con.execute(
            "SELECT ts FROM v_events WHERE ts IS NOT NULL LIMIT 1"
        ).fetchone()
        sample = row[0] if row else ""
        self.epoch = isinstance(sample, (int, float))
        if self.epoch:
            self.hour = "strftime('%Y-%m-%dT%H', ts, 'unixepoch')"
            self.iso = "strftime('%Y-%m-%dT%H:%M:%SZ', ts, 'unixepoch')"
        else:
            self.hour = "substr(ts,1,13)"
            self.iso = "ts"
        self.day = self.day_of("ts")

    def day_of(self, expr: str = "ts") -> str:
        if self.epoch:
            return f"strftime('%Y-%m-%d', {expr}, 'unixepoch')"
        return f"substr({expr},1,10)"

    def cutoff(self, days: int):
        t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=int(days))
        if self.epoch:
            return t.timestamp()
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    def day_range(self, day: str, span_days: int = 1):
        """Half-open [lo, hi) bounds for a YYYY-MM-DD day.

        The ISO form deliberately compares against the bare date string:
        '2026-08-04T00:00:00.123Z' sorts before '2026-08-04T00:00:00Z' because
        '.' is below 'Z' in ASCII, so a full timestamp bound would silently
        drop events in the first fraction of a second of the day.
        """
        start = dt.date.fromisoformat(day)
        end = start + dt.timedelta(days=int(span_days))
        if self.epoch:
            to_ts = lambda d: dt.datetime(
                d.year, d.month, d.day, tzinfo=dt.timezone.utc
            ).timestamp()
            return to_ts(start), to_ts(end)
        return start.isoformat(), end.isoformat()


def source_columns(con) -> dict:
    """The sources table has grown over time and column names differ between
    the original enrichment and the current one. Resolve them at runtime."""
    cols = [r[1] for r in con.execute("PRAGMA table_info(sources)").fetchall()]
    lower = {c.lower(): c for c in cols}

    def pick(*cands):
        for c in cands:
            if c in lower:
                return lower[c]
        return None

    return {
        "columns": cols,
        "ip": pick("src_ip", "ip", "address", "ip_addr"),
        "asn": pick("asn", "as_number", "asn_number", "as", "autonomous_system"),
        "org": pick("as_org", "asn_org", "as_name", "asn_name", "org", "isp", "organization"),
        "country": pick("country", "country_code", "cc", "country_name"),
        "city": pick("city"),
    }


def asn_label_sql(sc: dict) -> str:
    """SQL fragment producing a stable ASN label, e.g. 'AS214902'."""
    asn = sc.get("asn")
    if not asn:
        return "'unknown'"
    return (
        f"CASE WHEN s.{asn} IS NULL OR s.{asn}='' THEN 'unknown' "
        f"WHEN s.{asn} LIKE 'AS%' THEN s.{asn} "
        f"ELSE 'AS' || s.{asn} END"
    )


def clamp_days(days, default=30, lo=1, hi=3650) -> int:
    try:
        d = int(days)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, d))


def get_state(con, key, default=None):
    if not table_exists(con, "insights_state"):
        return default
    row = con.execute("SELECT value FROM insights_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_state(con, key, value):
    con.execute(
        "INSERT INTO insights_state(key,value,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, str(value), utcnow()),
    )


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
