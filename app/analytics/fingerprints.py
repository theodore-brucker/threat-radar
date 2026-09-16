"""SSH client fingerprints.

The old /api/hassh read a view that aggregated json_extract over every row in
raw_events, which is why it timed out at 1.37M rows. Same output, built once
per day into client_fp_daily and read from there.
"""

from . import db

KEX_EVENT = "cowrie.client.kex"
VERSION_EVENT = "cowrie.client.version"

# hassh values common enough to be worth naming on sight.
#
# The important distinction, and the one the old flat map hid: a hassh is a
# hash of the client's algorithm offer, so it identifies the SSH *library*,
# not the tool built on it. Every Go program using x/crypto/ssh with default
# settings produces the same fingerprint, and roughly 15k sessions here from
# unrelated netblocks carry that one value. Presenting it beside a genuine
# toolmark implies a clustering value it does not have.
#
#   kind="library"  many unrelated tools share this; useless as a cluster key
#   kind="toolmark" specific enough that shared use suggests shared tooling
KNOWN = {
    "0df0d56bb50c6b2426d8d40234bf1826": {
        "label": "libssh default",
        "kind": "library",
        "note": "libssh's default offer. Common to many botnet families and "
                "to legitimate software; shared use implies nothing.",
    },
    "aae6b9604f6f3356543709a376d7f657": {
        "label": "OpenSSH 7.x client",
        "kind": "library",
        "note": "A stock OpenSSH client build. Shared by anyone who typed "
                "ssh on a machine of that vintage.",
    },
    "06046964c022c6407d15a27b12a6a4fb": {
        "label": "Go x/crypto/ssh default",
        "kind": "library",
        "note": "The Go SSH library's default algorithm offer. About 15k "
                "sessions here across unrelated netblocks carry it, so it is "
                "a language choice, not a toolmark. Do not cluster on it.",
    },
    "b12d2871a1189eff20364cf5333619ee": {
        "label": "paramiko",
        "kind": "library",
        "note": "Python's paramiko with default settings. Common to many "
                "unrelated scripts.",
    },
}


def describe(hassh):
    """What is known about a fingerprint, or None.

    Returns the record rather than a bare string so callers can tell a
    library default from a toolmark instead of printing both the same way.
    """
    return KNOWN.get((hassh or "").lower())


def known_label(hassh):
    """Just the display name, for callers that only need text."""
    rec = describe(hassh)
    return rec["label"] if rec else None


def overview(con, days=30, limit=25):
    days = db.clamp_days(days, default=30)
    if not db.table_exists(con, "client_fp_daily"):
        return {"built": False, "fingerprints": []}
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]

    rows = db.qall(
        con,
        """
        SELECT hassh,
               MAX(version)          AS version,
               SUM(events)           AS events,
               SUM(sessions)         AS sessions,
               MAX(src_ips)          AS peak_daily_ips,
               MIN(day)              AS first_day,
               MAX(day)              AS last_day,
               COUNT(*)              AS active_days
        FROM client_fp_daily
        WHERE day >= ?
        GROUP BY hassh
        ORDER BY events DESC
        LIMIT ?
        """,
        (cut_day, int(limit)),
    )
    total = sum(r["events"] or 0 for r in rows) or 1
    for r in rows:
        r["share_pct"] = round(100.0 * (r["events"] or 0) / total, 2)
        rec = describe(r["hassh"])
        r["known_as"] = rec["label"] if rec else None
        r["known_kind"] = rec["kind"] if rec else None
        r["known_note"] = rec["note"] if rec else None
    return {"built": True, "window_days": days, "fingerprints": rows}


def rebuild(con, backfill_all=False, recent_days=3):
    """Per-day fingerprint counts. hassh rides on the kex event; the banner
    string rides on the version event, so they are joined on session."""
    ts = db.TsExpr(con)
    days = _days_to_build(con, ts, backfill_all, recent_days)
    if not days:
        return 0

    sql = f"""
        INSERT OR REPLACE INTO client_fp_daily
          (day, hassh, version, events, sessions, src_ips)
        SELECT ?,
               k.hassh,
               MAX(v.version),
               COUNT(*),
               COUNT(DISTINCT k.session),
               COUNT(DISTINCT k.src_ip)
        FROM (
          SELECT session, src_ip,
                 COALESCE(json_extract(payload,'$.hassh'),
                          json_extract(payload,'$.hasshAlgorithms')) AS hassh
          FROM v_events
          WHERE eventid = '{KEX_EVENT}' AND ts >= ? AND ts < ?
        ) k
        LEFT JOIN (
          SELECT session, json_extract(payload,'$.version') AS version
          FROM v_events
          WHERE eventid = '{VERSION_EVENT}' AND ts >= ? AND ts < ?
        ) v ON v.session = k.session
        WHERE k.hassh IS NOT NULL AND k.hassh <> ''
        GROUP BY k.hassh
    """
    for day in days:
        lo, hi = ts.day_range(day)
        con.execute("DELETE FROM client_fp_daily WHERE day = ?", (day,))
        con.execute(sql, (day, lo, hi, lo, hi))
        con.commit()
    return len(days)


def _days_to_build(con, ts, backfill_all, recent_days):
    row = con.execute("SELECT MIN(ts) lo, MAX(ts) hi FROM v_events").fetchone()
    if not row or row[0] is None:
        return []
    import datetime as dt

    if ts.epoch:
        lo = dt.datetime.fromtimestamp(row[0], dt.timezone.utc).date()
        hi = dt.datetime.fromtimestamp(row[1], dt.timezone.utc).date()
    else:
        lo = dt.date.fromisoformat(str(row[0])[:10])
        hi = dt.date.fromisoformat(str(row[1])[:10])
    days, cur = [], lo
    while cur <= hi:
        days.append(cur.isoformat())
        cur += dt.timedelta(days=1)
    if backfill_all:
        return days
    have = {r[0] for r in con.execute("SELECT DISTINCT day FROM client_fp_daily")}
    return sorted((set(days) - have) | set(days[-recent_days:]))
