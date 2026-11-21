"""Figures for the overview's Summary mode.

A non-specialist needs to know whether a number went up or down and by how
much, which a total does not say. Everything here turns a fact table into a
change against the prior period, with outage days removed from both sides of
the comparison.
"""

from . import db
from . import outages
from . import persona

FIELDS = ("connections", "authenticated", "shell", "transferred", "captured")


def _day_list(con, days, offset=0):
    """The N days ending `offset` periods back, minus known outage days."""
    ts = db.TsExpr(con)
    end = ts.cutoff_day(offset * days)
    start = ts.cutoff_day((offset + 1) * days)
    rows = db.qall(
        con,
        "SELECT DISTINCT day FROM asn_ip_daily WHERE day >= ? AND day < ? ORDER BY day",
        (start, end),
    )
    return [r["day"] for r in rows]


def _measure(con, day_list, field):
    """Count one funnel measure across an explicit day list."""
    days = [d for d in day_list if d not in outages.excluded_days(con, field)]
    if not days:
        return None, 0
    marks = ",".join("?" for _ in days)
    if field == "connections":
        row = db.qone(
            con,
            f"SELECT COUNT(*) n FROM session_facts WHERE day IN ({marks})",
            tuple(days),
        )
    elif field == "authenticated":
        row = db.qone(
            con,
            f"SELECT SUM(authed > 0) n FROM session_facts WHERE day IN ({marks})",
            tuple(days),
        )
    elif field == "shell":
        row = db.qone(
            con,
            f"SELECT SUM(commands > 0) n FROM session_facts WHERE day IN ({marks})",
            tuple(days),
        )
    elif field == "transferred":
        row = db.qone(
            con,
            f"SELECT SUM(downloads > 0 OR uploads > 0) n FROM session_facts "
            f"WHERE day IN ({marks})",
            tuple(days),
        )
    else:  # captured
        lo, hi = min(days), max(days)
        row = db.qone(
            con,
            "SELECT COUNT(DISTINCT shasum) n FROM payloads "
            "WHERE shasum <> '' AND et_day(last_seen) BETWEEN ? AND ?",
            (lo, hi),
        )
    return (row or {}).get("n") or 0, len(days)


def trends(con, days=30):
    """Current window against the one before it, outage days removed."""
    days = db.clamp_days(days, default=30)
    now_days = _day_list(con, days, 0)
    prev_days = _day_list(con, days, 1)
    out = {}
    for field in FIELDS:
        cur, cur_n = _measure(con, now_days, field)
        prev, prev_n = _measure(con, prev_days, field)
        # Compare daily rates, not totals, when the two windows lost a
        # different number of days to the outage.
        change = None
        if cur is not None and prev not in (None, 0) and cur_n and prev_n:
            cur_rate = cur / cur_n
            prev_rate = prev / prev_n
            change = round(100.0 * (cur_rate - prev_rate) / prev_rate, 1)
        out[field] = {
            "current": cur,
            "previous": prev,
            "current_days": cur_n,
            "previous_days": prev_n,
            "change_pct": change,
            "direction": "flat" if change is None or abs(change) < 5
            else ("up" if change > 0 else "down"),
            "comparable": bool(cur_n and prev_n and abs(cur_n - prev_n) <= max(2, days // 10)),
        }
    out["window_days"] = days
    out["excluded_days"] = sorted(outages.excluded_days(con, "authenticated"))
    # A percentage across a persona change measures our own configuration
    # change, not attacker behaviour. Say so rather than printing it bare.
    out["persona_note"] = persona.comparability(con, now_days, prev_days)
    return out


def odds(con, days=30):
    """The funnel restated as odds, which is the form that survives a meeting."""
    days = db.clamp_days(days, default=30)
    ts = db.TsExpr(con)
    cut = ts.cutoff_day(days)
    row = db.qone(
        con,
        """
        SELECT COUNT(*) connections,
               SUM(authed > 0) authenticated,
               SUM(commands > 0) shell,
               SUM(downloads > 0 OR uploads > 0) transferred
        FROM session_facts WHERE day >= ?
        """,
        (cut,),
    ) or {}
    conn = row.get("connections") or 0

    def one_in(n):
        if not n or not conn:
            return None
        return max(1, round(conn / n))

    return {
        "connections": conn,
        "login": one_in(row.get("authenticated")),
        "shell": one_in(row.get("shell")),
        "malware": one_in(row.get("transferred")),
        "authenticated": row.get("authenticated") or 0,
        "shell_sessions": row.get("shell") or 0,
        "transferred_sessions": row.get("transferred") or 0,
    }


def concentration(con, days=30, top=3):
    """How much of the traffic comes from how few networks. The single most
    useful executive fact this sensor produces."""
    days = db.clamp_days(days, default=30)
    ts = db.TsExpr(con)
    cut = ts.cutoff_day(days)
    rows = db.qall(
        con,
        """
        SELECT COALESCE(NULLIF(asn,''),'unattributed') asn, MAX(org) org,
               MAX(country) country, SUM(events) events,
               COUNT(DISTINCT src_ip) ips
        FROM asn_ip_daily WHERE day >= ?
        GROUP BY 1 ORDER BY events DESC LIMIT ?
        """,
        (cut, int(top)),
    )
    total = (db.qone(
        con, "SELECT SUM(events) n FROM asn_ip_daily WHERE day >= ?", (cut,)
    ) or {}).get("n") or 1
    for r in rows:
        r["share_pct"] = round(100.0 * (r["events"] or 0) / total, 1)
    return {
        "total_events": total,
        "top": rows,
        "top_share_pct": round(sum(r["share_pct"] for r in rows), 1),
    }


def goals(con, days=30, top=6):
    """What the credential guessing was after, in plain names."""
    days = db.clamp_days(days, default=30)
    if not db.table_exists(con, "cred_pair_daily"):
        return []
    ts = db.TsExpr(con)
    cut = ts.cutoff_day(days)
    rows = db.qall(
        con,
        """
        SELECT t.tag, SUM(d.attempts) attempts
        FROM cred_pair_tags t
        JOIN cred_pair_daily d ON d.username = t.username AND d.password = t.password
        WHERE d.day >= ? AND t.tag NOT IN
              ('unclustered','user-as-pass','pass-contains-user','numeric-pass','empty-pass')
        GROUP BY 1 ORDER BY attempts DESC LIMIT ?
        """,
        (cut, int(top)),
    )
    total = sum(r["attempts"] or 0 for r in rows) or 1
    for r in rows:
        r["share_pct"] = round(100.0 * (r["attempts"] or 0) / total, 1)
    return rows
