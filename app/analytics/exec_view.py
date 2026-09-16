"""Executive framing.

Three things an executive needs that an analyst does not: a comparison, a
direction, and a sentence. Totals answer none of those. Everything here turns
a fact table into a period-over-period movement with the outage days removed
from both sides of the comparison.
"""

import datetime as dt

from . import db
from . import outages
from . import persona

FIELDS = ("connections", "authenticated", "shell", "transferred", "captured")


def _day_list(con, days, offset=0):
    """The N days ending `offset` periods back, minus known outage days."""
    ts = db.TsExpr(con)
    end = str(ts.cutoff(offset * days))[:10]
    start = str(ts.cutoff((offset + 1) * days))[:10]
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
            "WHERE shasum <> '' AND substr(last_seen,1,10) BETWEEN ? AND ?",
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
    cut = str(ts.cutoff(days))[:10]
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
    cut = str(ts.cutoff(days))[:10]
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
    """What the credential guessing was actually after, in plain names."""
    days = db.clamp_days(days, default=30)
    if not db.table_exists(con, "cred_pair_daily"):
        return []
    ts = db.TsExpr(con)
    cut = str(ts.cutoff(days))[:10]
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


STALE_WARN_DAYS = 1      # nothing today: could be a slow pull
STALE_FAULT_DAYS = 2     # nothing for two days: delivery is broken


def health(con):
    """Is the sensor actually working, and is what we are showing current?

    Two independent failures, and the site has to tell them apart:

      1. The sensor answers but authentication is dead. Connections keep
         arriving, so volume looks fine. This is the July 31 fault.
      2. Nothing is arriving at all. session_facts simply stops growing.

    The second one used to read as healthy. This function asked for the last
    three days *that had rows*, so if delivery stopped a month ago it fetched
    the three good days before the stop, found authentications in them, and
    reported "sensor healthy" over month-old data. The window is now the last
    three calendar days, so a gap shows up as zeros instead of not being
    looked at.
    """
    today = dt.datetime.now(dt.timezone.utc).date()
    window = [(today - dt.timedelta(days=i)).isoformat() for i in range(3)]

    rows = {
        r["day"]: r
        for r in db.qall(
            con,
            """
            SELECT day, COUNT(*) sessions, SUM(authed > 0) authed,
                   SUM(commands) commands
            FROM session_facts WHERE day >= ? GROUP BY day
            """,
            (window[-1],),
        )
    }
    # Days with no rows are real zeros, not missing data points.
    recent = [rows.get(d, {"day": d, "sessions": 0, "authed": 0, "commands": 0})
              for d in window]

    last_auth = db.qone(
        con,
        "SELECT MAX(day) day FROM session_facts WHERE authed > 0",
    ) or {}
    last_any = db.qone(con, "SELECT MAX(day) day FROM asn_ip_daily") or {}
    ever = db.qone(con, "SELECT COUNT(*) n FROM session_facts") or {}

    sessions_recent = sum(r["sessions"] or 0 for r in recent)
    authed_recent = sum(r["authed"] or 0 for r in recent)

    lag = None
    if last_any.get("day"):
        try:
            lag = (today - dt.date.fromisoformat(last_any["day"])).days
        except ValueError:
            lag = None

    status, message = "ok", "Sensor is receiving traffic and authentications."
    if not ever.get("n"):
        status, message = "fault", "No sessions recorded at all."
    elif lag is not None and lag >= STALE_FAULT_DAYS:
        status = "fault"
        message = (
            f"No events have arrived for {lag} days. The most recent data on "
            f"this site is from {last_any['day']}, so every figure here is "
            f"stale. Check log delivery from the sensor."
        )
    elif sessions_recent and authed_recent == 0:
        status = "fault"
        message = (
            "Connections are arriving but nothing has authenticated in the last "
            "three days. That is a sensor fault, not a quiet week. "
            f"Last successful authentication: {last_auth.get('day') or 'never'}."
        )
    elif lag is not None and lag >= STALE_WARN_DAYS:
        status = "warn"
        message = (
            f"Nothing has arrived since {last_any['day']}. That is normal for a "
            f"few hours after midnight UTC and a problem after that."
        )
    elif (db.get_state(con, "last_run") or "") < db.utcnow()[:10]:
        status, message = "warn", "The analytics worker has not run today."

    return {
        "status": status,
        "message": message,
        "last_event_day": last_any.get("day"),
        "last_auth_day": last_auth.get("day"),
        "lag_days": lag,
        "recent": recent,
        "outages": outages.spans_for_chart(con),
        "personas": persona.spans_for_chart(con),
        "persona_now": (persona.epoch_for(con, last_any.get("day")) or {}).get("name"),
    }
