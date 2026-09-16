"""Volume spike detection and attribution.

Detection uses a rolling median with median absolute deviation rather than a
mean and standard deviation, so a three-day surge does not inflate the
threshold that is supposed to catch it.

Attribution compares the spike day against the same 14-day baseline across
four dimensions (source IP, ASN, event type, username) and keeps the movers
that account for the surge. The result is stored, so a day only gets scored
once and the dashboard reads a label instead of recomputing.
"""

import json
import os
import statistics

from . import db

BASELINE_DAYS = int(os.environ.get("TR_SPIKE_BASELINE_DAYS", "14"))
MIN_BASELINE_DAYS = 5
Z_THRESHOLD = float(os.environ.get("TR_SPIKE_Z", "3.5"))
RATIO_THRESHOLD = float(os.environ.get("TR_SPIKE_RATIO", "1.75"))
MIN_EVENTS = int(os.environ.get("TR_SPIKE_MIN_EVENTS", "5000"))


def daily_counts(con, days=180):
    if db.table_exists(con, "asn_ip_daily"):
        rows = db.qall(
            con,
            "SELECT day, SUM(events) AS events, COUNT(DISTINCT src_ip) AS src_ips "
            "FROM asn_ip_daily GROUP BY day ORDER BY day",
        )
        if rows:
            return rows[-days:]
    ts = db.TsExpr(con)
    return db.qall(
        con,
        f"SELECT {ts.day} AS day, COUNT(*) AS events, "
        f"COUNT(DISTINCT src_ip) AS src_ips FROM v_events GROUP BY 1 ORDER BY 1",
    )[-days:]


def score_series(series):
    """Attach baseline, ratio and robust z-score to each day."""
    out = []
    for i, row in enumerate(series):
        window = [r["events"] for r in series[max(0, i - BASELINE_DAYS) : i]]
        rec = dict(row)
        if len(window) < MIN_BASELINE_DAYS:
            rec.update({"baseline": None, "ratio": None, "z": None, "spike": False})
            out.append(rec)
            continue
        med = statistics.median(window)
        mad = statistics.median([abs(x - med) for x in window]) or 1.0
        z = 0.6745 * (row["events"] - med) / mad
        ratio = (row["events"] / med) if med else None
        rec.update(
            {
                "baseline": round(med, 1),
                "ratio": round(ratio, 2) if ratio else None,
                "z": round(z, 2),
                "spike": bool(
                    z >= Z_THRESHOLD
                    and ratio
                    and ratio >= RATIO_THRESHOLD
                    and row["events"] >= MIN_EVENTS
                ),
            }
        )
        out.append(rec)
    return out


def timeline(con, days=90):
    days = db.clamp_days(days, default=90, hi=365)
    series = score_series(daily_counts(con))[-days:]
    notes = {}
    if db.table_exists(con, "spike_annotations"):
        for r in db.qall(con, "SELECT * FROM spike_annotations"):
            try:
                r["detail"] = json.loads(r["detail"] or "{}")
            except ValueError:
                r["detail"] = {}
            notes[r["day"]] = r
    for row in series:
        row["annotation"] = notes.get(row["day"])
    return {
        "window_days": days,
        "series": series,
        "annotations": sorted(
            notes.values(), key=lambda x: x["day"], reverse=True
        ),
    }


# --------------------------------------------------------------------------
# attribution (called by the intel worker, needs a read-write connection)
# --------------------------------------------------------------------------

def _movers(con, day, baseline_days, dimension):
    """Compare one day against the mean of the baseline days for a dimension."""
    if not baseline_days:
        return []
    marks = ",".join("?" for _ in baseline_days)
    n = len(baseline_days)

    if dimension == "src_ip":
        sql_day = "SELECT src_ip AS k, SUM(events) AS n FROM asn_ip_daily WHERE day=? GROUP BY 1"
        sql_base = (
            f"SELECT src_ip AS k, SUM(events)*1.0/{n} AS n FROM asn_ip_daily "
            f"WHERE day IN ({marks}) GROUP BY 1"
        )
    elif dimension == "asn":
        sql_day = (
            "SELECT COALESCE(NULLIF(asn,''),'unknown') AS k, SUM(events) AS n, MAX(org) AS org "
            "FROM asn_ip_daily WHERE day=? GROUP BY 1"
        )
        sql_base = (
            f"SELECT COALESCE(NULLIF(asn,''),'unknown') AS k, SUM(events)*1.0/{n} AS n "
            f"FROM asn_ip_daily WHERE day IN ({marks}) GROUP BY 1"
        )
    elif dimension == "eventid":
        sql_day = "SELECT eventid AS k, events AS n FROM eventid_daily WHERE day=?"
        sql_base = (
            f"SELECT eventid AS k, SUM(events)*1.0/{n} AS n FROM eventid_daily "
            f"WHERE day IN ({marks}) GROUP BY 1"
        )
    else:
        return []

    today = {r["k"]: r for r in db.qall(con, sql_day, (day,))}
    base = {r["k"]: r["n"] for r in db.qall(con, sql_base, tuple(baseline_days))}

    movers = []
    for k, r in today.items():
        b = base.get(k, 0.0)
        delta = (r["n"] or 0) - b
        if delta <= 0:
            continue
        movers.append(
            {
                "key": k,
                "org": r.get("org"),
                "events": r["n"],
                "baseline": round(b, 1),
                "delta": round(delta, 1),
                "new": b == 0.0,
            }
        )
    movers.sort(key=lambda x: x["delta"], reverse=True)
    return movers[:5]


def _usernames(con, day):
    ts = db.TsExpr(con)
    lo, hi = ts.day_range(day)
    return db.qall(
        con,
        """
        SELECT json_extract(payload,'$.username') AS key, COUNT(*) AS events
        FROM v_events
        WHERE eventid LIKE 'cowrie.login.%' AND ts >= ? AND ts < ?
        GROUP BY 1 ORDER BY events DESC LIMIT 5
        """,
        (lo, hi),
    )


def _outage_for(con, day):
    """Return the outage window covering this day, if any.

    A spike inside an auth outage is connect/close churn against a sensor that
    could not authenticate anyone. Attributing it to whichever ASN happened to
    scan hardest that day, as this module did for 2026-08-04 to 08-06, reads as
    escalation and is simply wrong.
    """
    try:
        return db.qone(
            con,
            "SELECT start_day, end_day, scope, reason FROM outage_windows "
            "WHERE ? >= start_day AND ? <= end_day LIMIT 1",
            (day, day),
        )
    except Exception:
        return None


def annotate(con, force=False, max_days=10):
    """Detect spikes and write attributions. Returns the days annotated."""
    series = score_series(daily_counts(con))
    spikes = [r for r in series if r.get("spike")]
    if not spikes:
        return []

    existing = {
        r["day"]: r
        for r in db.qall(con, "SELECT day, events FROM spike_annotations")
    }
    written = []
    for row in spikes[-max_days:]:
        day = row["day"]
        if not force and day in existing and existing[day]["events"] == row["events"]:
            continue
        idx = [r["day"] for r in series].index(day)
        baseline_days = [
            r["day"]
            for r in series[max(0, idx - BASELINE_DAYS) : idx]
            if not r.get("spike")
        ]
        detail = {
            "by_ip": _movers(con, day, baseline_days, "src_ip"),
            "by_asn": _movers(con, day, baseline_days, "asn"),
            "by_eventid": _movers(con, day, baseline_days, "eventid"),
            "by_username": _usernames(con, day),
            "baseline_days": baseline_days,
        }
        outage = _outage_for(con, day)
        if outage:
            detail["outage"] = outage
        headline = _headline(row, detail, outage)
        con.execute(
            """
            INSERT INTO spike_annotations(day, events, baseline, ratio, zscore,
                                          headline, detail, created_at)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(day) DO UPDATE SET
              events=excluded.events, baseline=excluded.baseline,
              ratio=excluded.ratio, zscore=excluded.zscore,
              headline=excluded.headline, detail=excluded.detail,
              created_at=excluded.created_at
            """,
            (
                day,
                row["events"],
                row["baseline"],
                row["ratio"],
                row["z"],
                headline,
                json.dumps(detail),
                db.utcnow(),
            ),
        )
        written.append(day)
    con.commit()
    return written


def _headline(row, detail, outage=None):
    surge = row["events"] - (row["baseline"] or 0)
    parts = [f"{row['events']:,} events, {row['ratio']}x the 14-day median"]
    if outage:
        parts.append(
            f"inside the {outage['start_day']} to {outage['end_day']} "
            f"{outage['scope']} outage, so this is connect and close churn "
            f"against a sensor that could not authenticate anyone, not escalation"
        )
        top_evt = (detail.get("by_eventid") or [None])[0]
        if top_evt:
            parts.append(f"driven by {top_evt['key']}")
        return "; ".join(parts)
    top_asn = (detail["by_asn"] or [None])[0]
    top_ip = (detail["by_ip"] or [None])[0]
    top_evt = (detail["by_eventid"] or [None])[0]
    if top_asn and surge > 0:
        share = 100.0 * top_asn["delta"] / surge
        org = f" ({top_asn['org']})" if top_asn.get("org") else ""
        parts.append(
            f"{top_asn['key']}{org} accounts for {share:.0f}% of the increase"
            + (", first seen this day" if top_asn["new"] else "")
        )
    if top_ip:
        parts.append(f"top address {top_ip['key']} at +{int(top_ip['delta']):,}")
    if top_evt:
        parts.append(f"driven by {top_evt['key']}")
    return "; ".join(parts)
