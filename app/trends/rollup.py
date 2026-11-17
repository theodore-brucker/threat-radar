"""Weekly tables for the trends page, rebuilt whole once a day.

Weeks start on Monday. The week holding today is marked partial and left out
of the trend line, because a count that is still growing would pull the line
down. The trend is an ordinary least-squares fit of weekly count on week
number.
"""

import datetime as dt
import json

from app.analytics import db

COUNTED = ("org", "vendor")
CLUSTER_MIN = 3
CLUSTER_DAYS = 5


def week_of(day):
    d = dt.date.fromisoformat(day[:10])
    return (d - dt.timedelta(days=d.weekday())).isoformat()


def least_squares(ys):
    """Slope and intercept of y on x = 0..n-1. None when n < 2."""
    n = len(ys)
    if n < 2:
        return None
    mx = (n - 1) / 2
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in range(n))
    sxy = sum((x - mx) * (y - my) for x, y in enumerate(ys))
    slope = sxy / sxx
    return slope, my - slope * mx


def weekly(rows, today):
    """rows: dicts with id, started, cause_status. Answer one dict per week
    from the first week to the current one, empty weeks included."""
    if not rows:
        return [], None
    by = {}
    for r in rows:
        by.setdefault(week_of(r["started"]), []).append(r)
    first = dt.date.fromisoformat(min(by))
    last = dt.date.fromisoformat(max(max(by), week_of(today)))
    out, cur = [], first
    while cur <= last:
        k = cur.isoformat()
        rs = by.get(k, [])
        out.append({
            "week": k,
            "incidents": len(rs),
            "malicious": sum(r["cause_status"] == "malicious" for r in rs),
            "undisclosed": sum(r["cause_status"] == "undisclosed" for r in rs),
            "nonmalicious": sum(r["cause_status"] == "nonmalicious" for r in rs),
            "partial": int(k == week_of(today)),
            "ids": sorted(r["id"] for r in rs),
            "undisclosed_ids": sorted(r["id"] for r in rs if r["cause_status"] == "undisclosed"),
        })
        cur += dt.timedelta(days=7)
    full = [w["incidents"] for w in out if not w["partial"]]
    fit = least_squares(full)
    for i, w in enumerate(out):
        w["fitted"] = round(fit[1] + fit[0] * i, 3) if fit else None
    return out, fit


def clusters(outages, need=CLUSTER_MIN, days=CLUSTER_DAYS):
    """Windows of `days` days holding `need` or more national outages. Each
    window starts on an outage day; overlapping windows merge into one."""
    pts = sorted((dt.date.fromisoformat(o["started"][:10]), o["id"]) for o in outages)
    found = []
    for i, (start, _) in enumerate(pts):
        inside = [p for p in pts[i:] if (p[0] - start).days < days]
        if len(inside) >= need:
            found.append((start, inside[-1][0], [p[1] for p in inside]))
    merged = []
    for start, end, ids in found:
        if merged and start <= merged[-1][1]:
            m = merged[-1]
            merged[-1] = (m[0], max(m[1], end), sorted(set(m[2]) | set(ids)))
        else:
            merged.append((start, end, sorted(ids)))
    return [{"first_day": s.isoformat(), "last_day": e.isoformat(), "outages": len(ids), "ids": ids}
            for s, e, ids in merged]


def cause_delays(con):
    rows = db.qall(con, """
        SELECT i.id, i.started, MIN(s.stated_at) AS first_at,
               (SELECT s2.cause_status FROM statement s2
                 WHERE s2.incident_id = i.id AND s2.cause_status != 'undisclosed'
                   AND s2.stated_at IS NOT NULL ORDER BY s2.stated_at LIMIT 1) AS status
          FROM incident i JOIN statement s ON s.incident_id = i.id
         WHERE s.cause_status != 'undisclosed' AND s.stated_at IS NOT NULL
         GROUP BY i.id""")
    out = []
    for r in rows:
        days = (dt.date.fromisoformat(r["first_at"][:10]) - dt.date.fromisoformat(r["started"][:10])).days
        out.append({"incident_id": r["id"], "started": r["started"], "first_cause_at": r["first_at"],
                    "days": max(days, 0), "cause_status": r["status"]})
    return out


def fanouts(con):
    rows = db.qall(con, """
        SELECT iv.incident_id, iv.vendor_id, i.started, iv.customers
          FROM incident_vendor iv JOIN incident i ON i.id = iv.incident_id
         WHERE iv.role = 'supplier'""")
    for r in rows:
        linked = [x["incident_id"] for x in db.qall(con, """
            SELECT iv.incident_id FROM incident_vendor iv JOIN incident i ON i.id = iv.incident_id
             WHERE iv.vendor_id = ? AND abs(julianday(i.started) - julianday(?)) <= 7""",
            (r["vendor_id"], r["started"]))]
        r["linked"] = len(linked)
        r["ids"] = sorted(set(linked))
    return rows


def rebuild(con, today=None):
    today = today or dt.date.today().isoformat()
    counted = db.qall(con, "SELECT id, started, cause_status FROM incident "
                           "WHERE kind IN ('org','vendor') AND started <= ?", (today,))
    weeks, fit = weekly(counted, today)
    national = db.qall(con, "SELECT id, started FROM incident WHERE kind='national'")
    delays = cause_delays(con)
    fans = fanouts(con)
    groups = clusters(national)

    con.execute("DELETE FROM trend_weekly")
    con.executemany(
        "INSERT INTO trend_weekly(week, incidents, malicious, undisclosed, nonmalicious, fitted, "
        "partial, ids, undisclosed_ids) VALUES(?,?,?,?,?,?,?,?,?)",
        [(w["week"], w["incidents"], w["malicious"], w["undisclosed"], w["nonmalicious"],
          w["fitted"], w["partial"], json.dumps(w["ids"]), json.dumps(w["undisclosed_ids"]))
         for w in weeks])
    con.execute("DELETE FROM trend_cause_delay")
    con.executemany(
        "INSERT INTO trend_cause_delay(incident_id, started, first_cause_at, days, cause_status) "
        "VALUES(?,?,?,?,?)",
        [(d["incident_id"], d["started"], d["first_cause_at"], d["days"], d["cause_status"])
         for d in delays])
    con.execute("DELETE FROM trend_fanout")
    con.executemany(
        "INSERT INTO trend_fanout(incident_id, vendor_id, started, customers, linked, ids) "
        "VALUES(?,?,?,?,?,?)",
        [(f["incident_id"], f["vendor_id"], f["started"], f["customers"], f["linked"],
          json.dumps(f["ids"])) for f in fans])
    con.execute("DELETE FROM trend_cluster")
    con.executemany("INSERT INTO trend_cluster(first_day, last_day, outages, ids) VALUES(?,?,?,?)",
                    [(c["first_day"], c["last_day"], c["outages"], json.dumps(c["ids"])) for c in groups])
    meta = {"slope": fit[0] if fit else None, "intercept": fit[1] if fit else None,
            "built_at": db.utcnow(), "built_for": today}
    for k, v in meta.items():
        con.execute("INSERT INTO trend_meta(key, value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (k, None if v is None else str(v)))
    return {"weeks": len(weeks), "delays": len(delays), "fanouts": len(fans), "clusters": len(groups)}
