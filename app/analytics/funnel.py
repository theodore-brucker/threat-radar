"""Session-to-command funnel.

Every stage is counted in sessions, not events, so the drop-off between
"authenticated" and "typed something" is visible. Sessions that authenticate
and then issue nothing are the interesting bucket: credential validation
harvesting, broken automation, or a client that only wanted a tunnel.
"""

from . import db

STAGES = [
    ("connected", "Connected"),
    ("attempted", "Tried credentials"),
    ("authed", "Authenticated"),
    ("commanded", "Issued a command"),
    ("transferred", "Moved a file"),
]


def funnel(con, days=30):
    days = db.clamp_days(days, default=30)
    if not db.table_exists(con, "session_facts"):
        return {"built": False}
    ts = db.TsExpr(con)
    cut_day = ts.cutoff(days)
    cut_day = (cut_day if isinstance(cut_day, str) else "")[:10] or "0000-00-00"

    row = db.qone(
        con,
        """
        SELECT COUNT(*)                                     AS sessions,
               SUM(attempted > 0)                           AS attempted,
               SUM(authed > 0)                              AS authed,
               SUM(commands > 0)                            AS commanded,
               SUM(downloads > 0 OR uploads > 0)            AS transferred,
               SUM(tunnels > 0)                             AS tunnelled,
               SUM(authed > 0 AND commands = 0)             AS silent_authed,
               SUM(authed > 0 AND commands = 0 AND tunnels > 0) AS silent_but_tunnelled,
               SUM(attempted > 0 AND authed = 0)            AS auth_failed_only,
               SUM(attempted = 0)                           AS no_auth_attempt,
               SUM(commands)                                AS total_commands,
               AVG(CASE WHEN authed > 0 THEN duration END)  AS avg_authed_duration
        FROM session_facts
        WHERE day >= ?
        """,
        (cut_day,),
    ) or {}

    total = row.get("sessions") or 0
    stages = []
    prev = None
    values = {
        "connected": total,
        "attempted": row.get("attempted") or 0,
        "authed": row.get("authed") or 0,
        "commanded": row.get("commanded") or 0,
        "transferred": row.get("transferred") or 0,
    }
    for key, label in STAGES:
        n = values[key]
        stages.append(
            {
                "stage": key,
                "label": label,
                "sessions": n,
                "pct_of_total": round(100.0 * n / total, 2) if total else 0.0,
                "drop_from_previous": (prev - n) if prev is not None else 0,
                "drop_pct": round(100.0 * (prev - n) / prev, 2) if prev else 0.0,
            }
        )
        prev = n

    silent = row.get("silent_authed") or 0
    authed = row.get("authed") or 1
    row["silent_pct_of_authed"] = round(100.0 * silent / authed, 2)
    return {
        "built": True,
        "window_days": days,
        "stages": stages,
        "totals": row,
    }


def silent_sessions(con, days=30, limit=100, offset=0):
    """Authenticated, zero commands. Enriched with ASN so a cluster shows up."""
    days = db.clamp_days(days, default=30)
    if not db.table_exists(con, "session_facts"):
        return {"built": False, "sessions": []}
    ts = db.TsExpr(con)
    cut_day = ts.cutoff(days)
    cut_day = (cut_day if isinstance(cut_day, str) else "")[:10] or "0000-00-00"

    rows = db.qall(
        con,
        """
        SELECT f.session, f.src_ip, f.username, f.first_seen, f.last_seen,
               f.duration, f.tunnels, f.client, f.day,
               d.asn, d.org, d.country
        FROM session_facts f
        LEFT JOIN asn_ip_daily d ON d.src_ip = f.src_ip AND d.day = f.day
        WHERE f.day >= ? AND f.authed > 0 AND f.commands = 0
        ORDER BY f.last_seen DESC
        LIMIT ? OFFSET ?
        """,
        (cut_day, limit, offset),
    )

    clusters = db.qall(
        con,
        """
        SELECT COALESCE(d.asn,'unknown') AS asn, MAX(d.org) AS org,
               COUNT(*) AS silent_sessions, COUNT(DISTINCT f.src_ip) AS src_ips,
               SUM(f.tunnels > 0) AS with_tunnel
        FROM session_facts f
        LEFT JOIN asn_ip_daily d ON d.src_ip = f.src_ip AND d.day = f.day
        WHERE f.day >= ? AND f.authed > 0 AND f.commands = 0
        GROUP BY 1
        ORDER BY silent_sessions DESC
        LIMIT 15
        """,
        (cut_day,),
    )

    usernames = db.qall(
        con,
        """
        SELECT COALESCE(username,'') AS username, COUNT(*) AS sessions
        FROM session_facts
        WHERE day >= ? AND authed > 0 AND commands = 0
        GROUP BY 1 ORDER BY sessions DESC LIMIT 15
        """,
        (cut_day,),
    )

    return {
        "built": True,
        "window_days": days,
        "sessions": rows,
        "clusters": clusters,
        "usernames": usernames,
    }


