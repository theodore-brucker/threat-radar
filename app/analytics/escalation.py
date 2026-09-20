"""Escalation: how far each source got, and the rail that frames the site.

The funnel is the narrative spine. Every source is reduced to the furthest
stage it reached, which is what colours the map and filters the tables.

  0 connected only     1 authenticated     2 reached a shell
  3 transferred a file 4 transferred confirmed malware
"""

from . import db

STAGES = [
    {"stage": 0, "key": "connected", "label": "Connected", "unit": "sessions"},
    {"stage": 1, "key": "authenticated", "label": "Authenticated", "unit": "sessions"},
    {"stage": 2, "key": "shell", "label": "Reached a shell", "unit": "sessions"},
    {"stage": 3, "key": "transferred", "label": "Moved a file", "unit": "sessions"},
    {"stage": 4, "key": "captured", "label": "Samples captured", "unit": "samples"},
    {"stage": 5, "key": "submitted", "label": "Submitted upstream", "unit": "samples"},
]


def rail(con, days=30):
    """Counts for each stage of the escalation rail.

    Stages 0 to 3 are session counts. Stages 4 and 5 switch to unique samples,
    which is called out in the unit field so the page can label it honestly
    rather than implying one continuous measure.
    """
    days = db.clamp_days(days, default=30)
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]

    row = db.qone(
        con,
        """
        SELECT COUNT(*)                          AS connected,
               SUM(authed > 0)                   AS authenticated,
               SUM(commands > 0)                 AS shell,
               SUM(downloads > 0 OR uploads > 0) AS transferred
        FROM session_facts WHERE day >= ?
        """,
        (cut_day,),
    ) or {}

    captured = (db.qone(
        con,
        "SELECT COUNT(DISTINCT shasum) n FROM payloads "
        "WHERE shasum <> '' AND last_seen >= ?",
        (cut_day,),
    ) or {}).get("n", 0)

    submitted = 0
    if db.table_exists(con, "payload_submissions"):
        submitted = (db.qone(
            con,
            "SELECT COUNT(DISTINCT sha256) n FROM payload_submissions "
            # Only real uploads. 'duplicate' rows now exist for every hash a
            # service already held and would swamp this stage.
            "WHERE status = 'submitted' AND substr(submitted_at,1,10) >= ?",
            (cut_day,),
        ) or {}).get("n", 0)

    values = {
        "connected": row.get("connected") or 0,
        "authenticated": row.get("authenticated") or 0,
        "shell": row.get("shell") or 0,
        "transferred": row.get("transferred") or 0,
        "captured": captured,
        "submitted": submitted,
    }

    out, prev = [], None
    for s in STAGES:
        n = values[s["key"]]
        step = dict(s)
        step["count"] = n
        if prev is not None and prev.get("unit") == s["unit"]:
            step["drop"] = max(0, prev["count"] - n)
            step["retained_pct"] = round(100.0 * n / prev["count"], 2) if prev["count"] else 0.0
        else:
            step["drop"] = None
            step["retained_pct"] = None
        out.append(step)
        prev = step
    return {"window_days": days, "stages": out}


def map_points(con, days=30, limit=60, min_stage=0):
    """Points for the escalation map, scoped to the window.

    Ranked by how far each source got rather than by raw volume, so the
    interesting handful always survives the cut. Coordinates and attribution
    come from the lifetime table; every count comes from the daily one.
    """
    if not db.table_exists(con, "source_stage_daily"):
        return []
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]
    return db.qall(
        con,
        """
        SELECT d.src_ip,
               MAX(d.stage)     AS stage,
               SUM(d.sessions)  AS sessions,
               SUM(d.commands)  AS commands,
               SUM(d.transfers) AS transfers,
               MAX(d.day)       AS last_seen,
               COALESCE(SUM(a.events), 0) AS events,
               s.malicious, s.asn, s.org, s.country, s.lat, s.lon
        FROM source_stage_daily d
        JOIN source_stage s ON s.src_ip = d.src_ip
        LEFT JOIN asn_ip_daily a ON a.src_ip = d.src_ip AND a.day = d.day
        WHERE d.day >= ? AND s.lat IS NOT NULL AND s.lon IS NOT NULL
        GROUP BY d.src_ip
        HAVING MAX(d.stage) >= ?
        ORDER BY stage DESC, sessions DESC
        LIMIT ?
        """,
        (cut_day, int(min_stage), max(5, min(500, int(limit)))),
    )


def stage_totals(con, days=30):
    """How many sources sit at each stage inside the window. Feeds the legend."""
    if not db.table_exists(con, "source_stage_daily"):
        return []
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]
    return db.qall(
        con,
        """
        SELECT stage, COUNT(*) sources, SUM(sessions) sessions FROM (
          SELECT src_ip, MAX(stage) stage, SUM(sessions) sessions
          FROM source_stage_daily WHERE day >= ? GROUP BY src_ip)
        GROUP BY stage ORDER BY stage
        """,
        (cut_day,),
    )


def sources(con, days=30, min_stage=0, limit=100, offset=0):
    """Sources with counts scoped to the window rather than lifetime totals."""
    if not db.table_exists(con, "source_stage_daily"):
        return []
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]
    return db.qall(
        con,
        """
        SELECT d.src_ip,
               MAX(d.stage)     AS stage,
               SUM(d.sessions)  AS sessions,
               SUM(d.commands)  AS commands,
               SUM(d.transfers) AS transfers,
               MIN(d.day)       AS first_seen,
               MAX(d.day)       AS last_seen,
               COALESCE(SUM(a.events), 0) AS events,
               s.malicious, s.asn, s.org, s.country
        FROM source_stage_daily d
        LEFT JOIN source_stage s ON s.src_ip = d.src_ip
        LEFT JOIN asn_ip_daily a ON a.src_ip = d.src_ip AND a.day = d.day
        WHERE d.day >= ?
        GROUP BY d.src_ip
        HAVING MAX(d.stage) >= ?
        ORDER BY stage DESC, events DESC
        LIMIT ? OFFSET ?
        """,
        (cut_day, int(min_stage), int(limit), int(offset)),
    )


def source_detail(con, ip):
    row = db.qone(con, "SELECT * FROM source_stage WHERE src_ip = ?", (ip,))
    sessions = db.qall(
        con,
        "SELECT session, first_seen, last_seen, username, commands, downloads, "
        "uploads, tunnels, duration FROM session_facts WHERE src_ip = ? "
        "ORDER BY last_seen DESC LIMIT 25",
        (ip,),
    )
    commands = db.qall(
        con,
        "SELECT ts, json_extract(payload,'$.input') cmd FROM v_events "
        "WHERE src_ip = ? AND eventid = 'cowrie.command.input' "
        "ORDER BY ts DESC LIMIT 50",
        (ip,),
    )
    payloads = db.qall(
        con,
        "SELECT DISTINCT s.shasum, s.url, s.direction FROM payload_sightings s "
        "WHERE s.src_ip = ? LIMIT 25",
        (ip,),
    )
    return {"source": row, "sessions": sessions, "commands": commands, "payloads": payloads}


# --------------------------------------------------------------------------
# build side (worker, read-write connection)
# --------------------------------------------------------------------------

def rebuild(con):
    """Collapse session_facts, payloads and reputation into one row per
    source. Cheap enough to redo in full on every pass."""
    sc = db.source_columns(con)
    con.execute("DELETE FROM source_stage")

    malicious_hashes = set()
    if db.table_exists(con, "payload_intel"):
        malicious_hashes = {
            r["indicator"]
            for r in db.qall(
                con,
                "SELECT indicator FROM payload_intel "
                "WHERE kind='sha256' AND verdict IN ('malicious','suspicious')",
            )
        }
    bad_ips = set()
    if malicious_hashes:
        marks = ",".join("?" for _ in malicious_hashes)
        bad_ips = {
            r["src_ip"]
            for r in db.qall(
                con,
                f"SELECT DISTINCT src_ip FROM payload_sightings WHERE shasum IN ({marks})",
                tuple(malicious_hashes),
            )
            if r["src_ip"]
        }

    rows = db.qall(
        con,
        """
        SELECT f.src_ip,
               COUNT(*)                              AS sessions,
               SUM(f.commands)                       AS commands,
               SUM(f.downloads + f.uploads)          AS transfers,
               MAX(f.authed)                         AS authed,
               MIN(f.first_seen)                     AS first_seen,
               MAX(f.last_seen)                      AS last_seen
        FROM session_facts f
        WHERE f.src_ip IS NOT NULL AND f.src_ip <> ''
        GROUP BY f.src_ip
        """,
    )
    events = {
        r["src_ip"]: r["events"]
        for r in db.qall(
            con, "SELECT src_ip, SUM(events) events FROM asn_ip_daily GROUP BY src_ip"
        )
    }

    meta = {}
    if sc["ip"]:
        cols = [sc["ip"]]
        for k in ("asn", "org", "country"):
            if sc[k]:
                cols.append(sc[k])
        have = {c.lower() for c in sc["columns"]}
        for extra in ("lat", "lon"):
            if extra in have:
                cols.append(extra)
        meta = {
            r[sc["ip"]]: r
            for r in db.qall(con, f"SELECT {','.join(cols)} FROM sources")
        }

    for r in rows:
        ip = r["src_ip"]
        stage = 0
        if r["authed"]:
            stage = 1
        if (r["commands"] or 0) > 0:
            stage = 2
        if (r["transfers"] or 0) > 0:
            stage = 3
        if ip in bad_ips:
            stage = 4
        m = meta.get(ip, {})
        con.execute(
            """
            INSERT OR REPLACE INTO source_stage
              (src_ip, stage, sessions, events, commands, transfers, malicious,
               first_seen, last_seen, asn, org, country, lat, lon)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                ip,
                stage,
                r["sessions"],
                events.get(ip, 0),
                r["commands"] or 0,
                r["transfers"] or 0,
                1 if ip in bad_ips else 0,
                r["first_seen"],
                r["last_seen"],
                m.get(sc["asn"]) if sc["asn"] else None,
                m.get(sc["org"]) if sc["org"] else None,
                m.get(sc["country"]) if sc["country"] else None,
                m.get("lat"),
                m.get("lon"),
            ),
        )
    con.commit()
    return len(rows)


def rebuild_daily(con, backfill_all=False, recent_days=3):
    """Per-day escalation stage per source.

    The lifetime table answers "how far has this address ever got"; this one
    answers "how far did it get during the window I am looking at", which is
    what every list view and the map actually need.
    """
    ts = db.TsExpr(con)
    row = con.execute("SELECT MIN(day) lo, MAX(day) hi FROM session_facts").fetchone()
    if not row or not row[0]:
        return 0
    import datetime as dt

    lo = dt.date.fromisoformat(row[0])
    hi = dt.date.fromisoformat(row[1])
    days, cur = [], lo
    while cur <= hi:
        days.append(cur.isoformat())
        cur += dt.timedelta(days=1)
    if not backfill_all:
        have = {r[0] for r in con.execute("SELECT DISTINCT day FROM source_stage_daily")}
        days = sorted((set(days) - have) | set(days[-recent_days:]))
    if not days:
        return 0

    bad_ips = set()
    if db.table_exists(con, "payload_intel"):
        bad_ips = {
            r["src_ip"]
            for r in db.qall(
                con,
                """
                SELECT DISTINCT s.src_ip FROM payload_sightings s
                JOIN payload_intel i ON i.indicator = s.shasum
                WHERE i.kind = 'sha256' AND i.verdict IN ('malicious','suspicious')
                """,
            )
            if r["src_ip"]
        }

    for day in days:
        con.execute("DELETE FROM source_stage_daily WHERE day = ?", (day,))
        con.execute(
            """
            INSERT OR REPLACE INTO source_stage_daily
              (day, src_ip, stage, sessions, commands, transfers)
            SELECT ?, src_ip,
                   CASE WHEN SUM(downloads + uploads) > 0 THEN 3
                        WHEN SUM(commands) > 0 THEN 2
                        WHEN MAX(authed) > 0 THEN 1
                        ELSE 0 END,
                   COUNT(*), SUM(commands), SUM(downloads + uploads)
            FROM session_facts
            WHERE day = ? AND src_ip IS NOT NULL AND src_ip <> ''
            GROUP BY src_ip
            """,
            (day, day),
        )
        con.commit()

    if bad_ips:
        marks = ",".join("?" for _ in bad_ips)
        con.execute(
            f"UPDATE source_stage_daily SET stage = 4 "
            f"WHERE stage >= 3 AND src_ip IN ({marks})",
            tuple(bad_ips),
        )
        con.commit()
    return len(days)
