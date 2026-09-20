"""Overview: the numbers the front page leads with.

Everything here reads fact tables, so the page that a visitor lands on never
waits on raw_events.
"""

from . import db
from . import escalation


def headline(con, days=30):
    days = db.clamp_days(days, default=30)
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]

    totals = db.qone(
        con,
        "SELECT SUM(events) events, COUNT(DISTINCT src_ip) sources, "
        "MIN(day) first_day, MAX(day) last_day FROM asn_ip_daily",
    ) or {}
    window = db.qone(
        con,
        "SELECT SUM(events) events, COUNT(DISTINCT src_ip) sources "
        "FROM asn_ip_daily WHERE day >= ?",
        (cut_day,),
    ) or {}
    last_day = totals.get("last_day")
    latest = db.qone(
        con,
        "SELECT SUM(events) events, COUNT(DISTINCT src_ip) sources "
        "FROM asn_ip_daily WHERE day = ?",
        (last_day,),
    ) or {}

    countries = 0
    sc = db.source_columns(con)
    if sc["country"]:
        countries = (db.qone(
            con,
            f"SELECT COUNT(DISTINCT {sc['country']}) n FROM sources "
            f"WHERE {sc['country']} IS NOT NULL AND {sc['country']} <> ''",
        ) or {}).get("n", 0)

    # Windowed sample counts, with lifetime kept alongside so the page can
    # label the two differently instead of showing one and implying the other.
    samples = db.qone(
        con,
        "SELECT COUNT(DISTINCT shasum) hashes, COUNT(DISTINCT url) urls, "
        "SUM(hits) transfers FROM payload_daily WHERE shasum <> '' AND day >= ?",
        (cut_day,),
    ) if db.table_exists(con, "payload_daily") else {}
    samples = samples or {}
    lifetime = db.qone(
        con,
        "SELECT COUNT(DISTINCT shasum) hashes, SUM(hits) transfers "
        "FROM payloads WHERE shasum <> ''",
    ) or {}

    flagged = 0
    if db.table_exists(con, "payload_intel") and db.table_exists(con, "payload_daily"):
        flagged = (db.qone(
            con,
            "SELECT COUNT(DISTINCT i.indicator) n FROM payload_intel i "
            "WHERE i.kind='sha256' AND i.verdict IN ('malicious','suspicious') "
            "AND i.indicator IN (SELECT shasum FROM payload_daily WHERE day >= ?)",
            (cut_day,),
        ) or {}).get("n", 0)

    submitted = 0
    if db.table_exists(con, "payload_submissions"):
        submitted = (db.qone(
            con,
            "SELECT COUNT(DISTINCT sha256) n FROM payload_submissions "
            # 'duplicate' means the service already had the file. Since
            # the worker records every known hash, counting it here would
            # report the whole capture set as contributed.
            "WHERE status = 'submitted' "
            "AND substr(submitted_at,1,10) >= ?",
            (cut_day,),
        ) or {}).get("n", 0)

    return {
        "window_days": days,
        "first_day": totals.get("first_day"),
        "last_day": last_day,
        "events_total": totals.get("events") or 0,
        "events_window": window.get("events") or 0,
        "events_last_day": latest.get("events") or 0,
        "sources_total": totals.get("sources") or 0,
        "sources_window": window.get("sources") or 0,
        "sources_last_day": latest.get("sources") or 0,
        "countries": countries,
        "unique_samples": samples.get("hashes") or 0,
        "unique_samples_lifetime": lifetime.get("hashes") or 0,
        "transfers_lifetime": lifetime.get("transfers") or 0,
        "distribution_urls": samples.get("urls") or 0,
        "transfers": samples.get("transfers") or 0,
        "flagged_samples": flagged,
        "submitted_samples": submitted,
    }


def activity(con, days=45):
    """Daily volume with the spike flags already attached."""
    days = db.clamp_days(days, default=45, hi=365)
    rows = db.qall(
        con,
        "SELECT day, SUM(events) events, COUNT(DISTINCT src_ip) sources "
        "FROM asn_ip_daily GROUP BY day ORDER BY day",
    )[-days:]
    notes = {}
    if db.table_exists(con, "spike_annotations"):
        notes = {
            r["day"]: {"headline": r["headline"], "ratio": r["ratio"]}
            for r in db.qall(con, "SELECT day, headline, ratio FROM spike_annotations")
        }
    for r in rows:
        r["spike"] = notes.get(r["day"])
    return rows


def notable_sessions(con, days=30, limit=12):
    """Sessions worth looking at, not the most recent ones.

    The old recent-sessions panel filled with the same two IPs opening empty
    connections. Rank by what the session actually did instead.
    """
    # At most two rows per source, so one busy address cannot fill the panel
    # the way the old recent-sessions list did.
    return db.qall(
        con,
        """
        WITH ranked AS (
          SELECT f.session, f.src_ip, f.username, f.first_seen, f.duration,
                 f.commands, f.downloads, f.uploads, f.tunnels,
                 (f.downloads + f.uploads) * 100 + f.tunnels * 10 + f.commands AS weight,
                 ROW_NUMBER() OVER (
                   PARTITION BY f.src_ip
                   ORDER BY (f.downloads + f.uploads) * 100 + f.tunnels * 10
                            + f.commands DESC, f.last_seen DESC
                 ) AS rn
          FROM session_facts f
          WHERE f.day >= :cut AND (f.commands > 0 OR f.downloads > 0
                 OR f.uploads > 0 OR f.tunnels > 0)
        )
        SELECT r.session, r.src_ip, r.username, r.first_seen, r.duration,
               r.commands, r.downloads, r.uploads, r.tunnels,
               s.stage, s.country, s.org
        FROM ranked r
        LEFT JOIN source_stage s ON s.src_ip = r.src_ip
        WHERE r.rn <= 2
        ORDER BY r.weight DESC, r.first_seen DESC
        LIMIT :lim
        """,
        {"cut": str(db.TsExpr(con).cutoff(db.clamp_days(days, default=30)))[:10],
         "lim": int(limit)},
    )
