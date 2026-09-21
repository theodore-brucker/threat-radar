"""Payload and malware tracker.

Downloads and uploads are rolled up by hash and by URL, then joined against
the reputation cache so a captured stager shows its VirusTotal and URLhaus
standing without leaving the dashboard.
"""

from . import db

DOWNLOAD_EVENT = "cowrie.session.file_download"
UPLOAD_EVENT = "cowrie.session.file_upload"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _intel_map(con, indicators):
    if not indicators or not db.table_exists(con, "payload_intel"):
        return {}
    out = {}
    chunk = 400
    inds = list(indicators)
    for i in range(0, len(inds), chunk):
        part = inds[i : i + chunk]
        marks = ",".join("?" for _ in part)
        for r in db.qall(
            con,
            f"SELECT * FROM payload_intel WHERE indicator IN ({marks})",
            tuple(part),
        ):
            out.setdefault(r["indicator"], {})[r["source"]] = r
    return out


def summary(con, days=30):
    ts = db.TsExpr(con)
    cut = ts.cutoff(days)
    row = db.qone(
        con,
        """
        SELECT
          SUM(eventid = ?) AS downloads,
          SUM(eventid = ?) AS uploads,
          COUNT(DISTINCT CASE WHEN eventid IN (?, ?)
                THEN json_extract(payload,'$.shasum') END) AS distinct_hashes,
          COUNT(DISTINCT CASE WHEN eventid = ?
                THEN json_extract(payload,'$.url') END) AS distinct_urls,
          COUNT(DISTINCT CASE WHEN eventid IN (?, ?) THEN src_ip END) AS src_ips
        FROM v_events
        WHERE eventid IN (?, ?) AND ts >= ?
        """,
        (
            DOWNLOAD_EVENT, UPLOAD_EVENT, DOWNLOAD_EVENT, UPLOAD_EVENT,
            DOWNLOAD_EVENT, DOWNLOAD_EVENT, UPLOAD_EVENT,
            DOWNLOAD_EVENT, UPLOAD_EVENT, cut,
        ),
    ) or {}

    # Reputation verdicts are a property of the sample, but only count the
    # ones actually seen inside the window.
    flagged = 0
    if db.table_exists(con, "payload_intel") and db.table_exists(con, "payload_daily"):
        cut_day = str(ts.cutoff(days))[:10]
        flagged = (
            db.qone(
                con,
                """
                SELECT COUNT(DISTINCT i.indicator) AS n
                FROM payload_intel i
                WHERE i.verdict IN ('malicious','suspicious')
                  AND i.indicator IN (
                    SELECT shasum FROM payload_daily WHERE day >= ?
                    UNION SELECT url FROM payload_daily WHERE day >= ?
                    UNION SELECT host FROM payload_daily WHERE day >= ?)
                """,
                (cut_day, cut_day, cut_day),
            )
            or {}
        ).get("n", 0)

    built = db.get_state(con, "payloads_built_at") if db.table_exists(con, "insights_state") else None
    row["flagged_indicators"] = flagged
    row["rollup_built_at"] = built
    row["window_days"] = days
    return row


def list_payloads(con, days=30, direction=None, limit=200):
    """One row per (hash, url, direction) with reputation attached.

    Counts come from payload_daily so hits, sessions and source addresses all
    reflect the selected window. The lifetime table only filtered which rows
    appeared, which made the window control look broken.
    """
    if not db.table_exists(con, "payload_daily"):
        return {"built": False, "payloads": []}

    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]
    where = ["day >= ?"]
    params = [cut_day]
    if direction in ("download", "upload"):
        where.append("direction = ?")
        params.append(direction)
    params.append(limit)

    rows = db.qall(
        con,
        f"""
        SELECT shasum, url, MAX(host) host, direction, MAX(filename) filename,
               SUM(hits) hits, SUM(sessions) sessions, MAX(src_ips) src_ips,
               MIN(day) first_seen, MAX(day) last_seen
        FROM payload_daily
        WHERE {' AND '.join(where)}
        GROUP BY shasum, url, direction
        ORDER BY hits DESC, last_seen DESC
        LIMIT ?
        """,
        tuple(params),
    )

    inds = set()
    for r in rows:
        if r["shasum"]:
            inds.add(r["shasum"])
        if r["url"]:
            inds.add(r["url"])
        if r["host"]:
            inds.add(r["host"])
    intel = _intel_map(con, inds)

    for r in rows:
        r["intel"] = {
            "hash": intel.get(r["shasum"], {}),
            "url": intel.get(r["url"], {}),
            "host": intel.get(r["host"], {}),
        }
        r["verdict"] = _worst_verdict(r["intel"])
        r["labels"] = _labels(r["intel"])
    fams = families_for(con, [r["shasum"] for r in rows])
    for r in rows:
        f = fams.get(r["shasum"])
        r["family"] = f["family"] if f else None
        r["family_confidence"] = f["confidence"] if f else None
    return {"built": True, "window_days": days, "payloads": rows}


def _worst_verdict(intel_block):
    order = {"malicious": 3, "suspicious": 2, "undetected": 1, "clean": 1,
             "unknown": 0, "error": 0}
    best = "unknown"
    for group in intel_block.values():
        for rec in group.values():
            v = (rec.get("verdict") or "unknown").lower()
            if order.get(v, 0) > order.get(best, 0):
                best = v
    return best


def families_for(con, shasums):
    """Derived family per hash, for the transfers table."""
    from . import db as _db
    shas = [s for s in shasums if s]
    if not shas or not _db.table_exists(con, "payload_families"):
        return {}
    out = {}
    for i in range(0, len(shas), 300):
        part = shas[i:i + 300]
        marks = ",".join("?" for _ in part)
        for r in _db.qall(
            con,
            f"SELECT shasum, family, confidence FROM payload_families"
            f" WHERE shasum IN ({marks})",
            tuple(part),
        ):
            out[r["shasum"]] = r
    return out


def _labels(intel_block):
    out = []
    for group in intel_block.values():
        for rec in group.values():
            if rec.get("label"):
                out.append(f"{rec['source']}: {rec['label']}")
    return out


def hosts(con, days=30, limit=50):
    """Distribution host rollup. This is the view that answers 'who is serving
    the stagers' rather than 'what did they serve'."""
    if not db.table_exists(con, "payload_daily"):
        return {"built": False, "hosts": []}
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]
    rows = db.qall(
        con,
        """
        SELECT host,
               COUNT(DISTINCT url)    AS urls,
               COUNT(DISTINCT shasum) AS hashes,
               SUM(hits)              AS hits,
               MIN(day)               AS first_seen,
               MAX(day)               AS last_seen
        FROM payload_daily
        WHERE host IS NOT NULL AND host <> '' AND day >= ?
        GROUP BY host
        ORDER BY hits DESC
        LIMIT ?
        """,
        (cut_day, limit),
    )
    intel = _intel_map(con, [r["host"] for r in rows])
    sc = db.source_columns(con)
    for r in rows:
        r["intel"] = intel.get(r["host"], {})
        r["verdict"] = _worst_verdict({"host": r["intel"]})
        r["seen_as_attacker"] = False
        if sc["ip"]:
            hit = db.qone(
                con,
                f"SELECT 1 AS x FROM sources WHERE {sc['ip']} = ?",
                (r["host"],),
            )
            r["seen_as_attacker"] = bool(hit)
    return {"built": True, "hosts": rows}


def payload_detail(con, shasum, limit=100):
    """Everything tied to one hash: URLs, sessions, source IPs, and the
    commands issued in those sessions."""
    variants = db.qall(
        con,
        "SELECT url, direction, filename, host, hits, first_seen, last_seen "
        "FROM payloads WHERE shasum = ? ORDER BY hits DESC",
        (shasum,),
    )
    sightings = db.qall(
        con,
        "SELECT session, src_ip, ts, url, direction FROM payload_sightings "
        "WHERE shasum = ? ORDER BY ts DESC LIMIT ?",
        (shasum, limit),
    )
    sessions = [s["session"] for s in sightings if s["session"]][:25]
    commands = []
    if sessions:
        marks = ",".join("?" for _ in sessions)
        commands = db.qall(
            con,
            f"""
            SELECT session, ts, json_extract(payload,'$.input') AS cmd
            FROM v_events
            WHERE eventid = 'cowrie.command.input' AND session IN ({marks})
            ORDER BY ts
            LIMIT 400
            """,
            tuple(sessions),
        )
    inds = {shasum} | {v["url"] for v in variants if v["url"]} | {
        v["host"] for v in variants if v["host"]
    }
    return {
        "shasum": shasum,
        "variants": variants,
        "sightings": sightings,
        "commands": commands,
        "intel": _intel_map(con, inds),
    }
