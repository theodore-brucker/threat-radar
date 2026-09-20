#!/usr/bin/env python3
"""Threat Radar insights worker.

Builds the derived fact tables the insights endpoints read, then refreshes
reputation data for captured payloads. Safe to run repeatedly; every stage is
idempotent for the days it touches.

  intel_worker.py                     full pass (build + enrich)
  intel_worker.py --only payloads     one stage
  intel_worker.py --no-network        skip VirusTotal, URLhaus and MalwareBazaar
  intel_worker.py --backfill-all      rebuild every day, not just recent ones

Stages: facts, sessions, tunnels, payloads, credentials, spikes, intel,
submit (VirusTotal), bazaar (MalwareBazaar)
"""

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

APP_DIR = os.environ.get("TR_APP", "/opt/threat-radar")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from app.analytics import credentials as credmod  # noqa: E402
from app.analytics import db  # noqa: E402
from app.analytics import escalation as escmod  # noqa: E402
from app.analytics import families as fammod  # noqa: E402
from app.analytics import fingerprints as fpmod  # noqa: E402
from app.analytics import spikes as spikemod  # noqa: E402

MIGRATIONS = [
    os.path.join(APP_DIR, "migrations", "003_insights.sql"),
    os.path.join(APP_DIR, "migrations", "004_site.sql"),
    os.path.join(APP_DIR, "migrations", "005_exec.sql"),
    os.path.join(APP_DIR, "migrations", "006_windowing.sql"),
    # 007 then 008: both redefine v_cred_attempts and 008 is the live one
    # (it reads v_events, so operator testing stays out of the tiers).
    os.path.join(APP_DIR, "migrations", "007_persona_retarget.sql"),
    os.path.join(APP_DIR, "migrations", "008_excluded_sources.sql"),
    os.path.join(APP_DIR, "migrations", "009_entities.sql"),
    os.path.join(APP_DIR, "migrations", "010_integrity.sql"),
    os.path.join(APP_DIR, "migrations", "011_families.sql"),
    os.path.join(APP_DIR, "migrations", "012_epoch_labels.sql"),
]
LOCK_PATH = os.path.join(APP_DIR, ".insights.lock")

DOWNLOAD_EVENT = "cowrie.session.file_download"
UPLOAD_EVENT = "cowrie.session.file_upload"

RECENT_DAYS = int(os.environ.get("TR_INSIGHTS_RECENT_DAYS", "3"))
CRED_DAYS = int(os.environ.get("TR_CRED_DAYS", "90"))

VT_KEY = os.environ.get("TR_VT_API_KEY", "").strip()
URLHAUS_KEY = os.environ.get("TR_URLHAUS_AUTH_KEY", "").strip()
VT_MAX = int(os.environ.get("TR_VT_MAX_LOOKUPS", "40"))
VT_DAILY_CAP = int(os.environ.get("TR_VT_DAILY_CAP", "400"))
VT_SUBMIT_MAX = int(os.environ.get("TR_VT_SUBMIT_MAX", "5"))
URLHAUS_DAILY_CAP = int(os.environ.get("TR_URLHAUS_DAILY_CAP", "500"))
SAMPLE_DIR = os.environ.get("TR_SAMPLE_DIR", os.path.join(APP_DIR, "data", "samples"))
MAX_SAMPLE_BYTES = int(os.environ.get("TR_MAX_SAMPLE_BYTES", str(32 * 1024 * 1024)))
# Cowrie records zero-length and near-empty artifacts (redirect stubs, truncated
# fetches). They are not samples and spending free-tier quota on them is waste.
MIN_SAMPLE_BYTES = int(os.environ.get("TR_SAMPLE_MIN_BYTES", "64"))
URLHAUS_MAX = int(os.environ.get("TR_URLHAUS_MAX_LOOKUPS", "150"))
INTEL_TTL_DAYS = int(os.environ.get("TR_INTEL_TTL_DAYS", "7"))
HTTP_TIMEOUT = 20

# MalwareBazaar uses the same unified abuse.ch Auth-Key as URLhaus, so it falls
# back to that key when no dedicated one is set. Uploads are attributed to the
# key's account unless TR_MB_ANONYMOUS=1.
MB_KEY = os.environ.get("TR_MB_AUTH_KEY", "").strip() or URLHAUS_KEY
MB_API = "https://mb-api.abuse.ch/api/v1/"
MB_SUBMIT_MAX = int(os.environ.get("TR_MB_SUBMIT_MAX", "5"))
MB_DAILY_CAP = int(os.environ.get("TR_MB_DAILY_CAP", "100"))
MB_ANONYMOUS = os.environ.get("TR_MB_ANONYMOUS", "0").strip() == "1"
# MalwareBazaar's submission policy asks for confirmed malware no older than
# about ten days. Both are enforced as gates, not preferences.
MB_MAX_AGE_DAYS = int(os.environ.get("TR_MB_MAX_AGE_DAYS", "10"))
MB_MIN_DETECTIONS = int(os.environ.get("TR_MB_MIN_DETECTIONS", "1"))


def log(msg):
    print(f"[{db.utcnow()}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# schema and day helpers
# ---------------------------------------------------------------------------

def ensure_schema(con):
    for path in MIGRATIONS:
        if not os.path.exists(path):
            log(f"migration missing at {path}, skipping it")
            continue
        with open(path, "r", encoding="utf-8") as fh:
            con.executescript(fh.read())
        con.commit()


def all_days(con, ts):
    row = con.execute("SELECT MIN(ts) AS lo, MAX(ts) AS hi FROM v_events").fetchone()
    if not row or row["lo"] is None:
        return []
    if ts.epoch:
        lo = dt.datetime.fromtimestamp(row["lo"], dt.timezone.utc).date()
        hi = dt.datetime.fromtimestamp(row["hi"], dt.timezone.utc).date()
    else:
        lo = dt.date.fromisoformat(str(row["lo"])[:10])
        hi = dt.date.fromisoformat(str(row["hi"])[:10])
    out, cur = [], lo
    while cur <= hi:
        out.append(cur.isoformat())
        cur += dt.timedelta(days=1)
    return out


def days_to_build(con, ts, table, backfill_all=False):
    days = all_days(con, ts)
    if not days:
        return []
    if backfill_all:
        return days
    have = {r[0] for r in con.execute(f"SELECT DISTINCT day FROM {table}").fetchall()}
    recent = set(days[-RECENT_DAYS:])
    return sorted((set(days) - have) | recent)


# ---------------------------------------------------------------------------
# stage: per-day source facts
# ---------------------------------------------------------------------------

def build_facts(con, backfill_all=False):
    ts = db.TsExpr(con)
    sc = db.source_columns(con)
    days = days_to_build(con, ts, "asn_ip_daily", backfill_all)
    if not days:
        return 0

    if sc["ip"]:
        asn_expr = db.asn_label_sql(sc)
        org_expr = f"MAX(s.{sc['org']})" if sc["org"] else "NULL"
        cc_expr = f"MAX(s.{sc['country']})" if sc["country"] else "NULL"
        join = f"LEFT JOIN sources s ON s.{sc['ip']} = e.src_ip"
        asn_sel = f"MAX({asn_expr})"
    else:
        join, asn_sel, org_expr, cc_expr = "", "'unknown'", "NULL", "NULL"

    sql = f"""
        INSERT OR REPLACE INTO asn_ip_daily
          (day, src_ip, asn, org, country, events, sessions, logins,
           successes, commands, downloads, uploads, tunnels)
        SELECT ?, e.src_ip, {asn_sel}, {org_expr}, {cc_expr},
               COUNT(*),
               COUNT(DISTINCT e.session),
               SUM(e.eventid LIKE 'cowrie.login.%'),
               SUM(e.eventid = 'cowrie.login.success'),
               SUM(e.eventid = 'cowrie.command.input'),
               SUM(e.eventid = '{DOWNLOAD_EVENT}'),
               SUM(e.eventid = '{UPLOAD_EVENT}'),
               SUM(e.eventid LIKE 'cowrie.direct-tcpip%')
        FROM v_events e
        {join}
        WHERE e.ts >= ? AND e.ts < ? AND e.src_ip IS NOT NULL AND e.src_ip <> ''
        GROUP BY e.src_ip
    """
    evt_sql = """
        INSERT OR REPLACE INTO eventid_daily(day, eventid, events)
        SELECT ?, eventid, COUNT(*) FROM v_events
        WHERE ts >= ? AND ts < ? GROUP BY eventid
    """

    for day in days:
        lo, hi = ts.day_range(day)
        con.execute("DELETE FROM asn_ip_daily WHERE day = ?", (day,))
        con.execute(sql, (day, lo, hi))
        con.execute("DELETE FROM eventid_daily WHERE day = ?", (day,))
        con.execute(evt_sql, (day, lo, hi))
        con.commit()
    log(f"facts: rebuilt {len(days)} day(s) ({days[0]} to {days[-1]})")
    db.set_state(con, "facts_built_at", db.utcnow())
    con.commit()
    return len(days)


# ---------------------------------------------------------------------------
# stage: session facts
# ---------------------------------------------------------------------------

def build_sessions(con, backfill_all=False):
    ts = db.TsExpr(con)
    days = days_to_build(con, ts, "session_facts", backfill_all)
    if not days:
        return 0
    day_of_min = ts.day_of("MIN(e.ts)")

    sql = f"""
        INSERT OR REPLACE INTO session_facts
          (session, src_ip, first_seen, last_seen, day, duration, username,
           connected, attempted, authed, commands, downloads, uploads, tunnels, client)
        SELECT e.session,
               MAX(e.src_ip),
               MIN({ts.iso}),
               MAX({ts.iso}),
               {day_of_min},
               MAX(CAST(json_extract(e.payload,'$.duration') AS REAL)),
               MAX(CASE WHEN e.eventid='cowrie.login.success'
                        THEN json_extract(e.payload,'$.username') END),
               MAX(e.eventid = 'cowrie.session.connect'),
               MAX(e.eventid LIKE 'cowrie.login.%'),
               MAX(e.eventid = 'cowrie.login.success'),
               SUM(e.eventid = 'cowrie.command.input'),
               SUM(e.eventid = '{DOWNLOAD_EVENT}'),
               SUM(e.eventid = '{UPLOAD_EVENT}'),
               SUM(e.eventid LIKE 'cowrie.direct-tcpip%'),
               MAX(COALESCE(json_extract(e.payload,'$.version'),
                            json_extract(e.payload,'$.hasshAlgorithms')))
        FROM v_events e
        WHERE e.ts >= ? AND e.ts < ? AND e.session IS NOT NULL AND e.session <> ''
        GROUP BY e.session
        HAVING {day_of_min} = ?
    """
    for day in days:
        # Look one day past the boundary so sessions that cross midnight are
        # counted whole, then keep only the ones that started on this day.
        lo, hi = ts.day_range(day, span_days=2)
        con.execute("DELETE FROM session_facts WHERE day = ?", (day,))
        con.execute(sql, (lo, hi, day))
        con.commit()
    log(f"sessions: rebuilt {len(days)} day(s)")
    db.set_state(con, "sessions_built_at", db.utcnow())
    con.commit()
    return len(days)


# ---------------------------------------------------------------------------
# stage: tunnels
# ---------------------------------------------------------------------------

def build_tunnels(con, backfill_all=False):
    ts = db.TsExpr(con)
    days = days_to_build(con, ts, "tunnel_targets", backfill_all)
    if not days:
        return 0
    sql = """
        INSERT OR REPLACE INTO tunnel_targets
          (day, dst_ip, dst_port, requests, sessions, src_ips, data_events)
        SELECT ?,
               COALESCE(json_extract(payload,'$.dst_ip'),'unknown'),
               COALESCE(CAST(json_extract(payload,'$.dst_port') AS INTEGER),0),
               SUM(eventid = 'cowrie.direct-tcpip.request'),
               COUNT(DISTINCT session),
               COUNT(DISTINCT src_ip),
               SUM(eventid = 'cowrie.direct-tcpip.data')
        FROM v_events
        WHERE eventid LIKE 'cowrie.direct-tcpip%' AND ts >= ? AND ts < ?
        GROUP BY 2, 3
    """
    for day in days:
        lo, hi = ts.day_range(day)
        con.execute("DELETE FROM tunnel_targets WHERE day = ?", (day,))
        con.execute(sql, (day, lo, hi))
        con.commit()
    log(f"tunnels: rebuilt {len(days)} day(s)")
    db.set_state(con, "tunnels_built_at", db.utcnow())
    con.commit()
    return len(days)


# ---------------------------------------------------------------------------
# stage: payload rollup
# ---------------------------------------------------------------------------

def _host_of(url):
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
        return (parsed.hostname or "").strip()
    except ValueError:
        return ""


def build_payloads(con):
    ts = db.TsExpr(con)
    rows = db.qall(
        con,
        f"""
        SELECT eventid, session, src_ip, {ts.iso} AS ts,
               COALESCE(json_extract(payload,'$.shasum'),'')   AS shasum,
               COALESCE(json_extract(payload,'$.url'),'')      AS url,
               COALESCE(json_extract(payload,'$.destfile'),
                        json_extract(payload,'$.filename'),
                        json_extract(payload,'$.outfile'),'')  AS filename
        FROM v_events
        WHERE eventid IN (?, ?)
        ORDER BY ts
        """,
        (DOWNLOAD_EVENT, UPLOAD_EVENT),
    )

    agg = {}
    con.execute("DELETE FROM payloads")
    con.execute("DELETE FROM payload_sightings")
    for r in rows:
        direction = "download" if r["eventid"] == DOWNLOAD_EVENT else "upload"
        key = (r["shasum"] or "", r["url"] or "", direction)
        rec = agg.setdefault(
            key,
            {
                "filename": r["filename"],
                "host": _host_of(r["url"]),
                "hits": 0,
                "sessions": set(),
                "ips": set(),
                "first": r["ts"],
                "last": r["ts"],
            },
        )
        rec["hits"] += 1
        if r["session"]:
            rec["sessions"].add(r["session"])
        if r["src_ip"]:
            rec["ips"].add(r["src_ip"])
        rec["first"] = min(rec["first"] or r["ts"], r["ts"] or "")
        rec["last"] = max(rec["last"] or r["ts"], r["ts"] or "")
        if not rec["filename"] and r["filename"]:
            rec["filename"] = r["filename"]
        con.execute(
            "INSERT OR REPLACE INTO payload_sightings"
            "(shasum,url,direction,session,src_ip,ts) VALUES(?,?,?,?,?,?)",
            (key[0], key[1], direction, r["session"], r["src_ip"], r["ts"]),
        )

    for (sha, url, direction), rec in agg.items():
        con.execute(
            """
            INSERT OR REPLACE INTO payloads
              (shasum,url,direction,filename,host,hits,sessions,src_ips,first_seen,last_seen)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                sha,
                url,
                direction,
                rec["filename"],
                rec["host"],
                rec["hits"],
                len(rec["sessions"]),
                len(rec["ips"]),
                rec["first"],
                rec["last"],
            ),
        )
    # Per-day payload counts for the window selector.
    con.execute("DELETE FROM payload_daily")
    ts2 = db.TsExpr(con)
    con.execute(
        f"""
        INSERT OR REPLACE INTO payload_daily
          (day, shasum, url, direction, host, filename, hits, sessions, src_ips)
        SELECT {ts2.day},
               COALESCE(json_extract(payload,'$.shasum'),''),
               COALESCE(json_extract(payload,'$.url'),''),
               CASE WHEN eventid = ? THEN 'download' ELSE 'upload' END,
               NULL,
               COALESCE(json_extract(payload,'$.destfile'),
                        json_extract(payload,'$.filename'),
                        json_extract(payload,'$.outfile'),''),
               COUNT(*), COUNT(DISTINCT session), COUNT(DISTINCT src_ip)
        FROM v_events
        WHERE eventid IN (?, ?)
        GROUP BY 1, 2, 3, 4
        """,
        (DOWNLOAD_EVENT, DOWNLOAD_EVENT, UPLOAD_EVENT),
    )
    # host is parsed in Python, so fill it from the rollup we just built
    con.execute(
        "UPDATE payload_daily SET host = (SELECT p.host FROM payloads p "
        "WHERE p.shasum = payload_daily.shasum AND p.url = payload_daily.url "
        "AND p.direction = payload_daily.direction)"
    )
    db.set_state(con, "payloads_built_at", db.utcnow())
    con.commit()
    log(f"payloads: {len(agg)} rollup rows from {len(rows)} transfer events, "
        "per-day table rebuilt")
    return len(agg)


# ---------------------------------------------------------------------------
# stage: credential clustering
# ---------------------------------------------------------------------------

def build_credentials(con, backfill_all=False):
    ts = db.TsExpr(con)
    rules, _ = credmod.load_rules()
    if not rules:
        log("credentials: no rules loaded, check TR_CRED_RULES")
    pairs = db.qall(
        con,
        f"""
        SELECT COALESCE(json_extract(payload,'$.username'),'') AS username,
               COALESCE(json_extract(payload,'$.password'),'') AS password,
               COUNT(*) AS attempts,
               SUM(eventid = 'cowrie.login.success') AS successes,
               COUNT(DISTINCT src_ip) AS distinct_ips,
               MIN({ts.iso}) AS first_seen,
               MAX({ts.iso}) AS last_seen
        FROM v_events
        WHERE eventid LIKE 'cowrie.login.%'
        GROUP BY 1, 2
        """,
    )

    con.execute("DELETE FROM cred_pairs")
    con.execute("DELETE FROM cred_pair_tags")
    tag_of = {}
    for p in pairs:
        tags = credmod.tag_pair(p["username"], p["password"], rules)
        tag_of[(p["username"], p["password"])] = tags
        con.execute(
            "INSERT OR REPLACE INTO cred_pairs"
            "(username,password,attempts,successes,distinct_ips,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                p["username"],
                p["password"],
                p["attempts"],
                p["successes"],
                p["distinct_ips"],
                p["first_seen"],
                p["last_seen"],
            ),
        )
        for t in tags:
            con.execute(
                "INSERT OR REPLACE INTO cred_pair_tags(username,password,tag) VALUES(?,?,?)",
                (p["username"], p["password"], t),
            )
    con.commit()

    # Campaign to infrastructure mapping, scoped to keep the scan bounded.
    cut = ts.cutoff(CRED_DAYS)
    tag_ips = {}
    for r in con.execute(
        """
        SELECT COALESCE(json_extract(payload,'$.username'),'') AS u,
               COALESCE(json_extract(payload,'$.password'),'') AS p,
               src_ip, COUNT(*) AS n
        FROM v_events
        WHERE eventid LIKE 'cowrie.login.%' AND ts >= ?
        GROUP BY 1,2,3
        """,
        (cut,),
    ):
        for t in tag_of.get((r["u"], r["p"]), []):
            key = (t, r["src_ip"] or "")
            tag_ips[key] = tag_ips.get(key, 0) + r["n"]

    con.execute("DELETE FROM cred_tag_ips")
    for (tag, ip), n in tag_ips.items():
        con.execute(
            "INSERT OR REPLACE INTO cred_tag_ips(tag,src_ip,attempts) VALUES(?,?,?)",
            (tag, ip, n),
        )
    # Per-day counts, so the window selector moves the numbers and not just
    # which rows survive the filter.
    ts2 = db.TsExpr(con)
    days = days_to_build(con, ts2, "cred_pair_daily", backfill_all)
    for day in days:
        lo, hi = ts2.day_range(day)
        con.execute("DELETE FROM cred_pair_daily WHERE day = ?", (day,))
        con.execute(
            """
            INSERT OR REPLACE INTO cred_pair_daily
              (day, username, password, attempts, successes, src_ips)
            SELECT ?,
                   COALESCE(json_extract(payload,'$.username'),''),
                   COALESCE(json_extract(payload,'$.password'),''),
                   COUNT(*),
                   SUM(eventid = 'cowrie.login.success'),
                   COUNT(DISTINCT src_ip)
            FROM v_events
            WHERE eventid LIKE 'cowrie.login.%' AND ts >= ? AND ts < ?
            GROUP BY 2, 3
            """,
            (day, lo, hi),
        )
        con.commit()
    log(f"credentials: {len(pairs)} pairs tagged, {len(tag_ips)} tag/IP rows, "
        f"{len(days)} day(s) of per-day counts")
    db.set_state(con, "credentials_built_at", db.utcnow())
    con.commit()
    return len(pairs)


# ---------------------------------------------------------------------------
# stage: entity pivot rollups
# ---------------------------------------------------------------------------

def build_entities(con, backfill_all=False):
    """Per-day pivot tables for the entity pages: which address pushed which
    credential pair, and which address presented which client fingerprint.
    Same shape and idempotence as every other daily table here."""
    ts = db.TsExpr(con)

    cred_days = days_to_build(con, ts, "cred_ip_daily", backfill_all)
    cred_sql = """
        INSERT OR REPLACE INTO cred_ip_daily
          (day, username, password, src_ip, attempts, successes)
        SELECT ?,
               COALESCE(json_extract(payload,'$.username'),''),
               COALESCE(json_extract(payload,'$.password'),''),
               src_ip,
               COUNT(*),
               SUM(eventid = 'cowrie.login.success')
        FROM v_events
        WHERE eventid LIKE 'cowrie.login.%' AND ts >= ? AND ts < ?
          AND src_ip IS NOT NULL AND src_ip <> ''
        GROUP BY 2, 3, 4
    """
    for day in cred_days:
        lo, hi = ts.day_range(day)
        con.execute("DELETE FROM cred_ip_daily WHERE day = ?", (day,))
        con.execute(cred_sql, (day, lo, hi))
        con.commit()

    fp_days = days_to_build(con, ts, "hassh_ip_daily", backfill_all)
    fp_sql = """
        INSERT OR REPLACE INTO hassh_ip_daily
          (day, hassh, src_ip, events, sessions)
        SELECT ?,
               json_extract(payload,'$.hassh'),
               src_ip,
               COUNT(*),
               COUNT(DISTINCT session)
        FROM v_events
        WHERE eventid = 'cowrie.client.kex' AND ts >= ? AND ts < ?
          AND json_extract(payload,'$.hassh') IS NOT NULL
          AND src_ip IS NOT NULL AND src_ip <> ''
        GROUP BY 2, 3
    """
    for day in fp_days:
        lo, hi = ts.day_range(day)
        con.execute("DELETE FROM hassh_ip_daily WHERE day = ?", (day,))
        con.execute(fp_sql, (day, lo, hi))
        con.commit()

    log(f"entities: rebuilt {len(cred_days)} cred day(s), "
        f"{len(fp_days)} fingerprint day(s)")
    db.set_state(con, "entities_built_at", db.utcnow())
    con.commit()
    return len(cred_days) + len(fp_days)


# ---------------------------------------------------------------------------
# stage: reputation enrichment
# ---------------------------------------------------------------------------

def _remaining(con, source, per_run, daily_cap):
    """Per-run budget clipped by what today has already spent. The counter key
    carries the date, so it ages out on its own."""
    used = int(db.get_state(con, f"quota_{source}_{db.utcnow()[:10]}", 0) or 0)
    return min(per_run, max(0, daily_cap - used))


def _spend(con, source, n=1):
    key = f"quota_{source}_{db.utcnow()[:10]}"
    used = int(db.get_state(con, key, 0) or 0)
    db.set_state(con, key, used + n)
    con.commit()


USER_AGENT = "threat-radar/1.0 (+https://github.com/theodore-brucker/threat-radar)"


def _decode(status, raw):
    """Parse a JSON body. A body that is not JSON keeps its real status and a
    slice of the raw text, instead of being reported as a network failure."""
    text = raw.decode("utf-8", "replace")
    try:
        return status, json.loads(text)
    except ValueError:
        return status, {"error": "non-json response",
                        "raw": text[:400] if text.strip() else "(empty body)"}


def _http(url, headers=None, data=None):
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return _decode(resp.status, resp.read())
    except urllib.error.HTTPError as e:
        return _decode(e.code, e.read())
    except Exception as e:  # network down, DNS, TLS, timeout
        return 0, {"error": str(e)}


def _save_intel(con, indicator, kind, source, verdict, counts=None, label=None,
                reference=None, raw=None):
    counts = counts or {}
    con.execute(
        """
        INSERT OR REPLACE INTO payload_intel
          (indicator,kind,source,verdict,malicious,suspicious,harmless,undetected,
           label,reference,raw,checked_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            indicator,
            kind,
            source,
            verdict,
            counts.get("malicious", 0),
            counts.get("suspicious", 0),
            counts.get("harmless", 0),
            counts.get("undetected", 0),
            label,
            reference,
            json.dumps(raw)[:4000] if raw is not None else None,
            db.utcnow(),
        ),
    )
    con.commit()


def _stale(con, indicator, source):
    row = con.execute(
        "SELECT checked_at, verdict FROM payload_intel WHERE indicator=? AND source=?",
        (indicator, source),
    ).fetchone()
    if not row or not row["checked_at"]:
        return True
    ttl = 1 if (row["verdict"] or "unknown") in ("unknown", "error") else INTEL_TTL_DAYS
    try:
        seen = dt.datetime.strptime(row["checked_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError:
        return True
    return (dt.datetime.now(dt.timezone.utc) - seen).days >= ttl


def vt_lookup(con, indicator, kind):
    if kind == "sha256":
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        ref = f"https://www.virustotal.com/gui/file/{indicator}"
    elif kind == "url":
        vid = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{vid}"
        ref = f"https://www.virustotal.com/gui/url/{vid}"
    else:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        ref = f"https://www.virustotal.com/gui/ip-address/{indicator}"

    status, body = _http(url, headers={"x-apikey": VT_KEY, "Accept": "application/json"})
    if status == 404:
        _save_intel(con, indicator, kind, "virustotal", "unknown",
                    label="not in VirusTotal", reference=ref)
        return "unknown"
    if status != 200:
        _save_intel(con, indicator, kind, "virustotal", "error",
                    label=str(body.get("error", status))[:120], reference=ref)
        return "error"

    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    verdict = ("malicious" if malicious
               else "suspicious" if suspicious
               # "clean" claimed more than the data supports: zero detections
               # means no engine flagged it, which for a freshly submitted
               # sample often means nobody has looked at it yet.
               else "undetected")
    label = None
    ptc = attrs.get("popular_threat_classification") or {}
    if ptc.get("suggested_threat_label"):
        label = ptc["suggested_threat_label"]
    elif attrs.get("meaningful_name"):
        name = str(attrs["meaningful_name"])
        # For an unnamed sample VT returns the hash as the name, which is how
        # "<sha256>.unknown [unknown]" ended up rendered as a malware label.
        if not re.match(r"^[0-9a-f]{32,64}", name, re.I):
            label = name
    if attrs.get("type_description"):
        label = f"{label or ''} [{attrs['type_description']}]".strip()
    # popular_threat_name carries the per-family vote counts the derivation
    # benefits from, so keep it rather than only the suggested label.
    _save_intel(con, indicator, kind, "virustotal", verdict, stats, label, ref,
                {"stats": stats, "names": attrs.get("names", [])[:5],
                 "threat_names": [n.get("value") for n in
                                  (ptc.get("popular_threat_name") or [])[:5]],
                 "threat_categories": [n.get("value") for n in
                                       (ptc.get("popular_threat_category") or [])[:3]]})
    return verdict


def urlhaus_lookup(con, indicator, kind):
    headers = {"Auth-Key": URLHAUS_KEY} if URLHAUS_KEY else {}
    if kind == "url":
        endpoint, field = "url", "url"
    elif kind == "host":
        endpoint, field = "host", "host"
    else:
        endpoint, field = "payload", "sha256_hash"
    data = urllib.parse.urlencode({field: indicator}).encode()
    status, body = _http(
        f"https://urlhaus-api.abuse.ch/v1/{endpoint}/", headers=headers, data=data
    )
    if status == 401:
        _save_intel(con, indicator, kind, "urlhaus", "error",
                    label="auth key rejected or missing")
        return "error"
    if status != 200:
        _save_intel(con, indicator, kind, "urlhaus", "error", label=f"http {status}")
        return "error"

    qs = body.get("query_status")
    if qs in ("no_results", "not_found"):
        _save_intel(con, indicator, kind, "urlhaus", "unknown", label="not listed")
        return "unknown"
    if qs != "ok":
        _save_intel(con, indicator, kind, "urlhaus", "error", label=str(qs)[:80])
        return "error"

    if endpoint == "payload":
        label = body.get("signature") or body.get("file_type")
        ref = body.get("urlhaus_download")
        verdict = "malicious"
    elif endpoint == "host":
        n = int(body.get("url_count") or 0)
        label = f"{n} malware URL(s) hosted"
        ref = body.get("urlhaus_reference")
        verdict = "malicious" if n else "unknown"
    else:
        tags = ",".join(body.get("tags") or [])
        label = f"{body.get('threat','')} {tags}".strip()
        ref = body.get("urlhaus_reference")
        verdict = "malicious" if body.get("threat") else "suspicious"
    _save_intel(con, indicator, kind, "urlhaus", verdict, None, label, ref, body)
    return verdict


def enrich(con):
    if not VT_KEY and not URLHAUS_KEY:
        log("intel: no TR_VT_API_KEY or TR_URLHAUS_AUTH_KEY set, skipping lookups")
        return 0

    hashes = [
        r["shasum"]
        for r in db.qall(
            con,
            "SELECT DISTINCT shasum FROM payloads WHERE shasum <> '' ORDER BY last_seen DESC",
        )
    ]
    urls = [
        r["url"]
        for r in db.qall(
            con,
            "SELECT DISTINCT url FROM payloads WHERE url <> '' ORDER BY last_seen DESC",
        )
    ]
    hosts = [
        r["host"]
        for r in db.qall(
            con,
            "SELECT DISTINCT host FROM payloads WHERE host IS NOT NULL AND host <> ''",
        )
    ]

    done = 0
    if VT_KEY:
        budget = _remaining(con, "vt", VT_MAX, VT_DAILY_CAP)
        log(f"intel: virustotal budget this run {budget}")
        for kind, items in (("sha256", hashes), ("url", urls)):
            for ind in items:
                if budget <= 0:
                    break
                if not _stale(con, ind, "virustotal"):
                    continue
                v = vt_lookup(con, ind, kind)
                log(f"intel: virustotal {kind} {ind[:60]} -> {v}")
                budget -= 1
                done += 1
                _spend(con, "vt")
                time.sleep(16)  # public API allows 4 requests per minute
    if URLHAUS_KEY:
        budget = _remaining(con, "urlhaus", URLHAUS_MAX, URLHAUS_DAILY_CAP)
        for kind, items in (("url", urls), ("host", hosts), ("sha256", hashes)):
            for ind in items:
                if budget <= 0:
                    break
                if not _stale(con, ind, "urlhaus"):
                    continue
                v = urlhaus_lookup(con, ind, kind)
                log(f"intel: urlhaus {kind} {ind[:60]} -> {v}")
                budget -= 1
                done += 1
                _spend(con, "urlhaus")
                time.sleep(1)
    db.set_state(con, "intel_built_at", db.utcnow())
    con.commit()
    return done



# ---------------------------------------------------------------------------
# submission helpers shared by the VirusTotal and MalwareBazaar stages
# ---------------------------------------------------------------------------

DRY_RUN_SUBMIT = False


def _multipart(fields, filename, payload):
    """Build a multipart/form-data body with stdlib only, so the worker keeps
    its zero-dependency footprint."""
    boundary = "----radar" + hashlib.sha1(os.urandom(16)).hexdigest()[:24]
    out = []
    for k, v in (fields or {}).items():
        out.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    out.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
        f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
    )
    out.append(payload)
    out.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


def _record_submission(con, sha, status, analysis_id=None, permalink=None,
                       detail=None, size=None, service="virustotal"):
    con.execute(
        """
        INSERT OR REPLACE INTO payload_submissions
          (sha256, service, status, analysis_id, permalink, detail, size_bytes, submitted_at)
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (sha, service, status, analysis_id, permalink, detail, size, db.utcnow()),
    )
    con.commit()


def _record_known(con, sha, service, detail, permalink=None, size=None):
    """Record that a service already held this hash when we first checked.
    INSERT OR IGNORE, so it can never overwrite a row saying we submitted it."""
    con.execute(
        """
        INSERT OR IGNORE INTO payload_submissions
          (sha256, service, status, permalink, detail, size_bytes, submitted_at)
        VALUES(?,?,'duplicate',?,?,?,?)
        """,
        (sha, service, permalink, detail, size, db.utcnow()),
    )
    con.commit()


def _sample_path(sha):
    """Cowrie names the captured file after its sha256, so the hash is the
    filename. Fall back to a scan in case the sync flattened directories."""
    direct = os.path.join(SAMPLE_DIR, sha)
    if os.path.exists(direct):
        return direct
    for root, _dirs, files in os.walk(SAMPLE_DIR):
        if sha in files:
            return os.path.join(root, sha)
    return None


# ---------------------------------------------------------------------------
# stage: submit unknown samples to VirusTotal
# ---------------------------------------------------------------------------

def _backfill_vt_known(con):
    """Give every hash VirusTotal already knew a 'duplicate' row. Before this,
    only hashes the worker acted on were recorded, which hid the 'identified'
    stage of the contribution funnel. No network calls: it reads verdicts the
    intel stage already stored."""
    cur = con.execute(
        """
        INSERT OR IGNORE INTO payload_submissions
          (sha256, service, status, permalink, detail, submitted_at)
        SELECT i.indicator, 'virustotal', 'duplicate', i.reference,
               'already in VirusTotal when checked',
               COALESCE(i.checked_at, ?)
        FROM payload_intel i
        WHERE i.source = 'virustotal' AND i.kind = 'sha256'
          AND i.verdict NOT IN ('unknown', 'error')
        """,
        (db.utcnow(),),
    )
    con.commit()
    if cur.rowcount:
        log(f"submit: recorded {cur.rowcount} hash(es) VirusTotal already held")
    return cur.rowcount


def submit_samples(con):
    """Upload captured samples that VirusTotal has never seen.

    Only hashes VirusTotal answered 404 on are candidates, so nothing already
    in their corpus is re-uploaded. Uploads count against the same 500/day
    public quota as lookups and are spent from the same counter.
    """
    _backfill_vt_known(con)
    if not VT_KEY:
        log("submit: no TR_VT_API_KEY, skipping")
        return 0
    if not os.path.isdir(SAMPLE_DIR):
        log(f"submit: sample directory {SAMPLE_DIR} missing, run bin/fetch_samples.sh")
        return 0

    candidates = db.qall(
        con,
        """
        SELECT DISTINCT p.shasum AS sha
        FROM payloads p
        JOIN payload_intel i
          ON i.indicator = p.shasum AND i.source = 'virustotal' AND i.kind = 'sha256'
        WHERE p.shasum <> ''
          AND i.verdict = 'unknown'
          AND NOT EXISTS (
            SELECT 1 FROM payload_submissions s
            WHERE s.sha256 = p.shasum AND s.service = 'virustotal'
                  AND s.status IN ('submitted','duplicate')
          )
        ORDER BY p.shasum
        """,
    )
    if not candidates:
        log("submit: nothing new for VirusTotal")
        db.set_state(con, "submissions_built_at", db.utcnow())
        con.commit()
        return 0

    budget = min(VT_SUBMIT_MAX, _remaining(con, "vt", VT_SUBMIT_MAX, VT_DAILY_CAP))
    log(f"submit: {len(candidates)} candidate(s), budget {budget}")
    sent = 0
    for row in candidates:
        if budget <= 0:
            break
        sha = row["sha"]
        path = _sample_path(sha)
        if not path:
            _record_submission(con, sha, "skipped", detail="sample file not on this host")
            continue
        size = os.path.getsize(path)
        if size < MIN_SAMPLE_BYTES or size > MAX_SAMPLE_BYTES:
            _record_submission(con, sha, "skipped", detail=f"size {size} out of range",
                               size=size)
            continue
        if DRY_RUN_SUBMIT:
            log(f"submit: would upload {sha[:16]} ({size} bytes) from {path}")
            continue

        with open(path, "rb") as fh:
            blob = fh.read()
        body, ctype = _multipart({}, sha, blob)
        status, resp = _http(
            "https://www.virustotal.com/api/v3/files",
            headers={"x-apikey": VT_KEY, "Content-Type": ctype,
                     "Content-Length": str(len(body))},
            data=body,
        )
        _spend(con, "vt")
        budget -= 1
        if status in (200, 201):
            aid = ((resp.get("data") or {}).get("id")) or ""
            _record_submission(
                con, sha, "submitted", analysis_id=aid,
                permalink=f"https://www.virustotal.com/gui/file/{sha}",
                detail="uploaded", size=size,
            )
            # Force a re-lookup on the next pass now that VT has the file.
            con.execute(
                "UPDATE payload_intel SET checked_at=NULL "
                "WHERE indicator=? AND source='virustotal'",
                (sha,),
            )
            con.commit()
            sent += 1
            log(f"submit: uploaded {sha[:16]} ({size} bytes)")
        elif status == 409:
            _record_submission(con, sha, "duplicate", detail="already present",
                               size=size)
        else:
            _record_submission(con, sha, "error",
                               detail=f"http {status}: {str(resp)[:200]}", size=size)
            log(f"submit: {sha[:16]} failed http {status}")
        time.sleep(16)

    db.set_state(con, "submissions_built_at", db.utcnow())
    con.commit()
    log(f"submit: {sent} upload(s) this run")
    return sent


# ---------------------------------------------------------------------------
# stage: submit confirmed samples to MalwareBazaar
# ---------------------------------------------------------------------------

def _mb_tags(blob):
    tags = ["honeypot", "cowrie", "ssh"]
    if blob[:4] == b"\x7fELF":
        tags.append("elf")
    elif blob[:2] == b"#!" and b"sh" in blob[:64].split(b"\n", 1)[0]:
        tags.append("sh")
    return tags


def _mb_comment(first_day, via_url, via_upload):
    """Context for the MalwareBazaar entry. Deliberately limited to date and
    delivery method: nothing that identifies the sensor or its persona."""
    if via_url:
        how = "fetched from a URL (wget/curl) inside the session"
    elif via_upload:
        how = "pushed over SFTP/SCP"
    else:
        how = "written in-band during the session"
    return f"Captured by an SSH honeypot, first seen {first_day} UTC, {how}."


def _mb_lookup(con, sha):
    """Returns 'known', 'unknown' or 'error'. A hit is also stored in
    payload_intel so the family derivation can use MalwareBazaar's signature."""
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha}).encode()
    status, body = _http(MB_API, headers={"Auth-Key": MB_KEY}, data=data)
    ref = f"https://bazaar.abuse.ch/sample/{sha}/"
    if status != 200:
        return "error", f"http {status}: {str(body)[:160]}"
    qs = body.get("query_status")
    if qs == "hash_not_found":
        return "unknown", None
    if qs != "ok":
        return "error", str(qs)[:160]
    entry = (body.get("data") or [{}])[0]
    sig = entry.get("signature")
    _save_intel(con, sha, "sha256", "malwarebazaar", "malicious", None,
                sig or entry.get("file_type"), ref,
                {"reporter": entry.get("reporter"),
                 "first_seen": entry.get("first_seen"),
                 "tags": entry.get("tags")})
    return "known", sig


def submit_bazaar(con):
    """Upload samples to MalwareBazaar under the account that owns the key.

    Eligible samples are on this host, inside the size bounds, first seen
    within TR_MB_MAX_AGE_DAYS, and flagged by at least TR_MB_MIN_DETECTIONS
    VirusTotal engines. Each is checked by hash first so nothing already in
    the corpus is re-uploaded. Age and size failures are permanent and get a
    'skipped' row; a detection shortfall is not, because the VirusTotal score
    can still rise, so those are left to be re-evaluated on later runs.
    """
    if not MB_KEY:
        log("bazaar: no TR_MB_AUTH_KEY or TR_URLHAUS_AUTH_KEY, skipping")
        return 0
    if not os.path.isdir(SAMPLE_DIR):
        log(f"bazaar: sample directory {SAMPLE_DIR} missing, run bin/fetch_samples.sh")
        return 0

    rows = db.qall(
        con,
        """
        SELECT p.shasum AS sha,
               MIN(p.first_seen) AS first_seen,
               MAX(p.url <> '') AS via_url,
               MAX(p.direction = 'upload') AS via_upload,
               COALESCE(MAX(i.malicious), 0) AS malicious
        FROM payloads p
        LEFT JOIN payload_intel i
          ON i.indicator = p.shasum AND i.source = 'virustotal' AND i.kind = 'sha256'
        WHERE p.shasum <> ''
          AND NOT EXISTS (
            SELECT 1 FROM payload_submissions s
            WHERE s.sha256 = p.shasum AND s.service = 'malwarebazaar'
                  AND s.status IN ('submitted','duplicate','skipped')
          )
        GROUP BY p.shasum
        ORDER BY first_seen DESC
        """,
    )
    today = dt.datetime.now(dt.timezone.utc).date()
    budget = _remaining(con, "mb", MB_SUBMIT_MAX, MB_DAILY_CAP)
    log(f"bazaar: {len(rows)} unrecorded hash(es), budget {budget}")

    sent = waiting = 0
    for row in rows:
        sha = row["sha"]
        first_day = str(row["first_seen"] or "")[:10]
        try:
            age = (today - dt.date.fromisoformat(first_day)).days
        except ValueError:
            age = None
        if age is None or age > MB_MAX_AGE_DAYS:
            _record_submission(con, sha, "skipped", service="malwarebazaar",
                               detail=f"first seen {first_day or 'unknown'}, "
                                      f"outside the {MB_MAX_AGE_DAYS}-day window")
            continue
        path = _sample_path(sha)
        if not path:
            continue  # fetch_samples.sh may still bring it over
        size = os.path.getsize(path)
        if size < MIN_SAMPLE_BYTES or size > MAX_SAMPLE_BYTES:
            _record_submission(con, sha, "skipped", service="malwarebazaar",
                               detail=f"size {size} out of range", size=size)
            continue
        if row["malicious"] < MB_MIN_DETECTIONS:
            waiting += 1
            continue
        if budget <= 0:
            break

        state, info = _mb_lookup(con, sha)
        _spend(con, "mb")
        budget -= 1
        if state == "known":
            _record_known(con, sha, "malwarebazaar",
                          f"already in MalwareBazaar ({info or 'no signature'})",
                          permalink=f"https://bazaar.abuse.ch/sample/{sha}/", size=size)
            log(f"bazaar: {sha[:16]} already known")
            time.sleep(2)
            continue
        if state == "error":
            log(f"bazaar: lookup {sha[:16]} failed: {info}")
            time.sleep(2)
            continue
        if budget <= 0:
            break
        if DRY_RUN_SUBMIT:
            log(f"bazaar: would upload {sha[:16]} ({size} bytes, "
                f"{row['malicious']} VT detections, first seen {first_day})")
            continue

        with open(path, "rb") as fh:
            blob = fh.read()
        meta = {
            "anonymous": 1 if MB_ANONYMOUS else 0,
            "delivery_method": "web_download" if row["via_url"] else "other",
            "tags": _mb_tags(blob),
            "context": {"comment": _mb_comment(first_day, row["via_url"],
                                               row["via_upload"])},
        }
        body, ctype = _multipart({"json_data": json.dumps(meta)}, sha, blob)
        status, resp = _http(
            MB_API,
            headers={"Auth-Key": MB_KEY, "Content-Type": ctype,
                     "Content-Length": str(len(body))},
            data=body,
        )
        _spend(con, "mb")
        budget -= 1
        qs = resp.get("query_status") if isinstance(resp, dict) else None
        if qs is None and "inserted" in str(resp.get("raw", "")):
            qs = "inserted"
        link = f"https://bazaar.abuse.ch/sample/{sha}/"
        if status == 200 and qs == "inserted":
            _record_submission(con, sha, "submitted", permalink=link,
                               detail="uploaded", size=size, service="malwarebazaar")
            sent += 1
            log(f"bazaar: uploaded {sha[:16]} ({size} bytes)")
        elif status == 200 and qs == "file_already_known":
            _record_known(con, sha, "malwarebazaar", "already present at upload",
                          permalink=link, size=size)
        else:
            _record_submission(con, sha, "error", service="malwarebazaar",
                               detail=f"http {status}: {qs or str(resp)[:400]}",
                               size=size)
            log(f"bazaar: {sha[:16]} failed http {status} {qs}")
        time.sleep(2)

    db.set_state(con, "bazaar_built_at", db.utcnow())
    con.commit()
    log(f"bazaar: {sent} upload(s) this run, {waiting} waiting on "
        f"VirusTotal detections")
    return sent

# ---------------------------------------------------------------------------

STAGES = ("facts", "sessions", "tunnels", "payloads", "credentials",
          "fingerprints", "entities", "stage", "spikes", "intel", "families",
          "submit", "bazaar")


def main():
    ap = argparse.ArgumentParser(description="Threat Radar insights worker")
    ap.add_argument("--only", help="comma separated subset of: " + ",".join(STAGES))
    ap.add_argument("--no-network", action="store_true", help="skip reputation lookups")
    ap.add_argument("--backfill-all", action="store_true", help="rebuild every day")
    ap.add_argument("--force-spikes", action="store_true", help="re-annotate known spikes")
    ap.add_argument("--dry-run-submit", action="store_true",
                    help="list what would be uploaded to VirusTotal and "
                         "MalwareBazaar, upload nothing")
    args = ap.parse_args()

    stages = [s.strip() for s in args.only.split(",")] if args.only else list(STAGES)
    if args.no_network:
        for s_ in ("intel", "submit", "bazaar"):
            if s_ in stages:
                stages.remove(s_)
    global DRY_RUN_SUBMIT
    DRY_RUN_SUBMIT = args.dry_run_submit

    lock = open(LOCK_PATH, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("another worker run holds the lock, exiting")
        return 0

    con = db.connect_rw()
    ensure_schema(con)
    start = time.time()
    try:
        if "facts" in stages:
            build_facts(con, args.backfill_all)
        if "sessions" in stages:
            build_sessions(con, args.backfill_all)
        if "tunnels" in stages:
            build_tunnels(con, args.backfill_all)
        if "payloads" in stages:
            build_payloads(con)
        if "credentials" in stages:
            build_credentials(con, args.backfill_all)
        if "fingerprints" in stages:
            n = fpmod.rebuild(con, args.backfill_all, RECENT_DAYS)
            log(f"fingerprints: rebuilt {n} day(s)")
            db.set_state(con, "fingerprints_built_at", db.utcnow())
            con.commit()
        if "entities" in stages:
            build_entities(con, args.backfill_all)
        if "stage" in stages:
            n = escmod.rebuild(con)
            nd = escmod.rebuild_daily(con, args.backfill_all, RECENT_DAYS)
            log(f"stage: scored {n} source(s), {nd} day(s) of per-day stage")
            db.set_state(con, "stage_built_at", db.utcnow())
            con.commit()
        if "spikes" in stages:
            written = spikemod.annotate(con, force=args.force_spikes)
            log(f"spikes: annotated {len(written)} day(s) {written}")
            db.set_state(con, "spikes_built_at", db.utcnow())
            con.commit()
        if "intel" in stages:
            enrich(con)
        if "families" in stages:
            n = fammod.rebuild(con)
            log(f"families: derived a family for {n} sample(s)")
            db.set_state(con, "families_built_at", db.utcnow())
            con.commit()
        if "submit" in stages:
            submit_samples(con)
        if "bazaar" in stages:
            submit_bazaar(con)
        db.set_state(con, "last_run", db.utcnow())
        db.set_state(con, "last_run_seconds", round(time.time() - start, 1))
        con.commit()
    finally:
        con.close()
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
    log(f"done in {time.time() - start:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
