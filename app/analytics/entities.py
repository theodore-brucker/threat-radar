"""Entity drill-down: one canonical read per pivotable value.

Every indicator on the site (address, network, credential pair, client
fingerprint, fetch URL, calendar day) resolves to one entity endpoint,
/api/v1/entity/{type}/{value}, which returns one consistent shape:

    {type, value, label, profile: {...}, timeseries: [{day, ...}],
     related: {...}}

so the frontend renders every entity page from a single template.

Rules, same as the rest of the site:

  1. Values arrive attacker-controlled. Every value is validated before it
     touches a query, every query is parameterised, and free-text values
     (credentials, URLs) travel in the path as base64url so nothing needs
     to survive URL escaping.
  2. No handler scans raw_events for a list. Timeseries and related sets
     come from the daily fact tables; the only touches on v_events are
     bounded by an indexed equality (src_ip) with a LIMIT.
"""

import base64
import binascii
import datetime as dt
import re

from . import db
from .fingerprints import describe as hassh_describe

IP_RE = re.compile(r"^[0-9A-Fa-f:.]{3,45}$")
ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HASSH_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_DECODED = 1024  # bytes; longest credential or URL we will look up


class BadEntity(ValueError):
    """Raised when the value fails validation for its type."""


# ---------------------------------------------------------------------------
# id codecs
# ---------------------------------------------------------------------------

def decode_token(value):
    """base64url without padding -> str. Credentials and URLs contain
    characters that do not survive path segments, so they travel encoded."""
    v = str(value or "")
    if not v or len(v) > MAX_DECODED * 2:
        raise BadEntity("bad token")
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", v):
        raise BadEntity("bad token")
    pad = "=" * (-len(v.rstrip("=")) % 4)
    try:
        raw = base64.urlsafe_b64decode(v.rstrip("=") + pad)
    except (binascii.Error, ValueError):
        raise BadEntity("bad token")
    if not raw or len(raw) > MAX_DECODED:
        raise BadEntity("bad token")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BadEntity("bad token")


def _cut_day(con, days):
    ts = db.TsExpr(con)
    return str(ts.cutoff(db.clamp_days(days, default=30)))[:10]


# ---------------------------------------------------------------------------
# handlers
# ---------------------------------------------------------------------------

def ip_entity(con, value, days):
    if not IP_RE.match(value):
        raise BadEntity("not an address")
    cut = _cut_day(con, days)

    stage = db.qone(con, "SELECT * FROM source_stage WHERE src_ip=?", (value,))
    src = db.qone(con, "SELECT * FROM sources WHERE ip=?", (value,))
    if not stage and not src:
        return None

    profile = dict(stage or {})
    for k in ("first_seen", "last_seen", "country", "city", "asn", "as_org"):
        if src and src.get(k) is not None and not profile.get(k):
            profile[k] = src[k]
    if profile.get("asn") is not None and "AS" not in str(profile["asn"]):
        profile["asn"] = f"AS{profile['asn']}"
    profile.pop("lat", None)
    profile.pop("lon", None)

    timeseries = db.qall(
        con,
        "SELECT day, events, sessions, commands, downloads + uploads AS transfers"
        " FROM asn_ip_daily WHERE src_ip=? AND day>=? ORDER BY day",
        (value, cut),
    )
    sessions = db.qall(
        con,
        "SELECT session, first_seen, last_seen, day, username, commands,"
        " downloads, uploads, tunnels, duration FROM session_facts"
        " WHERE src_ip=? AND day>=? ORDER BY last_seen DESC LIMIT 50",
        (value, cut),
    )
    credentials = db.qall(
        con,
        "SELECT username, password, SUM(attempts) attempts,"
        " SUM(successes) successes, MIN(day) first_day, MAX(day) last_day"
        " FROM cred_ip_daily WHERE src_ip=? AND day>=?"
        " GROUP BY username, password ORDER BY attempts DESC LIMIT 25",
        (value, cut),
    ) if db.table_exists(con, "cred_ip_daily") else []
    fingerprints = db.qall(
        con,
        "SELECT hassh, SUM(events) events, SUM(sessions) sessions,"
        " MIN(day) first_day, MAX(day) last_day FROM hassh_ip_daily"
        " WHERE src_ip=? AND day>=? GROUP BY hassh"
        " ORDER BY events DESC LIMIT 10",
        (value, cut),
    ) if db.table_exists(con, "hassh_ip_daily") else []
    for f in fingerprints:
        rec = hassh_describe(f["hassh"])
        f["known_as"] = rec["label"] if rec else None
        f["known_kind"] = rec["kind"] if rec else None
    samples = db.qall(
        con,
        "SELECT shasum, url, direction, COUNT(*) sightings, MAX(ts) last_ts"
        " FROM payload_sightings WHERE src_ip=? AND shasum<>''"
        " GROUP BY shasum, url, direction ORDER BY last_ts DESC LIMIT 25",
        (value,),
    )
    commands = db.qall(
        con,
        "SELECT ts, json_extract(payload,'$.input') cmd FROM v_events"
        " WHERE src_ip=? AND eventid='cowrie.command.input'"
        " ORDER BY ts DESC LIMIT 30",
        (value,),
    )
    return {
        "profile": profile,
        "timeseries": timeseries,
        "related": {
            "sessions": sessions,
            "credentials": credentials,
            "fingerprints": fingerprints,
            "samples": samples,
            "commands": commands,
        },
    }


def asn_entity(con, value, days):
    m = ASN_RE.match(value)
    if not m:
        raise BadEntity("not an AS number")
    number = m.group(1)
    label = f"AS{number}"
    # source_stage carries the number as enrichment left it; asn_ip_daily
    # carries the AS-prefixed label. Match both spellings everywhere.
    forms = (label, number)
    cut = _cut_day(con, days)

    profile = db.qone(
        con,
        "SELECT COUNT(*) addresses, MAX(stage) max_stage, SUM(sessions) sessions,"
        " SUM(events) events, SUM(transfers) transfers, MAX(org) org,"
        " MIN(first_seen) first_seen, MAX(last_seen) last_seen"
        " FROM source_stage WHERE asn IN (?, ?)",
        forms,
    )
    if not profile or not profile.get("addresses"):
        return None
    countries = db.qall(
        con,
        "SELECT country, COUNT(*) addresses FROM source_stage WHERE asn IN (?, ?)"
        " AND country IS NOT NULL GROUP BY country ORDER BY addresses DESC LIMIT 6",
        forms,
    )
    profile["countries"] = ", ".join(
        f"{c['country']} ({c['addresses']})" for c in countries) or None

    timeseries = db.qall(
        con,
        "SELECT day, SUM(events) events, SUM(sessions) sessions,"
        " COUNT(DISTINCT src_ip) addresses FROM asn_ip_daily"
        " WHERE asn IN (?, ?) AND day>=? GROUP BY day ORDER BY day",
        (label, number, cut),
    )
    ips = db.qall(
        con,
        "SELECT src_ip, stage, sessions, events, commands, transfers,"
        " country, last_seen FROM source_stage WHERE asn IN (?, ?)"
        " ORDER BY stage DESC, sessions DESC LIMIT 50",
        forms,
    )
    return {
        "value": label,
        "profile": profile,
        "timeseries": timeseries,
        "related": {"ips": ips},
    }


def day_entity(con, value, days):
    if not DAY_RE.match(value):
        raise BadEntity("not a date")
    try:
        d = dt.date.fromisoformat(value)
    except ValueError:
        raise BadEntity("not a date")

    profile = db.qone(
        con,
        "SELECT SUM(events) events, COUNT(DISTINCT src_ip) addresses,"
        " SUM(sessions) sessions, SUM(commands) commands,"
        " SUM(downloads) downloads, SUM(uploads) uploads"
        " FROM asn_ip_daily WHERE day=?",
        (value,),
    )
    if not profile or profile.get("events") is None:
        return None
    spike = db.qone(
        con,
        "SELECT day, events, baseline, ratio, zscore, headline"
        " FROM spike_annotations WHERE day=?",
        (value,),
    )

    lo = (d - dt.timedelta(days=14)).isoformat()
    hi = (d + dt.timedelta(days=14)).isoformat()
    timeseries = db.qall(
        con,
        "SELECT day, SUM(events) events, SUM(sessions) sessions"
        " FROM asn_ip_daily WHERE day>=? AND day<=? GROUP BY day ORDER BY day",
        (lo, hi),
    )
    ips = db.qall(
        con,
        "SELECT d.src_ip, d.stage, d.sessions, d.commands, d.transfers,"
        " s.asn, s.org, s.country FROM source_stage_daily d"
        " LEFT JOIN source_stage s ON s.src_ip=d.src_ip WHERE d.day=?"
        " ORDER BY d.stage DESC, d.sessions DESC LIMIT 25",
        (value,),
    )
    eventids = db.qall(
        con,
        "SELECT eventid, events FROM eventid_daily WHERE day=?"
        " ORDER BY events DESC LIMIT 15",
        (value,),
    )
    credentials = db.qall(
        con,
        "SELECT username, password, attempts, successes, src_ips"
        " FROM cred_pair_daily WHERE day=? ORDER BY attempts DESC LIMIT 15",
        (value,),
    )
    payloads = db.qall(
        con,
        "SELECT shasum, url, direction, hits, sessions, src_ips"
        " FROM payload_daily WHERE day=? AND shasum<>''"
        " ORDER BY hits DESC LIMIT 25",
        (value,),
    )
    file_sessions = db.qall(
        con,
        "SELECT session, src_ip, first_seen, username, commands, downloads,"
        " uploads FROM session_facts WHERE day=? AND (downloads>0 OR uploads>0)"
        " ORDER BY first_seen LIMIT 25",
        (value,),
    )
    profile["spike"] = spike
    return {
        "profile": profile,
        "timeseries": timeseries,
        "related": {
            "ips": ips,
            "eventids": eventids,
            "credentials": credentials,
            "payloads": payloads,
            "file_sessions": file_sessions,
        },
    }


def credential_entity(con, value, days):
    pair = decode_token(value)
    if "\x00" not in pair:
        raise BadEntity("bad credential id")
    username, password = pair.split("\x00", 1)
    cut = _cut_day(con, days)

    profile = db.qone(
        con,
        "SELECT attempts, successes, distinct_ips, first_seen, last_seen"
        " FROM cred_pairs WHERE username=? AND password=?",
        (username, password),
    )
    if not profile:
        return None
    profile["username"] = username
    profile["password"] = password
    tags = db.qall(
        con,
        "SELECT tag FROM cred_pair_tags WHERE username=? AND password=?",
        (username, password),
    )
    profile["tags"] = [t["tag"] for t in tags]

    timeseries = db.qall(
        con,
        "SELECT day, attempts AS events, src_ips FROM cred_pair_daily"
        " WHERE username=? AND password=? AND day>=? ORDER BY day",
        (username, password, cut),
    )
    ips = db.qall(
        con,
        "SELECT c.src_ip, SUM(c.attempts) attempts, SUM(c.successes) successes,"
        " MIN(c.day) first_day, MAX(c.day) last_day,"
        " s.stage, s.asn, s.org, s.country"
        " FROM cred_ip_daily c LEFT JOIN source_stage s ON s.src_ip=c.src_ip"
        " WHERE c.username=? AND c.password=?"
        " GROUP BY c.src_ip ORDER BY attempts DESC LIMIT 50",
        (username, password),
    ) if db.table_exists(con, "cred_ip_daily") else []
    return {
        "profile": profile,
        "timeseries": timeseries,
        "related": {"ips": ips},
    }


def hassh_entity(con, value, days):
    if not HASSH_RE.match(value):
        raise BadEntity("not a fingerprint")
    cut = _cut_day(con, days)

    profile = db.qone(
        con,
        "SELECT MAX(version) version, SUM(events) events, SUM(sessions) sessions,"
        " MAX(src_ips) peak_daily_ips, MIN(day) first_seen, MAX(day) last_seen,"
        " COUNT(*) active_days FROM client_fp_daily WHERE hassh=?",
        (value,),
    )
    if not profile or not profile.get("events"):
        return None
    rec = hassh_describe(value)
    profile["known_as"] = rec["label"] if rec else None
    profile["known_kind"] = rec["kind"] if rec else None
    profile["known_note"] = rec["note"] if rec else None

    timeseries = db.qall(
        con,
        "SELECT day, events, sessions, src_ips FROM client_fp_daily"
        " WHERE hassh=? AND day>=? ORDER BY day",
        (value, cut),
    )
    ips = db.qall(
        con,
        "SELECT h.src_ip, SUM(h.events) events, SUM(h.sessions) sessions,"
        " MIN(h.day) first_day, MAX(h.day) last_day,"
        " s.stage, s.asn, s.org, s.country"
        " FROM hassh_ip_daily h LEFT JOIN source_stage s ON s.src_ip=h.src_ip"
        " WHERE h.hassh=? GROUP BY h.src_ip ORDER BY events DESC LIMIT 50",
        (value,),
    ) if db.table_exists(con, "hassh_ip_daily") else []
    return {
        "profile": profile,
        "timeseries": timeseries,
        "related": {"ips": ips},
    }


def url_entity(con, value, days):
    url = decode_token(value)
    cut = _cut_day(con, days)

    profile = db.qone(
        con,
        "SELECT MAX(host) host, SUM(hits) hits, SUM(sessions) sessions,"
        " SUM(src_ips) src_ips, MIN(first_seen) first_seen,"
        " MAX(last_seen) last_seen, COUNT(DISTINCT shasum) distinct_hashes"
        " FROM payloads WHERE url=?",
        (url,),
    )
    if not profile or not profile.get("hits"):
        return None
    profile["url"] = url

    indicators = [url] + ([profile["host"]] if profile.get("host") else [])
    marks = ",".join("?" for _ in indicators)
    intel = db.qall(
        con,
        f"SELECT indicator, kind, source, verdict, label, reference, checked_at"
        f" FROM payload_intel WHERE indicator IN ({marks})",
        tuple(indicators),
    )
    timeseries = db.qall(
        con,
        "SELECT day, SUM(hits) events, SUM(sessions) sessions FROM payload_daily"
        " WHERE url=? AND day>=? GROUP BY day ORDER BY day",
        (url, cut),
    )
    samples = db.qall(
        con,
        "SELECT shasum, direction, filename, hits, first_seen, last_seen"
        " FROM payloads WHERE url=? AND shasum<>'' ORDER BY hits DESC LIMIT 25",
        (url,),
    )
    sightings = db.qall(
        con,
        "SELECT ts, session, src_ip, shasum, direction FROM payload_sightings"
        " WHERE url=? ORDER BY ts DESC LIMIT 50",
        (url,),
    )
    return {
        "profile": profile,
        "intel": intel,
        "timeseries": timeseries,
        "related": {"samples": samples, "sightings": sightings},
    }


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

HANDLERS = {
    "ip": ip_entity,
    "asn": asn_entity,
    "day": day_entity,
    "credential": credential_entity,
    "hassh": hassh_entity,
    "url": url_entity,
}


def lookup(con, etype, value, days=30):
    """One entry point for the router. Returns the entity payload, or None
    for a well-formed value never seen. Raises BadEntity on malformed input
    and KeyError on an unknown type."""
    handler = HANDLERS[etype]
    out = handler(con, str(value or ""), days)
    if out is None:
        return None
    out.setdefault("type", etype)
    out.setdefault("value", value)
    out.setdefault("window_days", db.clamp_days(days, default=30))
    return out
