"""Hover cards: a batch summary for every entity rendered on a page.

A page draws hundreds of entity links. Fetching a card per hover would be
chatty and would make the first hover on each link feel slow, so the page
asks once for everything it drew and hovering is then instant and free.

One query per entity type, not per entity: the values arrive grouped and
each group becomes a single IN lookup against the fact table that already
holds the summary. Nothing here reads raw_events.
"""

from . import db
from .entities import (ASN_RE, DAY_RE, HASSH_RE, IP_RE, BadEntity,
                       decode_token)
from .fingerprints import describe as hassh_describe

# SQLite's default host-parameter ceiling is 999 on older builds. Chunk well
# under it rather than discovering the limit on a busy page.
CHUNK = 300
MAX_ITEMS = 600


def _chunks(seq):
    for i in range(0, len(seq), CHUNK):
        yield seq[i:i + CHUNK]


def _marks(n):
    return ",".join("?" for _ in range(n))


def _card(title, sub=None, facts=None, tone=None):
    return {"title": title, "sub": sub,
            "facts": [[k, v] for k, v in (facts or []) if v not in (None, "")],
            "tone": tone}


# ---------------------------------------------------------------------------
# per-type batch builders: (con, [values]) -> {value: card}
# ---------------------------------------------------------------------------

def _ips(con, values):
    out = {}
    vals = [v for v in values if IP_RE.match(v)]
    for part in _chunks(vals):
        for r in db.qall(
            con,
            f"SELECT src_ip, stage, sessions, events, commands, transfers,"
            f" first_seen, last_seen, asn, org, country FROM source_stage"
            f" WHERE src_ip IN ({_marks(len(part))})",
            tuple(part),
        ):
            from .escalation import STAGES
            stage = int(r["stage"] or 0)
            label = STAGES[stage]["label"] if stage < len(STAGES) else str(stage)
            out[r["src_ip"]] = _card(
                r["src_ip"],
                " · ".join(x for x in (r["org"], r["country"]) if x),
                [("reached", label),
                 ("sessions", r["sessions"]),
                 ("events", r["events"]),
                 ("commands", r["commands"]),
                 ("files moved", r["transfers"]),
                 ("first seen", (r["first_seen"] or "")[:10]),
                 ("last seen", (r["last_seen"] or "")[:10])],
                tone="bad" if stage >= 3 else "warn" if stage == 2 else None,
            )
    return out


def _asns(con, values):
    out = {}
    wanted = {}
    for v in values:
        m = ASN_RE.match(v)
        if m:
            wanted.setdefault(m.group(1), set()).add(v)
    if not wanted:
        return out
    # source_stage stores either spelling depending on enrichment vintage
    forms = []
    for num in wanted:
        forms.extend((num, f"AS{num}"))
    rows = {}
    for part in _chunks(forms):
        for r in db.qall(
            con,
            f"SELECT asn, MAX(org) org, COUNT(*) addresses, MAX(stage) max_stage,"
            f" SUM(sessions) sessions, SUM(events) events,"
            f" MIN(first_seen) first_seen, MAX(last_seen) last_seen"
            f" FROM source_stage WHERE asn IN ({_marks(len(part))}) GROUP BY asn",
            tuple(part),
        ):
            key = str(r["asn"]).lstrip("AS")
            prev = rows.get(key)
            if prev:  # both spellings present, merge
                r["addresses"] += prev["addresses"]
                r["sessions"] = (r["sessions"] or 0) + (prev["sessions"] or 0)
                r["events"] = (r["events"] or 0) + (prev["events"] or 0)
                r["max_stage"] = max(r["max_stage"] or 0, prev["max_stage"] or 0)
            rows[key] = r
    for num, spellings in wanted.items():
        r = rows.get(num)
        if not r:
            continue
        card = _card(
            f"AS{num}", r["org"],
            [("addresses seen", r["addresses"]),
             ("sessions", r["sessions"]),
             ("events", r["events"]),
             ("furthest any reached", r["max_stage"]),
             ("first seen", (r["first_seen"] or "")[:10]),
             ("last seen", (r["last_seen"] or "")[:10])],
        )
        for s in spellings:
            out[s] = card
    return out


def _credentials(con, values):
    out = {}
    decoded = {}
    for v in values:
        try:
            pair = decode_token(v)
        except BadEntity:
            continue
        if "\x00" in pair:
            decoded[v] = tuple(pair.split("\x00", 1))
    if not decoded:
        return out
    pairs = list({p for p in decoded.values()})
    found = {}
    for part in _chunks(pairs):
        clause = " OR ".join("(username=? AND password=?)" for _ in part)
        args = tuple(x for p in part for x in p)
        for r in db.qall(
            con,
            "SELECT username, password, attempts, successes, distinct_ips,"
            f" first_seen, last_seen FROM cred_pairs WHERE {clause}",
            args,
        ):
            found[(r["username"], r["password"])] = r
    for token, pair in decoded.items():
        r = found.get(pair)
        if not r:
            continue
        out[token] = _card(
            f"{r['username'] or '(blank)'}:{r['password'] or '(blank)'}",
            "credential pair",
            [("attempts", r["attempts"]),
             ("succeeded", r["successes"]),
             ("distinct addresses", r["distinct_ips"]),
             ("first seen", (r["first_seen"] or "")[:10]),
             ("last seen", (r["last_seen"] or "")[:10])],
            tone="bad" if r["successes"] else None,
        )
    return out


def _hasshes(con, values):
    out = {}
    vals = [v for v in values if HASSH_RE.match(v)]
    for part in _chunks(vals):
        for r in db.qall(
            con,
            f"SELECT hassh, MAX(version) version, SUM(events) events,"
            f" SUM(sessions) sessions, MIN(day) first_seen, MAX(day) last_seen,"
            f" COUNT(*) active_days FROM client_fp_daily"
            f" WHERE hassh IN ({_marks(len(part))}) GROUP BY hassh",
            tuple(part),
        ):
            out[r["hassh"]] = _card(
                r["hassh"][:16] + "…",
                (hassh_describe(r["hassh"]) or {}).get("label")
                or r["version"] or "client fingerprint",
                [("events", r["events"]),
                 ("sessions", r["sessions"]),
                 ("active days", r["active_days"]),
                 ("first seen", r["first_seen"]),
                 ("last seen", r["last_seen"])],
            )
    return out


def _urls(con, values):
    out = {}
    decoded = {}
    for v in values:
        try:
            decoded[v] = decode_token(v)
        except BadEntity:
            continue
    if not decoded:
        return out
    urls = list(set(decoded.values()))
    found, verdicts = {}, {}
    for part in _chunks(urls):
        for r in db.qall(
            con,
            f"SELECT url, MAX(host) host, SUM(hits) hits, SUM(sessions) sessions,"
            f" COUNT(DISTINCT shasum) hashes, MIN(first_seen) first_seen,"
            f" MAX(last_seen) last_seen FROM payloads"
            f" WHERE url IN ({_marks(len(part))}) GROUP BY url",
            tuple(part),
        ):
            found[r["url"]] = r
        for r in db.qall(
            con,
            f"SELECT indicator, verdict, label FROM payload_intel"
            f" WHERE indicator IN ({_marks(len(part))})",
            tuple(part),
        ):
            verdicts[r["indicator"]] = r
    for token, url in decoded.items():
        r = found.get(url)
        if not r:
            continue
        vt = verdicts.get(url)
        out[token] = _card(
            r["host"] or url[:40], "fetch url",
            [("standing", vt["verdict"] if vt else None),
             ("family", vt["label"] if vt else None),
             ("fetches", r["hits"]),
             ("distinct files", r["hashes"]),
             ("first seen", (r["first_seen"] or "")[:10]),
             ("last seen", (r["last_seen"] or "")[:10])],
            tone="bad" if vt and vt["verdict"] in ("malicious", "suspicious") else None,
        )
    return out


def _days(con, values):
    out = {}
    vals = [v for v in values if DAY_RE.match(v)]
    spikes = {}
    for part in _chunks(vals):
        for r in db.qall(
            con,
            f"SELECT day, SUM(events) events, COUNT(DISTINCT src_ip) addresses,"
            f" SUM(sessions) sessions, SUM(downloads + uploads) transfers"
            f" FROM asn_ip_daily WHERE day IN ({_marks(len(part))}) GROUP BY day",
            tuple(part),
        ):
            out[r["day"]] = r
        if db.table_exists(con, "spike_annotations"):
            for r in db.qall(
                con,
                f"SELECT day, ratio FROM spike_annotations"
                f" WHERE day IN ({_marks(len(part))})",
                tuple(part),
            ):
                spikes[r["day"]] = r["ratio"]
    return {
        day: _card(
            day, "one day of telemetry",
            [("events", r["events"]),
             ("addresses", r["addresses"]),
             ("sessions", r["sessions"]),
             ("files moved", r["transfers"]),
             ("spike", f"{float(spikes[day]):.1f}x baseline" if day in spikes else None)],
            tone="warn" if day in spikes else None,
        )
        for day, r in out.items()
    }


def _sessions(con, values):
    out = {}
    for part in _chunks(list(values)):
        for r in db.qall(
            con,
            f"SELECT session, src_ip, day, username, commands, downloads,"
            f" uploads, duration FROM session_facts"
            f" WHERE session IN ({_marks(len(part))})",
            tuple(part),
        ):
            files = (r["downloads"] or 0) + (r["uploads"] or 0)
            out[r["session"]] = _card(
                r["session"], f"{r['src_ip']} on {r['day']}",
                [("authenticated as", r["username"]),
                 ("commands", r["commands"]),
                 ("files moved", files),
                 ("duration", f"{float(r['duration']):.0f}s" if r["duration"] else None)],
                tone="bad" if files else None,
            )
    return out


def _samples(con, values):
    out = {}
    rows, verdicts = {}, {}
    for part in _chunks(list(values)):
        for r in db.qall(
            con,
            f"SELECT shasum, MAX(filename) filename, SUM(hits) hits,"
            f" COUNT(DISTINCT url) urls, MIN(first_seen) first_seen,"
            f" MAX(last_seen) last_seen FROM payloads"
            f" WHERE shasum IN ({_marks(len(part))}) GROUP BY shasum",
            tuple(part),
        ):
            rows[r["shasum"]] = r
        for r in db.qall(
            con,
            f"SELECT indicator, verdict, label, malicious FROM payload_intel"
            f" WHERE kind='sha256' AND indicator IN ({_marks(len(part))})",
            tuple(part),
        ):
            verdicts[r["indicator"]] = r
    for sha, r in rows.items():
        vt = verdicts.get(sha)
        out[sha] = _card(
            sha[:16] + "…", r["filename"] or "captured file",
            [("standing", vt["verdict"] if vt else "not looked up"),
             ("detections", vt["malicious"] if vt and vt["malicious"] else None),
             ("family", vt["label"] if vt else None),
             ("transfers", r["hits"]),
             ("source urls", r["urls"]),
             ("last seen", (r["last_seen"] or "")[:10])],
            tone="bad" if vt and vt["verdict"] in ("malicious", "suspicious") else None,
        )
    return out


BUILDERS = {
    "ip": _ips,
    "asn": _asns,
    "credential": _credentials,
    "hassh": _hasshes,
    "url": _urls,
    "day": _days,
    "session": _sessions,
    "sample": _samples,
}


def batch(con, items):
    """items: [{type, value}]. Returns {"type:value": card} for those found.

    Entities with no card are simply absent rather than an error: a link to
    something the fact tables have not caught up with should still work, it
    just will not preview.
    """
    grouped = {}
    for it in (items or [])[:MAX_ITEMS]:
        t = (it or {}).get("type")
        v = (it or {}).get("value")
        if t in BUILDERS and isinstance(v, str) and v:
            grouped.setdefault(t, set()).add(v)

    cards = {}
    for t, values in grouped.items():
        try:
            for value, card in BUILDERS[t](con, sorted(values)).items():
                cards[f"{t}:{value}"] = card
        except Exception:
            # One bad entity type should not cost the page every other card.
            continue
    return {"cards": cards, "count": len(cards)}
