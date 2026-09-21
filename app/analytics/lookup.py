"""Omnibar lookup: partial text to candidate entities.

The client resolves exact forms itself (an address, a sha256, an AS number,
a date, a hassh all have unambiguous shapes) and only calls here for text
that could mean several things: a username, a host fragment, a session
prefix, a network operator's name.

Every query is a bounded prefix or substring match against a fact table
with a LIMIT. Nothing here scans raw_events, and the whole endpoint is
capped so a one-character query cannot turn into a table scan on the Pi.
"""


from . import db

MIN_QUERY = 2
PER_KIND = 5
# Anything longer is not a search term; it is a paste accident.
MAX_QUERY = 128


def _like(q):
    """Escape LIKE wildcards so a query containing % or _ matches literally."""
    return q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search(con, q, limit=PER_KIND):
    q = (q or "").strip()
    if len(q) < MIN_QUERY:
        return {"query": q, "results": []}
    q = q[:MAX_QUERY]
    esc = _like(q)
    pre = f"{esc}%"
    mid = f"%{esc}%"
    out = []

    # addresses by prefix, ranked by how far they got
    for r in db.qall(
        con,
        "SELECT src_ip, stage, sessions, org, country FROM source_stage"
        " WHERE src_ip LIKE ? ESCAPE '\\' ORDER BY stage DESC, sessions DESC LIMIT ?",
        (pre, limit),
    ):
        out.append({
            "type": "ip", "value": r["src_ip"], "label": r["src_ip"],
            "sub": " · ".join(x for x in (r["org"], r["country"]) if x),
            "rank": 100 + (r["stage"] or 0),
        })

    # network operators by name
    for r in db.qall(
        con,
        "SELECT asn, MAX(org) org, COUNT(*) addresses FROM source_stage"
        " WHERE org LIKE ? ESCAPE '\\' AND asn IS NOT NULL"
        " GROUP BY asn ORDER BY addresses DESC LIMIT ?",
        (mid, limit),
    ):
        asn = str(r["asn"])
        out.append({
            "type": "asn", "value": asn if asn.startswith("AS") else f"AS{asn}",
            "label": r["org"] or asn,
            "sub": f"{r['addresses']} addresses",
            "rank": 80,
        })

    # usernames: the PK is (username, password) so a prefix uses the index
    for r in db.qall(
        con,
        "SELECT username, password, attempts, successes FROM cred_pairs"
        " WHERE username LIKE ? ESCAPE '\\' ORDER BY attempts DESC LIMIT ?",
        (pre, limit),
    ):
        out.append({
            "type": "credential",
            "value": {"username": r["username"], "password": r["password"]},
            "label": f"{r['username'] or '(blank)'}:{r['password'] or '(blank)'}",
            "sub": f"{r['attempts']} attempts"
                   + (f", {r['successes']} succeeded" if r["successes"] else ""),
            "rank": 70 if r["successes"] else 60,
        })

    # distribution hosts and fetch URLs
    for r in db.qall(
        con,
        "SELECT url, MAX(host) host, SUM(hits) hits FROM payloads"
        " WHERE url <> '' AND (host LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\')"
        " GROUP BY url ORDER BY hits DESC LIMIT ?",
        (mid, mid, limit),
    ):
        out.append({
            "type": "url", "value": r["url"], "label": r["url"],
            "sub": f"{r['hits']} fetches",
            "rank": 50,
        })

    # session ids by prefix
    for r in db.qall(
        con,
        "SELECT session, src_ip, day, commands, downloads + uploads AS files"
        " FROM session_facts WHERE session LIKE ? ESCAPE '\\'"
        " ORDER BY last_seen DESC LIMIT ?",
        (pre, limit),
    ):
        out.append({
            "type": "session", "value": r["session"], "label": r["session"],
            "sub": f"{r['src_ip']} on {r['day']}",
            "rank": 40,
        })

    # samples by hash prefix
    for r in db.qall(
        con,
        "SELECT DISTINCT shasum FROM payloads WHERE shasum <> ''"
        " AND shasum LIKE ? ESCAPE '\\' LIMIT ?",
        (pre, limit),
    ):
        out.append({
            "type": "sample", "value": r["shasum"], "label": r["shasum"],
            "sub": "captured file", "rank": 45,
        })

    out.sort(key=lambda r: -r["rank"])
    for r in out:
        r.pop("rank", None)
    return {"query": q, "results": out[:20]}
