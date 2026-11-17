"""One collector per source in docs/trends/SOURCES.md.

Each source has a parse step, which turns a response body into plain dicts
and is what the tests exercise, and a store step, which writes them. A dry
run fetches and parses and stops before the store step.
"""

import datetime as dt
import email.utils
import json
import os
import re
import xml.etree.ElementTree as ET

from app.analytics import db
from app.trends import TRACK_FROM, classify, item_hash, store

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def _day(value):
    """An RSS or ISO date as YYYY-MM-DD, or None."""
    if not value:
        return None
    v = value.strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}", v):
        return v[:10]
    try:
        return email.utils.parsedate_to_datetime(v).astimezone(dt.timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return None


def parse_rss(body):
    """RSS 2.0 items as dicts.

    A feed with a document type declaration is refused before parsing. RSS
    has no use for one, and refusing it closes the entity-expansion and
    external-entity attacks bandit's B314 warns about, which is what
    defusedxml would do; the collectors stay on the standard library.
    """
    if re.search(rb"<!(DOCTYPE|ENTITY)", body, re.I):
        raise ValueError("feed carries a document type declaration")
    root = ET.fromstring(body)  # nosec B314
    out = []
    for it in root.iter("item"):
        link = (it.findtext("link") or "").strip()
        if not link.startswith("https://"):
            continue
        out.append({
            "url": link,
            "title": (it.findtext("title") or "").strip()[:300],
            "published": _day(it.findtext("pubDate")),
            "categories": ", ".join(c.text.strip() for c in it.findall("category") if c.text)[:200],
        })
    return out


def parse_kev(body):
    data = json.loads(body)
    out = []
    for v in data.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").upper()
        if CVE_RE.fullmatch(cid):
            out.append({"cve_id": cid, "vendor": v.get("vendorProject"),
                        "product": v.get("product"), "kev_added": _day(v.get("dateAdded")),
                        "ransomware_use": v.get("knownRansomwareCampaignUse")})
    return out


def parse_claims(body):
    """ransomware.live victims, US only. The API's field names are read
    leniently because they were not confirmed against its documentation."""
    data = json.loads(body)
    rows = data.get("victims", data.get("data", data)) if isinstance(data, dict) else data
    out = []
    for v in rows if isinstance(rows, list) else []:
        if not isinstance(v, dict):
            continue
        country = (v.get("country") or "").upper()
        victim = (v.get("victim") or v.get("post_title") or v.get("name") or "").strip()
        actor = (v.get("group") or v.get("group_name") or "").strip()
        if country != "US" or not victim or not actor:
            continue
        post = v.get("url") or v.get("post_url") or v.get("permalink")
        out.append({"actor": actor[:120], "victim": victim[:200], "country": country,
                    "discovered": _day(v.get("discovered") or v.get("attackdate")),
                    "post_url": post if isinstance(post, str) and post.startswith("https://") else None})
    return out


SOURCES = {
    "cisa-kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        # The whole catalog in one file: 1.85 MB in November 2026 and growing.
        "parse": parse_kev, "every_hours": 6, "max_bytes": 8 * 1024 * 1024,
    },
    "cisa-advisories": {
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        # Items carry full advisory bodies, so the feed is over 2 MB.
        "parse": parse_rss, "every_hours": 6, "max_bytes": 8 * 1024 * 1024,
    },
    "dysruptionhub": {
        "url": "https://dysruptionhub.com/feed/",
        "parse": parse_rss, "every_hours": 2,
    },
    "ransomware-live": {
        # Path and header to be confirmed against the api-pro documentation
        # before the token is installed. Without a token the source is skipped.
        "url": "https://api-pro.ransomware.live" + os.environ.get("TR_RLIVE_PATH", "/victims/recent"),
        "parse": parse_claims, "every_hours": 1,
        "token_env": "TR_RANSOMWARE_LIVE_TOKEN",
        "header": os.environ.get("TR_RLIVE_HEADER", "X-API-KEY"),
    },
}


def _known_orgs(con):
    rows = db.qall(con, "SELECT id, name FROM organization WHERE length(name) >= 6")
    return [(r["id"], r["name"].lower()) for r in rows]


def match_incident(con, title, day, orgs, window_days=21):
    """The newest incident at an organization named in the title, started
    within window_days before day. None when no known name appears."""
    t = (title or "").lower()
    ids = [oid for oid, name in orgs if name in t]
    if not ids or not day:
        return None
    lo = (dt.date.fromisoformat(day) - dt.timedelta(days=window_days)).isoformat()
    for oid in ids:
        row = con.execute("SELECT id FROM incident WHERE organization_id=? AND started BETWEEN ? AND ? "
                          "ORDER BY started DESC LIMIT 1", (oid, lo, day)).fetchone()
        if row:
            return row[0]
    return None


def store_kev(con, rows):
    n = 0
    for r in rows:
        cur = con.execute("INSERT INTO cve(cve_id, vendor, product, kev_added, ransomware_use) "
                          "VALUES(?,?,?,?,?) ON CONFLICT(cve_id) DO NOTHING",
                          (r["cve_id"], r["vendor"], r["product"], r["kev_added"], r["ransomware_use"]))
        n += cur.rowcount
    return n


def store_items(con, source, rows, use_model, opens_incidents, seed_until):
    """Classify and store feed items. Answer the number of new items."""
    items = [dict(r, source=source, item_hash=item_hash(source, r["url"]),
                  text=f"{r['title']}. {r.get('categories') or ''}") for r in rows]
    known = {r[0] for r in con.execute(
        "SELECT item_hash FROM source_item WHERE source=?", (source,))}
    fresh = [i for i in items if i["item_hash"] not in known]
    labels = classify.classify_items(con, fresh, use_model=use_model)
    orgs = _known_orgs(con) if opens_incidents else []
    for it in fresh:
        status, method = labels[it["item_hash"]]
        conf = "medium" if method == "keyword" else "low"
        sid, _ = store.source_item(con, dict(it, status=status, method=method, confidence=conf))
        if not opens_incidents or not it["published"]:
            continue
        iid = match_incident(con, it["title"], it["published"], orgs)
        if iid is None and it["published"] >= TRACK_FROM and it["published"] > seed_until:
            iid = store.incident(con, kind="org", title=it["title"], started=it["published"],
                                 cause_status=status, source=source, confidence=conf,
                                 source_item_id=sid)
        if iid is None:
            continue
        store.statement(con, iid, sid, status, it["published"], it["title"])
        for cid in {c.upper() for c in CVE_RE.findall(it["title"])}:
            con.execute("INSERT INTO incident_cve(incident_id, cve_id) SELECT ?, cve_id FROM cve "
                        "WHERE cve_id=? ON CONFLICT DO NOTHING", (iid, cid))
    return len(fresh)


def store_claims(con, rows):
    n = 0
    orgs = _known_orgs(con)
    for r in rows:
        h = item_hash("ransomware-live", f"{r['actor']}\x00{r['victim']}\x00{r['discovered']}")
        cur = con.execute(
            "INSERT INTO actor_claim(claim_hash, actor, victim, country, discovered, post_url, source) "
            "VALUES(?,?,?,?,?,?,'ransomware-live') ON CONFLICT(claim_hash) DO NOTHING",
            (h, r["actor"], r["victim"], r["country"], r["discovered"], r["post_url"]))
        n += cur.rowcount
        if cur.rowcount and r["discovered"]:
            iid = match_incident(con, r["victim"], r["discovered"], orgs, window_days=45)
            if iid:
                con.execute("INSERT INTO incident_claim(incident_id, claim_id) VALUES(?,?) "
                            "ON CONFLICT DO NOTHING", (iid, cur.lastrowid))
    return n
