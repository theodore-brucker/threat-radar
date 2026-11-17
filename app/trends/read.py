"""Read side of incident trends, for the router and the export.

Every list a page draws carries the incident ids behind it, and rows() turns
any such list back into the rows themselves.
"""

import json
import re

from app.analytics import db
from app.trends import STATUS_LABEL, marks

MAX_ROWS = 500
SLUG_RE = re.compile(r"^[a-z0-9-]{1,80}$")


class BadValue(ValueError):
    pass


def built(con):
    return db.table_exists(con, "trend_meta") and db.qone(
        con, "SELECT value FROM trend_meta WHERE key='built_at'") is not None


def _meta(con):
    return {r["key"]: r["value"] for r in db.qall(con, "SELECT key, value FROM trend_meta")}


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def summary(con):
    m = _meta(con)
    weeks = db.qall(con, "SELECT * FROM trend_weekly ORDER BY week")
    for w in weeks:
        w["ids"] = json.loads(w["ids"])
        w["undisclosed_ids"] = json.loads(w["undisclosed_ids"])
        w["share_undisclosed"] = (w["undisclosed"] / w["incidents"]) if w["incidents"] else None
    delays = db.qall(con, """SELECT d.*, i.title FROM trend_cause_delay d
                              JOIN incident i ON i.id = d.incident_id ORDER BY d.started""")
    fan = db.qall(con, """SELECT f.*, v.slug AS vendor_slug, v.name AS vendor, v.product,
                                 i.title, i.cause_status
                            FROM trend_fanout f JOIN vendor v ON v.id = f.vendor_id
                            JOIN incident i ON i.id = f.incident_id ORDER BY f.started DESC""")
    for f in fan:
        f["ids"] = json.loads(f["ids"])
    clusters = db.qall(con, "SELECT * FROM trend_cluster ORDER BY first_day DESC")
    for c in clusters:
        c["ids"] = json.loads(c["ids"])
    national = db.qall(con, """SELECT id, title, started, scope, cause_status FROM incident
                               WHERE kind='national' ORDER BY started DESC, id DESC""")
    full = [w for w in weeks if not w["partial"]]
    return {
        "built_at": m.get("built_at"),
        "slope_per_week": _float(m.get("slope")),
        "weeks": weeks,
        "delays": delays,
        "fanouts": fan,
        "clusters": clusters,
        "national": national,
        "totals": {
            "incidents": sum(w["incidents"] for w in weeks),
            "ids": [i for w in weeks for i in w["ids"]],
            "undisclosed": sum(w["undisclosed"] for w in weeks),
            "undisclosed_ids": [i for w in weeks for i in w["undisclosed_ids"]],
            "full_weeks": len(full),
        },
        "status_labels": STATUS_LABEL,
    }


def parse_ids(text):
    try:
        ids = sorted({int(x) for x in (text or "").split(",") if x.strip()})
    except ValueError as exc:
        raise BadValue("ids must be a comma-separated list of numbers") from exc
    if len(ids) > MAX_ROWS:
        raise BadValue(f"at most {MAX_ROWS} ids at a time")
    return ids


def rows(con, ids):
    if not ids:
        return []
    return db.qall(con, f"""
        SELECT i.id, i.kind, i.title, i.started, i.state, i.sector, i.scope, i.cause_status,
               i.source, i.confidence, o.slug AS org_slug, o.name AS org_name, s.url AS source_url
          FROM incident i LEFT JOIN organization o ON o.id = i.organization_id
          LEFT JOIN source_item s ON s.id = i.source_item_id
         WHERE i.id IN ({marks(len(ids))}) ORDER BY i.started DESC, i.id DESC""", ids)


def incident(con, value):
    try:
        iid = int(value)
    except (TypeError, ValueError) as exc:
        raise BadValue("an incident id is a number") from exc
    found = rows(con, [iid])
    if not found:
        return None
    inc = found[0]
    inc["statements"] = db.qall(con, """
        SELECT st.stated_at, st.cause_status, st.text, s.source, s.url, s.title
          FROM statement st LEFT JOIN source_item s ON s.id = st.source_item_id
         WHERE st.incident_id = ? ORDER BY st.stated_at IS NULL, st.stated_at""", (iid,))
    inc["vendors"] = db.qall(con, """
        SELECT v.slug, v.name, v.product, iv.customers, iv.note FROM incident_vendor iv
          JOIN vendor v ON v.id = iv.vendor_id WHERE iv.incident_id = ?""", (iid,))
    inc["cves"] = db.qall(con, """SELECT c.* FROM incident_cve ic JOIN cve c ON c.cve_id = ic.cve_id
                                  WHERE ic.incident_id = ?""", (iid,))
    # Group name and link only: ransomware.live's terms do not allow
    # republishing its raw records.
    inc["claims"] = db.qall(con, """SELECT a.actor, a.discovered, a.post_url FROM incident_claim ic
                                    JOIN actor_claim a ON a.id = ic.claim_id WHERE ic.incident_id = ?""",
                            (iid,))
    inc["delay"] = db.qone(con, "SELECT days, first_cause_at FROM trend_cause_delay WHERE incident_id=?",
                           (iid,))
    return inc


def _slug(value):
    if not SLUG_RE.match(value or ""):
        raise BadValue("a name in a link is lower-case letters, digits and hyphens")
    return value


def vendor(con, value):
    v = db.qone(con, "SELECT * FROM vendor WHERE slug=?", (_slug(value),))
    if v is None:
        return None
    ids = [r["incident_id"] for r in db.qall(
        con, "SELECT incident_id FROM incident_vendor WHERE vendor_id=?", (v["id"],))]
    v["incidents"] = rows(con, ids)
    v["links"] = db.qall(con, """SELECT incident_id, customers, note FROM incident_vendor
                                 WHERE vendor_id=?""", (v["id"],))
    return v


def organization(con, value):
    o = db.qone(con, "SELECT * FROM organization WHERE slug=?", (_slug(value),))
    if o is None:
        return None
    ids = [r["id"] for r in db.qall(con, "SELECT id FROM incident WHERE organization_id=?", (o["id"],))]
    o["incidents"] = rows(con, ids)
    return o


HANDLERS = {"incident": incident, "vendor": vendor, "organization": organization}


def lookup(con, etype, value):
    return HANDLERS[etype](con, value)
