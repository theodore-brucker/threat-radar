"""Write helpers for the trends worker. Every insert is keyed so a rerun of
the same input changes nothing."""

from app.analytics import db
from app.trends import slugify


def organization(con, name, state=None, sector=None):
    slug = slugify(name)
    con.execute("INSERT INTO organization(slug, name, state, sector) VALUES(?,?,?,?) "
                "ON CONFLICT(slug) DO NOTHING", (slug, name, state, sector))
    return con.execute("SELECT id FROM organization WHERE slug=?", (slug,)).fetchone()[0]


def vendor(con, name, product=None):
    slug = slugify(name)
    con.execute("INSERT INTO vendor(slug, name, product) VALUES(?,?,?) "
                "ON CONFLICT(slug) DO NOTHING", (slug, name, product))
    return con.execute("SELECT id FROM vendor WHERE slug=?", (slug,)).fetchone()[0]


def source_item(con, item):
    """Insert one item. Answer (id, new)."""
    cur = con.execute(
        "INSERT INTO source_item(item_hash, source, url, title, published, categories, "
        "status, method, confidence, fetched_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(item_hash) DO NOTHING",
        (item["item_hash"], item["source"], item.get("url"), item.get("title"),
         item.get("published"), item.get("categories"), item.get("status"),
         item.get("method"), item.get("confidence", "low"), db.utcnow()))
    row = con.execute("SELECT id FROM source_item WHERE item_hash=?",
                      (item["item_hash"],)).fetchone()
    return row[0], cur.rowcount == 1


def incident(con, **f):
    """Insert an incident once per source item. Answer its id."""
    if f.get("source_item_id") is not None:
        row = con.execute("SELECT id FROM incident WHERE source_item_id=?",
                          (f["source_item_id"],)).fetchone()
        if row:
            return row[0]
    cur = con.execute(
        "INSERT INTO incident(kind, title, started, organization_id, state, sector, scope, "
        "cause_status, source, confidence, source_item_id, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (f["kind"], f["title"], f["started"], f.get("organization_id"), f.get("state"),
         f.get("sector"), f.get("scope"), f["cause_status"], f["source"],
         f.get("confidence", "low"), f.get("source_item_id"), db.utcnow()))
    return cur.lastrowid


def statement(con, incident_id, source_item_id, cause_status, stated_at=None, text=None):
    con.execute(
        "INSERT INTO statement(incident_id, source_item_id, stated_at, cause_status, text) "
        "VALUES(?,?,?,?,?) ON CONFLICT(incident_id, source_item_id) DO NOTHING",
        (incident_id, source_item_id, stated_at, cause_status, text))


def link_vendor(con, incident_id, vendor_id, customers=None, note=None):
    con.execute(
        "INSERT INTO incident_vendor(incident_id, vendor_id, role, customers, note) "
        "VALUES(?,?,'supplier',?,?) ON CONFLICT(incident_id, vendor_id) DO NOTHING",
        (incident_id, vendor_id, customers, note))
