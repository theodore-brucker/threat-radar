"""Load the seed files in seed/.

incidents.csv holds 214 US incidents from the DysruptionHub registry, May 4 to
November 15 2026. Their cause_status was assigned by a model from one-line
summaries, so every row loads with source=seed and confidence=low.
national.csv holds national outages from November 12 to 16, and fanout.csv
holds supplier outages that reached several customers.

A file's rows load once: the worker skips the loader when the files hash to
the value it stored after the last load.
"""

import csv
import hashlib
import os

from app.analytics import db
from app.trends import LABEL_STATUS, SEED_DIR, item_hash, store

FILES = ("incidents.csv", "national.csv", "fanout.csv")

# national.csv states its status in words. Mixed rows count as undisclosed
# because most of the organizations involved gave no cause.
NATIONAL_STATUS = {
    "stated non-malicious": "nonmalicious",
    "open; no evidence of attack": "undisclosed",
    "undisclosed": "undisclosed",
    "suspected malicious": "malicious",
    "chase non-malicious; rest undisclosed": "undisclosed",
}


def files_hash(seed_dir=SEED_DIR):
    h = hashlib.sha256()
    for name in FILES:
        p = os.path.join(seed_dir, name)
        if os.path.exists(p):
            with open(p, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


def _rows(seed_dir, name):
    p = os.path.join(seed_dir, name)
    if not os.path.exists(p):
        return []
    with open(p, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _status(label):
    s = LABEL_STATUS.get((label or "").strip().lower())
    if s is None:
        raise ValueError(f"unknown cause status in the seed: {label!r}")
    return s


def plan(seed_dir=SEED_DIR):
    """The rows each file would load, without touching a database."""
    return {name: len(_rows(seed_dir, name)) for name in FILES}


def load(con, seed_dir=SEED_DIR):
    """Load every seed row. Answer the number of incidents now from the seed."""
    for i, r in enumerate(_rows(seed_dir, "incidents.csv"), 2):
        key = f"seed/incidents.csv:{i}"
        status = _status(r["cause_status"])
        sid, _ = store.source_item(con, {
            "item_hash": item_hash("seed", key), "source": "seed", "url": None,
            "title": r["org"], "published": r["date"], "categories": r["sector"],
            "status": status, "method": "seed", "confidence": "low"})
        org = store.organization(con, r["org"], r["state"] or None, r["sector"] or None)
        store.incident(con, kind="org", title=r["org"], started=r["date"],
                       organization_id=org, state=r["state"] or None, sector=r["sector"] or None,
                       cause_status=status, source="seed", confidence="low", source_item_id=sid)

    for r in _rows(seed_dir, "national.csv"):
        key = f"seed/national.csv:{r['id']}"
        status = NATIONAL_STATUS.get(r["status"].strip().lower(), "undisclosed")
        sid, _ = store.source_item(con, {
            "item_hash": item_hash("seed", key), "source": "seed", "title": r["event"],
            "published": r["date"], "status": status, "method": "seed", "confidence": "low"})
        iid = store.incident(con, kind="national", title=r["event"], started=r["date"],
                             scope=r["scope"], cause_status=status, source="seed",
                             confidence="low", source_item_id=sid)
        if r.get("stated_cause") and r["stated_cause"].strip().lower() != "none stated":
            store.statement(con, iid, sid, status, None, r["stated_cause"])

    for i, r in enumerate(_rows(seed_dir, "fanout.csv"), 2):
        key = f"seed/fanout.csv:{i}"
        status = _status(r["cause_status"])
        customers = int(r["customers"]) if (r.get("customers") or "").strip() else None
        vid = store.vendor(con, r["vendor"], r["product"] or None)
        iid = None
        if r.get("match_org"):
            row = con.execute(
                "SELECT id FROM incident WHERE kind='org' AND started=? AND title LIKE ? "
                "ORDER BY id LIMIT 1", (r["date"], f"%{r['match_org']}%")).fetchone()
            iid = row[0] if row else None
        if iid is None:
            sid, _ = store.source_item(con, {
                "item_hash": item_hash("seed", key), "source": "seed",
                "title": f"{r['vendor']} {r['product']}".strip(), "published": r["date"],
                "status": status, "method": "seed", "confidence": "low"})
            org = store.organization(con, r["vendor"], None, "IT")
            iid = store.incident(con, kind="vendor", title=f"{r['vendor']} {r['product']} outage",
                                 started=r["date"], organization_id=org, sector="IT",
                                 cause_status=status, source="seed", confidence="low",
                                 source_item_id=sid)
        store.link_vendor(con, iid, vid, customers, r.get("note") or None)

    con.execute("INSERT INTO trend_meta(key, value) VALUES('seed_hash', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (files_hash(seed_dir),))
    return db.qone(con, "SELECT COUNT(*) n FROM incident WHERE source='seed'")["n"]
