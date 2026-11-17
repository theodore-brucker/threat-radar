"""Incident trends: disruptive incidents at US organizations and their causes.

The worker in bin/trends_worker.py collects, classifies and rolls up. The web
process reads the tables through app/routers/trends.py and never writes.
"""

import hashlib
import os
import re

APP_DIR = os.environ.get("TR_APP", os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
MIGRATION = os.path.join(APP_DIR, "migrations", "trends", "001_trends.sql")
SEED_DIR = os.path.join(APP_DIR, "seed")

STATUSES = ("malicious", "undisclosed", "nonmalicious")
STATUS_LABEL = {
    "malicious": "Malicious cause stated",
    "undisclosed": "Undisclosed or vague",
    "nonmalicious": "Non-malicious or precautionary",
}
# The seed files spell the three values as their labels.
LABEL_STATUS = {v.lower(): k for k, v in STATUS_LABEL.items()}

# Tracking starts here. Earlier rows come from the seed and give the trend a
# baseline; collected items published before this date are kept as source
# items but never open an incident.
TRACK_FROM = "2026-11-01"


def item_hash(source, key):
    return hashlib.sha256(f"{source}\x00{key}".encode("utf-8")).hexdigest()


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s[:80] or "unnamed"


def marks(n):
    """Bound-parameter placeholders for an IN list."""
    return ",".join("?" * n)
