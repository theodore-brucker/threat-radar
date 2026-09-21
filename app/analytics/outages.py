"""Known sensor outages.

Volume kept flowing through the July 31 to August 17 fault because connections
were still logged; only authentication and everything downstream of it died.
Any trend that averages those days in will report a collapse in attacker
success that is really a collapse in sensor function, so they are excluded
from baselines by name and drawn on the activity chart as a labelled gap.
"""

import datetime as dt

from . import db

# Stages affected by each scope. An 'auth' outage leaves connection counts
# trustworthy, so only the downstream measures are suppressed.
SCOPE_FIELDS = {
    "auth": {"authenticated", "shell", "transferred", "captured", "submitted",
             "logins", "successes", "commands", "downloads", "uploads"},
    "ingest": {"*"},
    "all": {"*"},
}


def windows(con):
    if not db.table_exists(con, "outage_windows"):
        return []
    return db.qall(
        con,
        "SELECT start_day, end_day, scope, reason FROM outage_windows ORDER BY start_day",
    )


def excluded_days(con, field=None):
    """Days to leave out of a baseline. Pass a field name to respect scope."""
    out = set()
    for w in windows(con):
        affected = SCOPE_FIELDS.get(w["scope"], {"*"})
        if field is not None and "*" not in affected and field not in affected:
            continue
        try:
            start = dt.date.fromisoformat(w["start_day"])
            end = dt.date.fromisoformat(w["end_day"])
        except ValueError:
            continue
        cur = start
        while cur <= end:
            out.add(cur.isoformat())
            cur += dt.timedelta(days=1)
    return out


def spans_for_chart(con):
    """Start and end days for drawing the gap band."""
    return [
        {"start": w["start_day"], "end": w["end_day"], "reason": w["reason"],
         "scope": w["scope"]}
        for w in windows(con)
    ]
