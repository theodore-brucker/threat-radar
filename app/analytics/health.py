"""When each part of the pipeline last did its job, in Eastern time.

The view reports times and makes no judgement about them. Each stage runs on
its own cadence, and a threshold that fits one week of traffic raises alarms
in the next, so the reader compares the times against the clock instead.

Sources, one per row:

  events, logins   newest timestamps in raw_events (index lookups)
  pull, samples    mtime of the heartbeat file pull.sh and fetch_samples.sh
                   touch after a cycle where every request succeeded
  enrich           newest sources.enriched_at
  worker and its   insights_state keys the intel worker writes per step
  steps
  trends           newest trend_fetch_state.last_run
  prune            insights_state key prune.py writes at the end of a run

A row with no record (a fresh install, a stage that has never run) has
`at` set to None.
"""

import datetime as dt
import os

from . import clock
from . import db
from . import outages
from . import persona

TZ_NAME = clock.NAME

BASE = os.environ.get("TR_BASE", "/opt/threat-radar")
PULL_HEARTBEAT = os.path.join(BASE, "spool", ".pulled")
FETCH_HEARTBEAT = os.path.join(
    os.environ.get("TR_SAMPLE_DIR", os.path.join(BASE, "data", "samples")), ".fetched")

parse_ts = clock.parse


def heartbeat(path):
    try:
        return dt.datetime.fromtimestamp(os.stat(path).st_mtime, tz=dt.timezone.utc)
    except OSError:
        return None


def eastern(when):
    """'2026-11-20 21:12 EST', or None. EST or EDT follows the date."""
    return clock.fmt(when, zone=True)


def _newest(con, eventid):
    row = db.qone(con, "SELECT MAX(ts) ts FROM raw_events WHERE eventid = ?", (eventid,))
    return parse_ts((row or {}).get("ts"))


def _trends_run(con):
    if not db.table_exists(con, "trend_fetch_state"):
        return None
    row = db.qone(con, "SELECT MAX(last_run) ts FROM trend_fetch_state")
    return parse_ts((row or {}).get("ts"))


def _rows(con):
    """(key, label, what it is, when) in pipeline order."""
    newest_event = parse_ts(
        (db.qone(con, "SELECT MAX(ts) ts FROM raw_events") or {}).get("ts"))
    failed = _newest(con, "cowrie.login.failed")
    success = _newest(con, "cowrie.login.success")
    attempt = max((t for t in (failed, success) if t), default=None)
    enriched = parse_ts(
        (db.qone(con, "SELECT MAX(enriched_at) ts FROM sources") or {}).get("ts"))

    def state(key):
        return parse_ts(db.get_state(con, key))

    return [
        ("pull", "Log pull completed",
         "The Pi copied new log lines from the sensor.", heartbeat(PULL_HEARTBEAT)),
        ("events", "Newest event received",
         "Timestamp of the most recent sensor event stored on the Pi.", newest_event),
        ("login_attempt", "Newest login attempt",
         "Most recent password attempt, accepted or refused.", attempt),
        ("login_success", "Newest accepted login",
         "Most recent login the sensor let through.", success),
        ("enrich", "Newest address lookup",
         "Most recent source address given a country and network.", enriched),
        ("samples", "Sample fetch completed",
         "The Pi copied captured files from the sensor.", heartbeat(FETCH_HEARTBEAT)),
        ("worker", "Analytics run finished",
         "The worker rebuilt the tables every page reads.", state("last_run")),
        ("facts", "Daily facts rebuilt",
         "Per-day counts behind the charts and comparisons.", state("facts_built_at")),
        ("intel", "Reputation lookups ran",
         "VirusTotal and URLhaus checks on captured samples.", state("intel_built_at")),
        ("submissions", "Upstream submissions ran",
         "Uploads of new samples to VirusTotal and MalwareBazaar.",
         state("submissions_built_at")),
        ("trends", "Incident feeds checked",
         "Outage and incident sources for the trends page.", _trends_run(con)),
        ("prune", "Retention prune finished",
         "Old raw events, spool files and storage size checked.", state("prune_at")),
    ]


def status(con, now=None):
    now = now or clock.now()
    items = [
        {
            "key": key,
            "label": label,
            "detail": detail,
            "at": when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else None,
            "at_local": eastern(when),
        }
        for key, label, detail, when in _rows(con)
    ]
    last_day = (db.qone(con, "SELECT MAX(day) day FROM asn_ip_daily") or {}).get("day")
    return {
        "timezone": TZ_NAME,
        "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checked_at_local": eastern(now),
        "items": items,
        # prune.py writes this only when the database is over its cap or the
        # disk is too small for VACUUM, and clears it otherwise.
        "storage": db.get_state(con, "storage_status") or None,
        "last_event_day": last_day,
        "outages": outages.spans_for_chart(con),
        "personas": persona.spans_for_chart(con),
        "persona_now": (persona.epoch_for(con, last_day) or {}).get("name"),
    }
