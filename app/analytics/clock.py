"""US Eastern time for every day boundary and every displayed time.

Stored timestamps stay UTC: raw_events.ts is what Cowrie wrote, and the
*_at columns are written with db.utcnow(). What changes is where a day starts
and how a time is shown. A day is midnight to midnight in America/New_York,
so EST or EDT depending on the date, and the per-day tables are keyed by that
day.

Three groups of callers:

  day(), today(), days_ago()   which Eastern day a moment falls on
  bounds()                     the UTC range raw_events.ts is compared with
                               to select one Eastern day
  fmt(), iso(), localize()     how a time is written for a reader

register() adds et_day() to a SQLite connection so a query can group raw
events by Eastern day. db.connect_ro and db.connect_rw call it.
"""

import datetime as dt
import functools
import re
from zoneinfo import ZoneInfo

TZ = ZoneInfo("America/New_York")
NAME = "Eastern time"
UTC = dt.timezone.utc

# A stored UTC timestamp: ISO date and time, optional seconds and fraction,
# and either Z, a zero offset or nothing (stored values with no suffix are
# UTC). Anything else, including a bare date, is left alone by localize().
_UTC_STAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]00:?00)?$")


def parse(value):
    """A stored time (ISO text or epoch seconds) as an aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value, UTC)
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        t = dt.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def now():
    return dt.datetime.now(UTC)


def local(value):
    t = parse(value)
    return t.astimezone(TZ) if t else None


# DST changes at 2 AM local time, which is always on a UTC hour, so the
# Eastern day of a moment depends only on its UTC hour. Caching by hour keeps
# et_day() cheap when SQLite calls it once per raw event.
@functools.lru_cache(maxsize=65536)
def _day_of_hour(prefix):
    t = dt.datetime.strptime(prefix, "%Y-%m-%dT%H").replace(tzinfo=UTC)
    return t.astimezone(TZ).date().isoformat()


def day(value):
    """The Eastern day (YYYY-MM-DD) a stored time falls on, or None."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        hour = dt.datetime.fromtimestamp(int(value // 3600) * 3600, UTC)
        return _day_of_hour(hour.strftime("%Y-%m-%dT%H"))
    s = str(value).strip()
    if len(s) == 10:
        return s if _is_day(s) else None
    if len(s) >= 13 and s[10] in "T ":
        try:
            return _day_of_hour(f"{s[:10]}T{s[11:13]}")
        except ValueError:
            return None
    return None


def _is_day(s):
    try:
        dt.date.fromisoformat(s)
    except ValueError:
        return False
    return True


def today():
    return now().astimezone(TZ).date().isoformat()


def days_ago(n):
    """The Eastern day of the moment n days ago: the first day of a window."""
    return (now() - dt.timedelta(days=int(n))).astimezone(TZ).date().isoformat()


def start_of(day_str):
    """Midnight Eastern at the start of a day, as an aware UTC datetime."""
    d = dt.date.fromisoformat(day_str[:10])
    return dt.datetime(d.year, d.month, d.day, tzinfo=TZ).astimezone(UTC)


def bounds(day_str, span_days=1):
    """Half-open UTC bounds [lo, hi) covering span_days Eastern days.

    Written without a zone suffix: stored times carry fractional seconds
    before the Z, and '.' sorts below 'Z', so '…T05:00:00.5Z' would sort
    before a bound of '…T05:00:00Z'. The prefix '…T05:00:00' sorts below
    every stored time in that second.
    """
    d = dt.date.fromisoformat(day_str[:10])
    end = (d + dt.timedelta(days=int(span_days))).isoformat()
    fmt_ = "%Y-%m-%dT%H:%M:%S"
    return start_of(d.isoformat()).strftime(fmt_), start_of(end).strftime(fmt_)


def epoch_bounds(day_str, span_days=1):
    d = dt.date.fromisoformat(day_str[:10])
    end = (d + dt.timedelta(days=int(span_days))).isoformat()
    return start_of(d.isoformat()).timestamp(), start_of(end).timestamp()


def fmt(value, zone=False):
    """'2026-11-20 16:42', with ' EST' or ' EDT' when zone is set."""
    t = local(value)
    if t is None:
        return None
    out = t.strftime("%Y-%m-%d %H:%M")
    return f"{out} {t.strftime('%Z')}" if zone else out


def iso(value):
    """ISO 8601 in Eastern time with its offset: 2026-11-20T16:42:51-05:00,
    with milliseconds when the stored time has a fraction, so the session
    timeline can still measure sub-second gaps."""
    t = local(value)
    if t is None:
        return None
    return t.isoformat(timespec="milliseconds" if t.microsecond else "seconds")


# Keys whose values are stored UTC times. Values are converted only when the
# key matches and the value has the shape of a UTC timestamp, so attacker
# text (commands, credentials, URLs) is never rewritten.
_TIME_KEYS = re.compile(
    r"^(ts|at|started|ended|discovered|kev_added)$|_(ts|at|seen|contributed)$")


def localize(obj):
    """A copy of a JSON-shaped value with stored UTC times in Eastern ISO."""
    if isinstance(obj, dict):
        return {k: (iso(v) if _is_time(k, v) else localize(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [localize(v) for v in obj]
    return obj


def _is_time(key, value):
    return (isinstance(key, str) and isinstance(value, str)
            and _TIME_KEYS.search(key) is not None and _UTC_STAMP.match(value) is not None)


def register(con):
    """Add et_day(ts) to a SQLite connection."""
    con.create_function("et_day", 1, day, deterministic=True)
    return con
