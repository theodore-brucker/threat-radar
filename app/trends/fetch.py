"""Conditional HTTP GET for the trend collectors, standard library only.

Each source keeps the ETag and Last-Modified it last saw in
trend_fetch_state. An unchanged feed answers 304 with no body, which is most
runs. Bodies are capped so a misbehaving server cannot fill the SD card.
"""

import urllib.error
import urllib.request

from app.analytics import db

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 30
USER_AGENT = "threat-radar-trends/1 (+https://github.com/theodore-brucker/threat-radar)"


class FetchError(Exception):
    pass


def _state(con, source):
    if con is None:
        return {}
    return db.qone(con, "SELECT etag, last_modified FROM trend_fetch_state WHERE source=?",
                   (source,)) or {}


def save_state(con, source, status, etag=None, last_modified=None, size=0):
    """Record the outcome of a fetch. On 304 the stored validators stay."""
    con.execute(
        "INSERT INTO trend_fetch_state(source, etag, last_modified, last_run, last_status, last_bytes) "
        "VALUES(?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
        "etag=COALESCE(excluded.etag, etag), "
        "last_modified=COALESCE(excluded.last_modified, last_modified), "
        "last_run=excluded.last_run, last_status=excluded.last_status, "
        "last_bytes=excluded.last_bytes",
        (source, etag, last_modified, db.utcnow(), str(status), size))


def get(source, url, con=None, headers=None, opener=None):
    """Answer (status, body, etag, last_modified). status 304 has body None.

    con is read for the stored validators and never written here, so a dry
    run can pass a read-only connection or None.
    """
    st = _state(con, source)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    if st.get("etag"):
        req.add_header("If-None-Match", st["etag"])
    if st.get("last_modified"):
        req.add_header("If-Modified-Since", st["last_modified"])
    open_ = opener or urllib.request.urlopen
    try:
        with open_(req, timeout=TIMEOUT) as resp:
            body = resp.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise FetchError(f"{source}: response is over {MAX_BYTES} bytes")
            return (resp.status, body, resp.headers.get("ETag"),
                    resp.headers.get("Last-Modified"))
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, None, None, None
        raise FetchError(f"{source}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise FetchError(f"{source}: {getattr(exc, 'reason', exc)}") from exc
