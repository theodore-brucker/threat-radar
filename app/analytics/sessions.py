"""Session narratives and sample inspection.

Two rules govern this module, because the site is intended to go public:

  1. No endpoint returns sample bytes. Text samples are returned as decoded
     text with control characters stripped; binaries return metadata and
     filtered strings only. There is no download path.
  2. Every value here originated with an attacker. Nothing is interpolated
     into SQL and nothing is trusted for length or encoding.
"""

import json
import math
import os
import re
import struct

SAMPLE_DIR = os.environ.get("TR_SAMPLE_DIR", "/opt/threat-radar/data/samples")

MAX_TEXT_BYTES = 256 * 1024      # text samples larger than this are truncated
MIN_SAMPLE_BYTES = int(os.environ.get("TR_SAMPLE_MIN_BYTES", "64"))  # below this it is an artifact, not a specimen
MAX_STRINGS = 400                # strings returned for a binary
MIN_STRING_LEN = 8

# Compressed and encrypted regions emit long runs of bytes that happen to be
# printable. Requiring a plausible word shape keeps the extractor from filling
# its budget with 400 fragments of a UPX blob before reaching the real stub.
STRING_SHAPE = re.compile(r"[A-Za-z]{4}")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
# sha256 of zero bytes. Cowrie logs a file event for aborted transfers, so this
# hash recurs forever and is never a real artifact.
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SESSION_RE = re.compile(r"^[0-9a-f]{6,32}$")

# Strings that are noise in every ELF and only dilute the interesting ones.
STRING_NOISE = re.compile(
    r"^(GCC:|GLIBC_|__|\.[a-z]|_ITM_|_GLOBAL__|gmon_start|libc\.so|"
    r"[0-9A-Za-z+/=]{80,}$)")

TEXT_HINTS = (b"#!/", b"#!", b"<?php", b"import ", b"function ")


def _table_exists(con, name):
    return con.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name=?",
        (name,)).fetchone() is not None


def _rows(cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _jget(payload, key, default=None):
    try:
        return (json.loads(payload) or {}).get(key, default)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# session list
# ---------------------------------------------------------------------------

def sessions_with_files(con, days=30, limit=200):
    """Sessions that moved at least one file. This is the interesting set:
    roughly 0.05% of sessions, and every one of them has a story."""
    cur = con.execute(
        """
        WITH filed AS (
          SELECT DISTINCT session
          FROM v_events
          WHERE eventid IN ('cowrie.session.file_download',
                            'cowrie.session.file_upload')
            AND ts >= datetime('now', ?)
        )
        SELECT e.session,
               MIN(e.ts)  AS started,
               MAX(e.ts)  AS ended,
               MAX(e.src_ip) AS src_ip,
               SUM(e.eventid = 'cowrie.command.input')         AS commands,
               SUM(e.eventid = 'cowrie.session.file_download') AS downloads,
               SUM(e.eventid = 'cowrie.session.file_upload')   AS uploads,
               SUM(e.eventid = 'cowrie.login.success')         AS logins
        FROM v_events e
        JOIN filed f ON f.session = e.session
        GROUP BY e.session
        ORDER BY started DESC
        LIMIT ?
        """,
        (f"-{int(days)} days", int(limit)),
    )
    rows = _rows(cur)

    # Previously one query per session, file_download only, with LIMIT 4
    # applied to raw event rows before deduplication. A session that uploaded
    # seven files over SFTP reported no hashes at all, and one that re-fetched
    # the same hash five times reported fewer than it had. Cross-session hash
    # reuse is the best clustering key in this dataset, so undercounting it
    # here mattered. Now both directions, distinct hashes, one query per page.
    #
    # The all-zeros sha is the SHA-256 of an empty file. Four unrelated sources
    # have "shared" it, which is not a relationship.
    EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sha_cur = con.execute(
        """SELECT session, json_extract(payload,'$.shasum') AS sha
           FROM v_events
           WHERE eventid IN ('cowrie.session.file_download',
                             'cowrie.session.file_upload')
             AND ts >= datetime('now', ?)
             AND json_extract(payload,'$.shasum') IS NOT NULL
             AND json_extract(payload,'$.shasum') NOT IN ('', ?)
           ORDER BY ts""",
        (f"-{int(days)} days", EMPTY),
    )
    by_session = {}
    for row in sha_cur.fetchall():
        sess, sha = row[0], row[1]
        bucket = by_session.setdefault(sess, [])
        if sha not in bucket:
            bucket.append(sha)
    for r in rows:
        r["shasums"] = by_session.get(r["session"], [])
    return {"sessions": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# session timeline
# ---------------------------------------------------------------------------

# What each event contributes to the narrative. Anything not listed is dropped
# rather than rendered as raw JSON.
def _summarize(eventid, payload):
    g = lambda k, d=None: _jget(payload, k, d)
    if eventid == "cowrie.session.connect":
        return "connected", f"from {g('src_ip','?')}:{g('src_port','?')}"
    if eventid == "cowrie.client.version":
        return "client", str(g("version", "?"))
    if eventid == "cowrie.client.kex":
        return "key exchange", f"hassh {g('hassh','?')}"
    if eventid == "cowrie.login.success":
        return "authenticated", f"{g('username','?')} / {g('password','?')}"
    if eventid == "cowrie.login.failed":
        return "login rejected", f"{g('username','?')} / {g('password','?')}"
    if eventid == "cowrie.session.params":
        return "fingerprinted host", f"arch {g('arch','?')}"
    if eventid == "cowrie.command.input":
        return "ran command", str(g("input", ""))
    if eventid == "cowrie.command.failed":
        return "command not found", str(g("input", ""))
    if eventid == "cowrie.session.file_download":
        url = g("url") or "(pushed in-band, no url)"
        return "file arrived", f"{g('shasum','?')} via {url}"
    if eventid == "cowrie.session.file_upload":
        return "file uploaded to us", f"{g('shasum','?')} {g('filename','')}"
    if eventid == "cowrie.client.fingerprint":
        return "offered key", f"{g('type','?')} {g('fingerprint','?')}"
    if eventid == "cowrie.direct-tcpip.request":
        return "relay attempt", f"{g('dst_ip','?')}:{g('dst_port','?')}"
    if eventid == "cowrie.session.closed":
        d = g("duration_ms")
        return "disconnected", f"after {round(d/1000.0,1)}s" if d else "disconnected"
    return None, None


def session_detail(con, session):
    if not SESSION_RE.match(session or ""):
        return {"error": "malformed session id"}

    cur = con.execute(
        """SELECT ts, eventid, payload, src_ip FROM v_events
           WHERE session=? ORDER BY ts, rowid""", (session,))
    raw = _rows(cur)
    if not raw:
        return {"error": "unknown session"}

    timeline, commands, files = [], [], []
    for r in raw:
        label, detail = _summarize(r["eventid"], r["payload"])
        if label is None:
            continue
        timeline.append({"ts": r["ts"], "eventid": r["eventid"],
                         "label": label, "detail": detail})
        if r["eventid"] in ("cowrie.command.input", "cowrie.command.failed"):
            commands.append({"ts": r["ts"], "input": _jget(r["payload"], "input", ""),
                             "found": r["eventid"] == "cowrie.command.input"})
        if r["eventid"] in ("cowrie.session.file_download",
                            "cowrie.session.file_upload"):
            files.append({
                "ts": r["ts"],
                "direction": "in" if r["eventid"].endswith("download") else "out",
                "shasum": _jget(r["payload"], "shasum"),
                "url": _jget(r["payload"], "url"),
                "filename": _jget(r["payload"], "filename"),
            })

    first, last = raw[0], raw[-1]
    meta = {
        "session": session,
        "src_ip": first.get("src_ip"),
        "started": first["ts"],
        "ended": last["ts"],
        "event_count": len(raw),
    }
    for r in raw:
        if r["eventid"] == "cowrie.client.version":
            meta["client"] = _jget(r["payload"], "version")
        elif r["eventid"] == "cowrie.client.kex":
            meta["hassh"] = _jget(r["payload"], "hassh")
        elif r["eventid"] == "cowrie.session.params":
            meta["arch"] = _jget(r["payload"], "arch")
        elif r["eventid"] == "cowrie.login.success":
            meta["username"] = _jget(r["payload"], "username")
            meta["password"] = _jget(r["payload"], "password")
        elif r["eventid"] == "cowrie.session.closed":
            meta["duration_ms"] = _jget(r["payload"], "duration_ms")

    return {"meta": meta, "timeline": timeline,
            "commands": commands, "files": files}


# ---------------------------------------------------------------------------
# sample inspection
# ---------------------------------------------------------------------------

def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


def _packer(data):
    """UPX identifies its own files by a trailer at the end, not by the header
    magic. A file carrying the header block without that trailer will refuse to
    unpack with `upx -d` while still unpacking itself at runtime, which is a
    deliberate and reportable state rather than a corrupt file."""
    i = data.find(b"UPX!")
    if i < 0:
        return None
    out = {"packer": "UPX", "header_offset": i}
    if len(data) >= i + 20:
        out["version"] = data[i + 4]
        out["format"] = data[i + 5]
        out["method"] = data[i + 6]
        out["level"] = data[i + 7]
        try:
            out["unpacked_size"] = struct.unpack("<I", data[i + 16:i + 20])[0]
        except Exception:
            pass
    # The trailer sits in the last 64 bytes of a stock UPX file.
    out["trailer_present"] = b"UPX!" in data[-64:]
    if not out["trailer_present"]:
        out["note"] = ("UPX header present but the trailing identification "
                       "structure is absent, so standard unpackers decline "
                       "this file")
    return out


def _identify(head):
    if head[:4] == b"\x7fELF":
        bits = {1: "32-bit", 2: "64-bit"}.get(head[4], "?")
        endian = {1: "LSB", 2: "MSB"}.get(head[5], "?")
        etype = {1: "relocatable", 2: "executable", 3: "shared object"}.get(
            struct.unpack("<H", head[16:18])[0], "?") if len(head) >= 18 else "?"
        machine = {0x03: "x86", 0x28: "ARM", 0x3E: "x86-64", 0xB7: "AArch64",
                   0x08: "MIPS"}.get(
            struct.unpack("<H", head[18:20])[0], "?") if len(head) >= 20 else "?"
        return f"ELF {bits} {endian} {etype}, {machine}", False
    if head[:2] == b"MZ":
        return "PE / MS-DOS executable", False
    if head[:2] == b"\x1f\x8b":
        return "gzip archive", False
    if head[:2] == b"#!":
        return "script with interpreter line", True
    if any(head.startswith(h) for h in TEXT_HINTS):
        return "script", True
    # Heuristic: mostly printable and no NULs means treat it as text.
    sample = head[:512]
    if sample and b"\x00" not in sample:
        printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
        if printable / len(sample) > 0.95:
            return "text", True
    return "binary, unrecognised", False


def _strings(data, minlen=MIN_STRING_LEN, cap=MAX_STRINGS):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
            continue
        if len(cur) >= minlen:
            s = cur.decode("ascii", "ignore")
            if STRING_SHAPE.search(s) and not STRING_NOISE.match(s):
                out.append(s)
                if len(out) >= cap:
                    return out, True
        cur = bytearray()
    if len(cur) >= minlen:
        s = cur.decode("ascii", "ignore")
        if STRING_SHAPE.search(s) and not STRING_NOISE.match(s):
            out.append(s)
    return out, False


def sample_detail(con, shasum):
    """Metadata, and content only when it is text. Never raw bytes."""
    if not SHA_RE.match((shasum or "").lower()):
        return {"error": "malformed sha256"}
    shasum = shasum.lower()

    if shasum == EMPTY_SHA:
        return {"sha256": shasum, "present": False, "empty_transfer": True,
                "note": "zero-byte transfer; the session recorded a file event "
                        "but nothing was written"}

    out = {"sha256": shasum, "present": False}

    cur = con.execute(
        """SELECT source, verdict, malicious, suspicious, harmless, undetected,
                  label, reference, checked_at
           FROM payload_intel WHERE indicator=?""", (shasum,))
    out["intel"] = _rows(cur)

    cur = con.execute(
        """SELECT status, permalink, size_bytes, submitted_at, detail
           FROM payload_submissions WHERE sha256=?""", (shasum,))
    out["submissions"] = _rows(cur)

    # payload_sightings is indexed on shasum. The previous version selected
    # every transfer event in the database and filtered in Python, so the page
    # cost grew with total captures rather than with this sample's sightings.
    cur = con.execute(
        """SELECT session, src_ip, ts, url, direction FROM payload_sightings
           WHERE shasum = ? ORDER BY ts""", (shasum,))
    seen = []
    for r in _rows(cur):
        url = r["url"] or ""
        # Cowrie puts a local path here for in-band and SFTP transfers. It is
        # not a URL and must not be offered as one.
        is_url = "://" in url
        seen.append({
            "session": r["session"], "src_ip": r["src_ip"], "ts": r["ts"],
            "url": url if is_url else None,
            "path": None if is_url else (url or None),
            # The event type is authoritative. Inferring direction from whether
            # a URL is present labelled every SFTP upload as a fetch.
            "direction": "in" if (r["direction"] or "").startswith("down") else "out",
        })
    out["sightings"] = seen

    fam = None
    if _table_exists(con, "payload_families"):
        row = con.execute(
            "SELECT family, confidence, basis, candidates FROM payload_families"
            " WHERE shasum = ?", (shasum,)).fetchone()
        if row:
            cols = [d[0] for d in con.execute(
                "SELECT family, confidence, basis, candidates FROM payload_families"
                " WHERE shasum = ?", (shasum,)).description]
            fam = dict(zip(cols, row))
    out["family"] = fam

    path = os.path.join(SAMPLE_DIR, shasum)
    if not (os.path.isfile(path) and os.path.realpath(path).startswith(
            os.path.realpath(SAMPLE_DIR) + os.sep)):
        return out

    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(4096)
        fh.seek(0)
        body = fh.read(min(size, MAX_TEXT_BYTES))

    kind, is_text = _identify(head)
    # Cowrie records whatever crossed the wire, including truncated fetches and
    # single-line probes. These are real observations but they are not
    # specimens, and presenting them with full analysis furniture overstates
    # what they are.
    if size < MIN_SAMPLE_BYTES:
        out.update({"present": True, "size_bytes": size, "kind": kind,
                    "is_text": is_text, "trivial": True,
                    "note": "too small to be a functioning payload; recorded "
                            "as an observation, not analysed as a specimen"})
        if is_text:
            out["text"] = body.decode("utf-8", "replace")
            out["line_count"] = out["text"].count("\n") + 1
        return out
    if not is_text:
        with open(path, "rb") as fh:
            fh.seek(max(0, size - 64))
            tail = fh.read(64)
        pk = _packer(head + b"\x00" * 8 + tail) if b"UPX!" in head else None
        if pk is None and b"UPX!" in tail:
            pk = {"packer": "UPX", "trailer_present": True}
        if pk:
            out["packer"] = pk
    out.update({
        "present": True,
        "size_bytes": size,
        "kind": kind,
        "is_text": is_text,
        "entropy": _entropy(body[:65536]),
    })
    # High entropy on a binary means packed or encrypted, which is worth
    # stating plainly rather than leaving as a number.
    if not is_text and out["entropy"] >= 7.2:
        out["note"] = "high entropy, consistent with packing or encryption"

    if is_text:
        text = body.decode("utf-8", "replace")
        text = "".join(c for c in text if c in "\n\t" or 32 <= ord(c) < 127
                       or ord(c) > 159)
        out["text"] = text
        out["truncated"] = size > MAX_TEXT_BYTES
        out["line_count"] = text.count("\n") + 1
    else:
        strings, capped = _strings(body)
        out["strings"] = strings
        out["strings_capped"] = capped

    return out
