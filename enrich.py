#!/usr/bin/env python3
"""Threat Radar enricher.

Tags new source IPs with GeoLite2 city + ASN data from the local MaxMind
databases (kept current by geoipupdate). Runs forever, batch at a time.
API-based enrichers (GreyNoise, AbuseIPDB, VT) slot in here later.
"""
import os
import sqlite3
import time
from datetime import datetime, timezone

import geoip2.database
import geoip2.errors

BASE = os.environ.get("TR_BASE", "/opt/threat-radar")
DB = os.path.join(BASE, "data", "radar.db")
CITY_DB = os.environ.get("TR_CITY_DB", "/var/lib/GeoIP/GeoLite2-City.mmdb")
ASN_DB = os.environ.get("TR_ASN_DB", "/var/lib/GeoIP/GeoLite2-ASN.mmdb")
INTERVAL = int(os.environ.get("TR_ENRICH_INTERVAL", "60"))


def enrich_batch(conn, city_reader, asn_reader) -> int:
    rows = conn.execute(
        "SELECT ip FROM sources WHERE enriched_at IS NULL LIMIT 200"
    ).fetchall()
    now = datetime.now(timezone.utc).isoformat()
    for (ip,) in rows:
        country = code = city = as_org = None
        lat = lon = asn = None
        try:
            r = city_reader.city(ip)
            country = r.country.name
            code = r.country.iso_code
            city = r.city.name
            lat = r.location.latitude
            lon = r.location.longitude
        except (geoip2.errors.AddressNotFoundError, ValueError):
            pass
        try:
            a = asn_reader.asn(ip)
            asn = a.autonomous_system_number
            as_org = a.autonomous_system_organization
        except (geoip2.errors.AddressNotFoundError, ValueError):
            pass
        conn.execute(
            "UPDATE sources SET country=?, country_code=?, city=?, lat=?, lon=?,"
            " asn=?, as_org=?, enriched_at=? WHERE ip=?",
            (country, code, city, lat, lon, asn, as_org, now, ip),
        )
    conn.commit()
    return len(rows)


def main():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA busy_timeout=300000")
    while not (os.path.exists(CITY_DB) and os.path.exists(ASN_DB)):
        print(f"[enrich] waiting for GeoLite2 databases at {CITY_DB} / {ASN_DB}",
              flush=True)
        time.sleep(300)
    with geoip2.database.Reader(CITY_DB) as city_reader, \
         geoip2.database.Reader(ASN_DB) as asn_reader:
        print("[enrich] GeoLite2 loaded", flush=True)
        while True:
            n = enrich_batch(conn, city_reader, asn_reader)
            if n:
                print(f"[enrich] tagged {n} sources", flush=True)
            time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
