"""direct-tcpip breakdown.

Cowrie logs every forwarding request the client asks for, even though nothing
is actually proxied. The destination host and port say what the operator wanted
the box for: an open relay, a proxy check, a mining pool, or a pivot into
someone else's network.
"""

from . import db

PORT_INTENT = {
    21: ("ftp", "FTP pivot"),
    22: ("ssh", "SSH pivot or chained scan"),
    23: ("telnet", "Telnet pivot"),
    25: ("smtp", "Mail relay abuse"),
    53: ("dns", "DNS tunnelling or resolver test"),
    80: ("http", "Open proxy check or web scraping"),
    110: ("pop3", "Mail account testing"),
    143: ("imap", "Mail account testing"),
    443: ("https", "Open proxy check, ad fraud, or API abuse"),
    445: ("smb", "SMB pivot"),
    465: ("smtps", "Mail relay abuse"),
    587: ("submission", "Mail relay abuse"),
    993: ("imaps", "Mail account testing"),
    995: ("pop3s", "Mail account testing"),
    1080: ("socks", "SOCKS proxy chaining"),
    1433: ("mssql", "Database pivot"),
    3128: ("proxy", "Proxy chaining"),
    3306: ("mysql", "Database pivot"),
    3389: ("rdp", "RDP pivot"),
    5432: ("postgres", "Database pivot"),
    5900: ("vnc", "VNC pivot"),
    6379: ("redis", "Redis pivot"),
    6667: ("irc", "IRC botnet control"),
    8080: ("http-alt", "Proxy check or admin panel"),
    8443: ("https-alt", "Admin panel or API abuse"),
    9050: ("tor", "Tor SOCKS"),
}
MINING_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700, 45560}


def _intent(port):
    if port in PORT_INTENT:
        return PORT_INTENT[port]
    if port in MINING_PORTS:
        return ("mining", "Mining pool connection")
    return ("other", "Unclassified destination")


def overview(con, days=30, limit=50):
    days = db.clamp_days(days, default=30)
    if not db.table_exists(con, "tunnel_targets"):
        return {"built": False}
    ts = db.TsExpr(con)
    cut_day = ts.cutoff(days)
    cut_day = (cut_day if isinstance(cut_day, str) else "")[:10] or "0000-00-00"

    totals = db.qone(
        con,
        """
        SELECT SUM(requests) AS requests, SUM(data_events) AS data_events,
               COUNT(DISTINCT dst_ip) AS destinations,
               COUNT(DISTINCT dst_port) AS ports
        FROM tunnel_targets WHERE day >= ?
        """,
        (cut_day,),
    ) or {}

    by_port = db.qall(
        con,
        """
        SELECT dst_port, SUM(requests) AS requests,
               COUNT(DISTINCT dst_ip) AS destinations
        FROM tunnel_targets WHERE day >= ?
        GROUP BY dst_port ORDER BY requests DESC LIMIT 25
        """,
        (cut_day,),
    )
    for r in by_port:
        svc, intent = _intent(int(r["dst_port"] or 0))
        r["service"] = svc
        r["intent"] = intent

    by_dest = db.qall(
        con,
        """
        SELECT dst_ip, dst_port, SUM(requests) AS requests,
               SUM(sessions) AS sessions, MAX(src_ips) AS src_ips,
               MIN(day) AS first_day, MAX(day) AS last_day
        FROM tunnel_targets WHERE day >= ?
        GROUP BY dst_ip, dst_port ORDER BY requests DESC LIMIT ?
        """,
        (cut_day, limit),
    )
    for r in by_dest:
        svc, intent = _intent(int(r["dst_port"] or 0))
        r["service"] = svc
        r["intent"] = intent

    intent_rollup = {}
    for r in by_dest:
        intent_rollup.setdefault(r["intent"], 0)
        intent_rollup[r["intent"]] += r["requests"] or 0

    return {
        "built": True,
        "window_days": days,
        "totals": totals,
        "by_port": by_port,
        "by_destination": by_dest,
        "by_intent": sorted(
            [{"intent": k, "requests": v} for k, v in intent_rollup.items()],
            key=lambda x: x["requests"],
            reverse=True,
        ),
        "fingerprints": fingerprints(con, days),
        "requesters": requesters(con, days),
    }


def fingerprints(con, days=30, limit=20):
    """JA4H and hassh values seen on tunnel traffic. Cowrie puts the HTTP
    fingerprint on the tunnel data event when the client speaks HTTP through
    the forward, which is what separates proxy-check bots from pivot attempts."""
    ts = db.TsExpr(con)
    cut = ts.cutoff(days)
    rows = db.qall(
        con,
        f"""
        SELECT COALESCE(json_extract(payload,'$.ja4h'),
                        json_extract(payload,'$.ja4h_r'),
                        json_extract(payload,'$.hassh')) AS fingerprint,
               COALESCE(json_extract(payload,'$.ja4h'),'') <> '' AS is_ja4h,
               COUNT(*) AS hits,
               COUNT(DISTINCT src_ip) AS src_ips,
               COUNT(DISTINCT session) AS sessions,
               MIN({ts.iso}) AS first_seen,
               MAX({ts.iso}) AS last_seen
        FROM v_events
        WHERE eventid LIKE 'cowrie.direct-tcpip%' AND ts >= ?
        GROUP BY fingerprint
        HAVING fingerprint IS NOT NULL AND fingerprint <> ''
        ORDER BY hits DESC LIMIT ?
        """,
        (cut, limit),
    )
    return rows


def requesters(con, days=30, limit=20):
    ts = db.TsExpr(con)
    cut = ts.cutoff(days)
    return db.qall(
        con,
        """
        SELECT src_ip, COUNT(*) AS requests,
               COUNT(DISTINCT session) AS sessions,
               COUNT(DISTINCT json_extract(payload,'$.dst_ip')) AS destinations,
               COUNT(DISTINCT json_extract(payload,'$.dst_port')) AS ports
        FROM v_events
        WHERE eventid = 'cowrie.direct-tcpip.request' AND ts >= ?
        GROUP BY src_ip ORDER BY requests DESC LIMIT ?
        """,
        (cut, limit),
    )
