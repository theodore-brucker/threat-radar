"""How networks are ranked, and why.

Volume alone puts the big residential and cloud networks on top, which is not
actionable. The previous answer was a 0-100 score blending four weighted terms
plus stacking bonuses. It ranked reasonably but could not be read: the weights
were chosen rather than calibrated, and mixing volume with contact depth meant
a loud scanner and a quiet hands-on actor could land on the same number for
opposite reasons. A reader seeing 73 learned nothing about why.

This reports two independent axes and a category instead.

  depth   how far this network's traffic got, on the same 0-4 escalation
          scale the rest of the site uses. Not a weighting, a maximum.
  share   percentage of events in the window. A raw measurement.

Networks sort by depth first and share second, so anything that reached a
shell outranks anything that merely shouted. The category names the shape
(dedicated infrastructure, hands-on, bulk credential, relay) and `basis`
states the facts it was drawn from, so a disagreement with the label is a
disagreement with stated evidence rather than with an opaque number.
"""

from . import db

SINGLE_IP_MIN_SHARE = 0.02      # 2% of window volume from one IP is enough to flag
DOMINANT_SHARE = 0.20
CONCENTRATION_MIN = 0.90


def _window_days(days):
    return db.clamp_days(days, default=30)


def abuse_scores(con, days=30, limit=25):
    days = _window_days(days)
    if not db.table_exists(con, "asn_ip_daily"):
        return {"built": False, "asns": []}

    ts = db.TsExpr(con)
    cut_day = ts.cutoff(days)
    cut_day = (cut_day if isinstance(cut_day, str) else "")[:10] or "0000-00-00"

    rows = db.qall(
        con,
        """
        SELECT COALESCE(NULLIF(asn,''),'unknown') AS asn,
               MAX(org)                AS org,
               MAX(country)            AS country,
               SUM(events)             AS events,
               COUNT(DISTINCT src_ip)  AS src_ips,
               SUM(sessions)           AS sessions,
               SUM(logins)             AS logins,
               SUM(successes)          AS successes,
               SUM(commands)           AS commands,
               SUM(downloads)          AS downloads,
               SUM(uploads)            AS uploads,
               SUM(tunnels)            AS tunnels,
               MIN(day)                AS first_day,
               MAX(day)                AS last_day
        FROM asn_ip_daily
        WHERE day >= ?
        GROUP BY 1
        ORDER BY events DESC
        LIMIT 200
        """,
        (cut_day,),
    )
    if not rows:
        return {"built": True, "asns": [], "total_events": 0}

    total = (
        db.qone(con, "SELECT SUM(events) AS n FROM asn_ip_daily WHERE day >= ?", (cut_day,))
        or {}
    ).get("n") or 1

    # Busiest single IP inside each ASN, for the concentration term.
    top_ips = {}
    for r in db.qall(
        con,
        """
        SELECT asn, src_ip, SUM(events) AS events
        FROM asn_ip_daily
        WHERE day >= ?
        GROUP BY asn, src_ip
        """,
        (cut_day,),
    ):
        key = r["asn"] or "unknown"
        cur = top_ips.get(key)
        if cur is None or r["events"] > cur["events"]:
            top_ips[key] = r

    # Stage 4 (confirmed malware) is not derivable from asn_ip_daily, which
    # counts transfers but knows nothing about reputation. source_stage does.
    malicious_asns = set()
    if db.table_exists(con, "source_stage"):
        for m in db.qall(
            con, "SELECT DISTINCT asn FROM source_stage WHERE malicious > 0"
        ):
            a = str(m["asn"] or "")
            malicious_asns.add(a)
            malicious_asns.add(a.lstrip("AS"))
            malicious_asns.add(f"AS{a.lstrip('AS')}")

    out = []
    for r in rows:
        events = r["events"] or 0
        ips = r["src_ips"] or 1
        share = events / total
        top = top_ips.get(r["asn"], {"src_ip": None, "events": 0})
        concentration = (top["events"] / events) if events else 0.0
        per_ip = events / ips
        transfers = (r["downloads"] or 0) + (r["uploads"] or 0)

        depth, depth_label = _depth(r, transfers, r["asn"] in malicious_asns)
        klass, klass_label = _classify(r, share, concentration, ips, transfers)

        flags = []
        if ips == 1 and share >= SINGLE_IP_MIN_SHARE:
            flags.append("single-ip-asn")
        if ips > 1 and concentration >= CONCENTRATION_MIN and share >= 0.01:
            flags.append("single-ip-dominant")
        if share >= DOMINANT_SHARE:
            flags.append("dominant-volume")
        if per_ip >= 10000:
            flags.append("high-intensity")
        if (r["commands"] or 0) > 0:
            flags.append("hands-on-keyboard")
        if transfers > 0:
            flags.append("payload-transfer")
        if (r["tunnels"] or 0) > 0:
            flags.append("tunnel-abuse")
        if (r["logins"] or 0) and (r["successes"] or 0) == 0:
            flags.append("no-successful-auth")

        r.update(
            {
                "share_pct": round(100 * share, 2),
                "top_ip": top["src_ip"],
                "top_ip_events": top["events"],
                "top_ip_share_pct": round(100 * concentration, 1),
                "events_per_ip": int(per_ip),
                "depth": depth,
                "depth_label": depth_label,
                "class": klass,
                "class_label": klass_label,
                "flags": flags,
            }
        )
        r["reason"] = _reason(r, share, concentration, ips, per_ip)
        out.append(r)

    # Depth first, share second: reaching a shell outranks being loud.
    out.sort(key=lambda x: (x["depth"], x["share_pct"]), reverse=True)
    return {
        "built": True,
        "window_days": days,
        "total_events": total,
        "asns": out[:limit],
    }


DEPTH_LABELS = ["connected only", "authenticated", "reached a shell",
                "moved a file", "confirmed malware"]


def _depth(r, transfers, seen_malicious):
    """Furthest stage this network's traffic reached. A maximum, not a blend."""
    if seen_malicious:
        return 4, DEPTH_LABELS[4]
    if transfers > 0:
        return 3, DEPTH_LABELS[3]
    if (r["commands"] or 0) > 0:
        return 2, DEPTH_LABELS[2]
    if (r["successes"] or 0) > 0:
        return 1, DEPTH_LABELS[1]
    return 0, DEPTH_LABELS[0]


def _classify(r, share, concentration, ips, transfers):
    """Name the shape of the traffic. Most specific match wins.

    These are descriptions of observed behaviour, not attribution. A network
    is called dedicated infrastructure because its volume sits on one address,
    which is a fact about our logs, not a claim about who rents it.
    """
    if (r["commands"] or 0) > 0 or transfers > 0:
        return "hands-on", "Hands-on activity"
    if (r["tunnels"] or 0) > 0 and (r["tunnels"] or 0) >= (r["logins"] or 0):
        return "relay", "Relay attempts"
    if (ips == 1 or concentration >= CONCENTRATION_MIN) and share >= SINGLE_IP_MIN_SHARE:
        return "dedicated", "Dedicated infrastructure"
    if (r["logins"] or 0) > 0:
        return "credential-bulk", "Bulk credential guessing"
    return "background", "Background noise"


def _reason(r, share, concentration, ips, per_ip):
    bits = []
    if ips == 1:
        bits.append(
            f"one address ({r.get('top_ip')}) is {share*100:.1f}% of all events in the window"
        )
    elif concentration >= CONCENTRATION_MIN:
        bits.append(
            f"{concentration*100:.0f}% of this ASN's traffic comes from {r.get('top_ip')}"
        )
    else:
        bits.append(f"{ips} addresses averaging {int(per_ip):,} events each")
    if r.get("commands"):
        bits.append(f"{r['commands']:,} shell commands issued")
    if r.get("downloads") or r.get("uploads"):
        bits.append(
            f"{(r.get('downloads') or 0):,} downloads / {(r.get('uploads') or 0):,} uploads"
        )
    return "; ".join(bits)


def asn_detail(con, asn, days=30):
    days = _window_days(days)
    ts = db.TsExpr(con)
    cut_day = ts.cutoff(days)
    cut_day = (cut_day if isinstance(cut_day, str) else "")[:10] or "0000-00-00"
    ips = db.qall(
        con,
        """
        SELECT src_ip, SUM(events) AS events, SUM(sessions) AS sessions,
               SUM(successes) AS successes, SUM(commands) AS commands,
               SUM(downloads) AS downloads, MIN(day) AS first_day, MAX(day) AS last_day
        FROM asn_ip_daily
        WHERE day >= ? AND COALESCE(NULLIF(asn,''),'unknown') = ?
        GROUP BY src_ip
        ORDER BY events DESC
        LIMIT 100
        """,
        (cut_day, asn),
    )
    daily = db.qall(
        con,
        """
        SELECT day, SUM(events) AS events, COUNT(DISTINCT src_ip) AS src_ips
        FROM asn_ip_daily
        WHERE day >= ? AND COALESCE(NULLIF(asn,''),'unknown') = ?
        GROUP BY day ORDER BY day
        """,
        (cut_day, asn),
    )
    return {"asn": asn, "window_days": days, "addresses": ips, "daily": daily}
