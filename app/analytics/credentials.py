"""Credential theme clustering.

Raw credential pairs are noisy: 15k distinct pairs hide the fact that a few
hundred of them are one campaign. Rules in config/credential_tags.json map a
pair to one or more campaign tags; the intel worker materialises the mapping
into cred_pair_tags so the dashboard can aggregate by campaign instead of by
literal string.
"""

import json
import os
import re

from . import db

RULES_PATH = os.environ.get(
    "TR_CRED_RULES", "/opt/threat-radar/config/credential_tags.json"
)

_CACHE = {"mtime": None, "rules": [], "labels": {}}


def load_rules(path: str = None):
    p = path or RULES_PATH
    try:
        mtime = os.path.getmtime(p)
    except OSError:
        return [], {}
    if _CACHE["mtime"] == mtime:
        return _CACHE["rules"], _CACHE["labels"]

    with open(p, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    compiled = []
    labels = {}
    for rule in doc.get("rules", []):
        tag = rule.get("tag")
        if not tag:
            continue
        labels[tag] = rule.get("label", tag)
        compiled.append(
            {
                "tag": tag,
                "user": re.compile(rule["user"], re.I) if rule.get("user") else None,
                "pass": re.compile(rule["pass"], re.I) if rule.get("pass") else None,
                "either": re.compile(rule["either"], re.I) if rule.get("either") else None,
            }
        )
    _CACHE.update({"mtime": mtime, "rules": compiled, "labels": labels})
    return compiled, labels


def tag_pair(username: str, password: str, rules=None) -> list:
    """Return the campaign tags for one credential pair."""
    if rules is None:
        rules, _ = load_rules()
    u = username or ""
    p = password or ""
    tags = []
    for rule in rules:
        hit = False
        if rule["user"] is not None and rule["user"].search(u):
            hit = True
        if not hit and rule["pass"] is not None and rule["pass"].search(p):
            hit = True
        if not hit and rule["either"] is not None and (
            rule["either"].search(u) or rule["either"].search(p)
        ):
            hit = True
        if hit:
            tags.append(rule["tag"])

    # Structural tags that are easier to express in code than in a regex.
    if u and p and u.lower() == p.lower():
        tags.append("user-as-pass")
    if u and p and len(u) > 2 and u.lower() in p.lower() and u.lower() != p.lower():
        tags.append("pass-contains-user")
    if not tags:
        tags.append("unclustered")
    return sorted(set(tags))


def tag_labels() -> dict:
    _, labels = load_rules()
    labels.setdefault("user-as-pass", "Password equals username")
    labels.setdefault("pass-contains-user", "Password derived from username")
    labels.setdefault("unclustered", "No rule matched")
    return labels


# --------------------------------------------------------------------------
# read side
# --------------------------------------------------------------------------

def campaigns(con, days=30, limit=40):
    """Campaign rollup, counted inside the window.

    This used to sum lifetime attempts from cred_pairs and only filter which
    campaigns appeared, so changing the window moved rows around without
    moving a single number. It now aggregates cred_pair_daily.
    """
    if not db.table_exists(con, "cred_pair_tags"):
        return {"built": False, "campaigns": []}
    if not db.table_exists(con, "cred_pair_daily"):
        return {"built": False, "campaigns": [], "note": "run the worker to build cred_pair_daily"}

    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]

    rows = db.qall(
        con,
        """
        SELECT t.tag                       AS tag,
               COUNT(DISTINCT d.username || ':' || d.password) AS pairs,
               SUM(d.attempts)             AS attempts,
               SUM(d.successes)            AS successes,
               MAX(d.src_ips)              AS peak_ips_single_pair,
               MIN(d.day)                  AS first_seen,
               MAX(d.day)                  AS last_seen
        FROM cred_pair_daily d
        JOIN cred_pair_tags t
          ON t.username = d.username AND t.password = d.password
        WHERE d.day >= ?
        GROUP BY t.tag
        ORDER BY attempts DESC
        LIMIT ?
        """,
        (cut_day, limit),
    )

    ip_counts = {
        r["tag"]: r
        for r in db.qall(
            con,
            "SELECT tag, COUNT(*) AS ips, SUM(attempts) AS ip_attempts "
            "FROM cred_tag_ips GROUP BY tag",
        )
    }

    total = sum(r["attempts"] or 0 for r in rows) or 1
    labels = tag_labels()
    for r in rows:
        r["label"] = labels.get(r["tag"], r["tag"])
        r["share_pct"] = round(100.0 * (r["attempts"] or 0) / total, 2)
        r["src_ips"] = (ip_counts.get(r["tag"]) or {}).get("ips", 0)
        r["examples"] = db.qall(
            con,
            """
            SELECT d.username, d.password,
                   SUM(d.attempts) AS attempts, SUM(d.successes) AS successes
            FROM cred_pair_daily d
            JOIN cred_pair_tags t
              ON t.username = d.username AND t.password = d.password
            WHERE t.tag = ? AND d.day >= ?
            GROUP BY d.username, d.password
            ORDER BY attempts DESC
            LIMIT 5
            """,
            (r["tag"], cut_day),
        )
    return {"built": True, "window_days": days, "campaigns": rows}


def top_pairs(con, days=30, limit=25):
    """Most attempted pairs inside the window."""
    if not db.table_exists(con, "cred_pair_daily"):
        return []
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]
    return db.qall(
        con,
        """
        SELECT username, password, SUM(attempts) attempts,
               SUM(successes) successes, MAX(src_ips) distinct_ips,
               MIN(day) first_seen, MAX(day) last_seen
        FROM cred_pair_daily WHERE day >= ?
        GROUP BY username, password
        ORDER BY attempts DESC LIMIT ?
        """,
        (cut_day, int(limit)),
    )


def campaign_detail(con, tag, days=30, limit=100):
    if not db.table_exists(con, "cred_pair_daily"):
        return {"built": False}
    ts = db.TsExpr(con)
    cut_day = str(ts.cutoff(days))[:10]
    pairs = db.qall(
        con,
        """
        SELECT d.username, d.password, SUM(d.attempts) attempts,
               SUM(d.successes) successes, MAX(d.src_ips) distinct_ips,
               MIN(d.day) first_seen, MAX(d.day) last_seen
        FROM cred_pair_tags t
        JOIN cred_pair_daily d
          ON d.username = t.username AND d.password = t.password
        WHERE t.tag = ? AND d.day >= ?
        GROUP BY d.username, d.password
        ORDER BY attempts DESC
        LIMIT ?
        """,
        (tag, cut_day, limit),
    )
    ips = db.qall(
        con,
        "SELECT src_ip, attempts FROM cred_tag_ips WHERE tag=? "
        "ORDER BY attempts DESC LIMIT 25",
        (tag,),
    )
    sc = db.source_columns(con)
    if sc["ip"] and ips:
        marks = ",".join("?" for _ in ips)
        meta = {
            r[sc["ip"]]: r
            for r in db.qall(
                con,
                f"SELECT * FROM sources WHERE {sc['ip']} IN ({marks})",
                tuple(i["src_ip"] for i in ips),
            )
        }
        for i in ips:
            m = meta.get(i["src_ip"], {})
            i["asn"] = m.get(sc["asn"]) if sc["asn"] else None
            i["org"] = m.get(sc["org"]) if sc["org"] else None
            i["country"] = m.get(sc["country"]) if sc["country"] else None
    return {
        "built": True,
        "tag": tag,
        "label": tag_labels().get(tag, tag),
        "pairs": pairs,
        "source_ips": ips,
    }
