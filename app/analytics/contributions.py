"""Upstream contributions.

A contribution is a sample this sensor uploaded to a public corpus that did
not already hold it: a payload_submissions row with status 'submitted'. Rows
marked 'duplicate' mean the service already had the file when we checked,
which is useful context for the funnel but is never counted as ours.

For each contribution this module joins three things back together:

  capture context  from sample_provenance, which outlives raw_events retention
  VirusTotal view  from vt_snapshots, one row per lookup, oldest to newest
  attribution      our upload time against VirusTotal's first_submission_date

The attribution check is deliberately conservative. The worker only uploads
after VirusTotal answered 404, but someone else can upload the same file in
the gap between that lookup and our upload. When VirusTotal's first
submission predates ours by more than the tolerance, the sample is shown as
preceded rather than claimed.
"""

import datetime as dt

from . import db

# VirusTotal stamps first_submission_date when it receives the file; we stamp
# submitted_at after the upload call returns. Fifteen minutes absorbs clock
# skew and slow uploads without letting a genuinely earlier submitter through.
FIRST_TOLERANCE_S = 900

SERVICES = ("virustotal", "malwarebazaar")
SERVICE_LABELS = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar"}


def _epoch(iso):
    """'2026-08-24T16:12:25Z' -> epoch seconds, or None."""
    if not iso:
        return None
    try:
        return int(dt.datetime.strptime(str(iso)[:19], "%Y-%m-%dT%H:%M:%S")
                   .replace(tzinfo=dt.timezone.utc).timestamp())
    except ValueError:
        return None


def _iso(epoch):
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def verify_first(submitted_at, first_submission_date, tolerance=FIRST_TOLERANCE_S):
    """Classify our VirusTotal upload against VirusTotal's own record.

    confirmed   VirusTotal's first submission is ours, within tolerance
    preceded    VirusTotal already had it from someone else before our upload
    unverified  we lack either timestamp, so no claim either way
    """
    ours = _epoch(submitted_at)
    if ours is None or first_submission_date is None:
        return "unverified"
    try:
        theirs = int(first_submission_date)
    except (TypeError, ValueError):
        return "unverified"
    return "confirmed" if theirs >= ours - tolerance else "preceded"


def trajectory(snapshots, submitted_at=None):
    """Detection counts at submission and now.

    'initial' is the first snapshot taken at or after our upload, which is the
    closest thing to what VirusTotal said on the day. When every snapshot
    predates the upload (a 404 leaves none), the earliest one stands in.
    """
    snaps = sorted((s for s in snapshots or [] if s.get("fetched_at")),
                   key=lambda s: s["fetched_at"])
    if not snaps:
        return {"initial": None, "current": None, "points": [], "lift": None}
    initial = None
    if submitted_at:
        initial = next((s for s in snaps if s["fetched_at"] >= submitted_at), None)
    initial = initial or snaps[0]
    current = snaps[-1]

    def pick(s):
        return {"at": s["fetched_at"], "malicious": int(s.get("malicious") or 0),
                "engines": int(s.get("engines") or 0)}

    a, b = pick(initial), pick(current)
    return {
        "initial": a,
        "current": b,
        "lift": b["malicious"] - a["malicious"],
        "points": [pick(s) for s in snaps],
    }


def _submitted(con, sha=None):
    """{sha: {service: row}} for rows we actually uploaded."""
    if not db.table_exists(con, "payload_submissions"):
        return {}
    sql = ("SELECT sha256, service, permalink, size_bytes, submitted_at "
           "FROM payload_submissions WHERE status = 'submitted'")
    params = ()
    if sha:
        sql += " AND sha256 = ?"
        params = (sha,)
    out = {}
    for r in db.qall(con, sql, params):
        out.setdefault(r["sha256"], {})[r["service"]] = r
    return out


def _snapshots(con, shas):
    if not shas or not db.table_exists(con, "vt_snapshots"):
        return {}
    out = {}
    shas = list(shas)
    for i in range(0, len(shas), 300):
        part = shas[i:i + 300]
        marks = ",".join("?" for _ in part)
        for r in db.qall(
            con,
            f"SELECT * FROM vt_snapshots WHERE sha256 IN ({marks}) ORDER BY fetched_at",
            tuple(part),
        ):
            out.setdefault(r["sha256"], []).append(r)
    return out


def _by_sha(con, table, key, shas, cols="*"):
    if not shas or not db.table_exists(con, table):
        return {}
    out = {}
    shas = list(shas)
    for i in range(0, len(shas), 300):
        part = shas[i:i + 300]
        marks = ",".join("?" for _ in part)
        for r in db.qall(con, f"SELECT {cols} FROM {table} WHERE {key} IN ({marks})",
                         tuple(part)):
            out[r[key]] = r
    return out


def _labels(con, shas):
    """Vendor label per source, for the table's secondary line."""
    if not shas or not db.table_exists(con, "payload_intel"):
        return {}
    out = {}
    shas = list(shas)
    for i in range(0, len(shas), 300):
        part = shas[i:i + 300]
        marks = ",".join("?" for _ in part)
        for r in db.qall(
            con,
            f"SELECT indicator, source, label FROM payload_intel "
            f"WHERE kind = 'sha256' AND indicator IN ({marks})",
            tuple(part),
        ):
            if r["label"]:
                out.setdefault(r["indicator"], {})[r["source"]] = r["label"]
    return out


def _build(con, subs):
    shas = list(subs)
    snaps = _snapshots(con, shas)
    prov = _by_sha(con, "sample_provenance", "sha256", shas)
    fams = _by_sha(con, "payload_families", "shasum", shas,
                   "shasum, family, confidence")
    labels = _labels(con, shas)

    items = []
    for sha, svc in subs.items():
        vt = svc.get("virustotal")
        s = snaps.get(sha, [])
        firsts = [x["first_submission_date"] for x in s
                  if x.get("first_submission_date") is not None]
        first_sub = min(firsts) if firsts else None
        traj = trajectory(s, vt["submitted_at"] if vt else None)
        p = prov.get(sha) or {}
        f = fams.get(sha) or {}
        earliest = min((r["submitted_at"] or "" for r in svc.values()), default="")
        items.append({
            "sha256": sha,
            "services": {
                k: {"submitted_at": v["submitted_at"], "permalink": v["permalink"],
                    "label": SERVICE_LABELS.get(k, k)}
                for k, v in svc.items()
            },
            "first_contributed": earliest or None,
            "size_bytes": next((v["size_bytes"] for v in svc.values()
                                if v.get("size_bytes")), None),
            "vt_first_submission": _iso(first_sub),
            "attribution": verify_first(vt["submitted_at"], first_sub) if vt else None,
            "detections": traj,
            "family": f.get("family"),
            "family_confidence": f.get("confidence"),
            "labels": labels.get(sha, {}),
            "capture": {
                "first_seen": p.get("first_seen"),
                "last_seen": p.get("last_seen"),
                "sessions": p.get("sessions"),
                "src_ips": p.get("src_ips"),
                "delivery": p.get("delivery"),
                "source_url": p.get("source_url"),
                "host": p.get("host"),
                "first_session": p.get("first_session"),
                "first_src_ip": p.get("first_src_ip"),
            } if p else None,
        })
    items.sort(key=lambda r: r["first_contributed"] or "", reverse=True)
    return items


def contributions(con, limit=200):
    """Every contribution, newest first."""
    items = _build(con, _submitted(con))
    return items[:limit]


def for_sample(con, sha):
    """The contribution record for one hash, or None if we never uploaded it."""
    subs = _submitted(con, sha)
    if not subs:
        return None
    items = _build(con, subs)
    return items[0] if items else None


def summary(con, days=None):
    """Status counts per service, plus the headline numbers.

    Lifetime unless days is given, in which case 'contributed_window' counts
    distinct samples first uploaded inside the window.
    """
    by_service = {s: {"submitted": 0, "duplicate": 0, "skipped": 0, "error": 0}
                  for s in SERVICES}
    if db.table_exists(con, "payload_submissions"):
        for r in db.qall(
            con,
            "SELECT service, status, COUNT(*) AS n FROM payload_submissions "
            "GROUP BY service, status",
        ):
            by_service.setdefault(r["service"], {})[r["status"]] = r["n"]

    items = contributions(con, limit=100000)
    out = {
        "by_service": by_service,
        "contributed_samples": len(items),
        "confirmed_first": sum(1 for i in items if i["attribution"] == "confirmed"),
        "preceded": sum(1 for i in items if i["attribution"] == "preceded"),
        "unverified": sum(1 for i in items if i["attribution"] == "unverified"),
    }
    if days is not None:
        days = db.clamp_days(days, default=30)
        cut = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).strftime(
            "%Y-%m-%d")
        out["window_days"] = days
        out["contributed_window"] = sum(
            1 for i in items if (i["first_contributed"] or "")[:10] >= cut)
    return out
