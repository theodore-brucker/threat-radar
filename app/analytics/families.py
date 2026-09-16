"""Derived malware families.

The site was showing raw vendor strings: 'trojan. [Text]',
'miner.genericrxss/multiverze [ELF]', and in one case a sha256 followed by
'.unknown [unknown]'. None of those answer the question a reader actually
has, which is what families land on this sensor.

This module derives a family name from the labels the vendors already gave
us rather than from a curated map. The rule is simple and stated openly on
the page: strip the parts of a vendor label that describe a *category*
(trojan, downloader, ELF) or a detection artefact (generic, agent, variant,
a hex blob), then take the most-supported token that remains. When vendors
disagree the candidates are kept so the disagreement is visible.

The trade-off is honest to state: derivation follows the vendors, so it
inherits their naming drift, and a family here means "what detection
engines call this", not an attribution claim.
"""

import re
from collections import Counter

# Category words. These describe what the file does, not which family it is.
CATEGORY = {
    "trojan", "virus", "worm", "backdoor", "rootkit", "ransom", "ransomware",
    "downloader", "dropper", "spyware", "adware", "riskware", "hacktool",
    "exploit", "flooder", "ddos", "miner", "coinminer", "cryptominer",
    "packed", "packer", "obfuscated", "malware", "malicious", "pua", "pup",
    "hoax", "joke", "proxy", "banker", "infostealer", "stealer", "webshell",
    "shell", "script", "bot",
}

# Detection artefacts: engine-specific noise that is never a family.
NOISE = {
    "generic", "genericrx", "genericrxss", "gen", "agent", "variant", "heur",
    "heuristic", "unknown", "undetected", "suspicious", "susp", "confidence",
    "ml", "ai", "cloud", "static", "behaveslike", "application", "program",
    "test", "eicar", "multiverze", "artemis", "unsafe", "reputation",
    "malware1", "malware2", "trojanx", "score", "sf", "ct", "attribute",
    "virustotal", "urlhaus", "abuse", "listed", "hosted",
}

# Platform and file-type tokens, usually inside the bracketed suffix.
PLATFORM = {
    "elf", "linux", "unix", "win", "win32", "win64", "w32", "w64", "msil",
    "android", "osx", "macos", "python", "perl", "php", "js", "vbs", "bash",
    "sh", "text", "html", "java", "doc", "pdf", "arm", "mips", "x86", "x64",
    "i386", "amd64", "ppc", "sparc", "sh4", "m68k", "data", "binary",
}

DROP = CATEGORY | NOISE | PLATFORM

# The worker writes status strings into the same label column ("not in
# VirusTotal", "not listed", "auth key rejected or missing", "http 404").
# They are bookkeeping, not vendor naming, and tokenizing them produced a
# family called "virustotal".
STATUS = re.compile(
    r"^\s*(not in |not listed|auth key|http \d|error|\d+ malware url)", re.I)

HEXISH = re.compile(r"^[0-9a-f]{6,}$", re.I)
VERSIONISH = re.compile(r"^[a-z]{1,2}\d{1,6}$", re.I)   # engine suffixes: ab12, c4
SPLIT = re.compile(r"[^A-Za-z0-9]+")

# A family this short is almost always an engine abbreviation.
MIN_LEN = 3


def tokens(label):
    """Family candidates from one vendor label, most significant first.

    VirusTotal's suggested_threat_label is 'category.family/family', and the
    worker appends ' [type_description]'. urlhaus gives a bare signature.
    Both reduce to the same thing: split, drop what cannot be a family.
    """
    if not label:
        return []
    text = str(label)
    if STATUS.match(text):
        return []
    # The bracketed suffix is a file type the worker appended, never a family.
    text = re.sub(r"\[[^\]]*\]", " ", text)
    out = []
    for raw in SPLIT.split(text):
        t = raw.strip().lower()
        if not t or len(t) < MIN_LEN:
            continue
        if t in DROP or HEXISH.match(t) or VERSIONISH.match(t):
            continue
        if t.isdigit():
            continue
        if t not in out:
            out.append(t)
    return out


def derive(records):
    """Pick a family from several vendor records for one indicator.

    records: [{"source": ..., "label": ..., "verdict": ...}]

    Returns {family, confidence, basis, candidates, sources} where confidence
    is how many distinct vendors offered the winning token. None when no
    record carries anything family-shaped, which is a real and common answer
    for commodity samples.
    """
    votes = Counter()
    by_source = {}
    for rec in records or []:
        # Only engines that actually flagged the sample get a vote. A label
        # attached to an "unknown" or "error" record is a status string.
        if (rec.get("verdict") or "").lower() not in ("malicious", "suspicious"):
            continue
        src = rec.get("source") or "?"
        cand = tokens(rec.get("label"))
        if not cand:
            continue
        by_source[src] = cand
        # First token of a label carries the most weight; later ones are
        # alternates the engine listed after a slash.
        for i, t in enumerate(cand):
            votes[t] += 2 if i == 0 else 1

    if not votes:
        return None

    family, _ = votes.most_common(1)[0]
    supporting = sorted(s for s, c in by_source.items() if family in c)
    candidates = [t for t, _ in votes.most_common(5)]
    return {
        "family": family,
        "confidence": "agreed" if len(supporting) > 1
                      else "single-vendor" if supporting else "derived",
        "basis": "; ".join(f"{s}: {', '.join(c[:3])}" for s, c in sorted(by_source.items())),
        "candidates": candidates,
        "sources": supporting,
    }


def rebuild(con):
    """Derive a family for every hash that has vendor labels.

    Cheap: payload_intel is one row per indicator per source and is already
    small. Rebuilt whole on each pass so a changed vendor label or an
    improved token list takes effect without a backfill flag.
    """
    from . import db

    if not db.table_exists(con, "payload_families"):
        return 0
    rows = db.qall(
        con,
        "SELECT indicator, source, label, verdict FROM payload_intel"
        " WHERE kind='sha256' AND label IS NOT NULL AND label <> ''"
        "   AND verdict IN ('malicious','suspicious')",
    )
    grouped = {}
    for r in rows:
        grouped.setdefault(r["indicator"], []).append(r)

    con.execute("DELETE FROM payload_families")
    n = 0
    for sha, recs in grouped.items():
        got = derive(recs)
        if not got:
            continue
        con.execute(
            "INSERT OR REPLACE INTO payload_families"
            "(shasum, family, confidence, basis, candidates, derived_at)"
            " VALUES(?,?,?,?,?,?)",
            (sha, got["family"], got["confidence"], got["basis"],
             ",".join(got["candidates"]), db.utcnow()),
        )
        n += 1
    con.commit()
    return n


def overview(con, days=30, limit=20):
    """Families seen in the window, ranked by distinct samples."""
    from . import db

    if not db.table_exists(con, "payload_families"):
        return {"built": False, "families": []}
    ts = db.TsExpr(con)
    cut = str(ts.cutoff(db.clamp_days(days, default=30)))[:10]
    rows = db.qall(
        con,
        """
        SELECT f.family,
               COUNT(DISTINCT f.shasum) AS samples,
               SUM(p.hits)              AS transfers,
               MIN(f.confidence)        AS confidence,
               MAX(p.last_seen)         AS last_seen
        FROM payload_families f
        JOIN payloads p ON p.shasum = f.shasum
        WHERE substr(p.last_seen,1,10) >= ?
        GROUP BY f.family
        ORDER BY samples DESC, transfers DESC
        LIMIT ?
        """,
        (cut, int(limit)),
    )
    unnamed = db.qone(
        con,
        """
        SELECT COUNT(DISTINCT p.shasum) n FROM payloads p
        LEFT JOIN payload_families f ON f.shasum = p.shasum
        WHERE p.shasum <> '' AND f.shasum IS NULL
          AND substr(p.last_seen,1,10) >= ?
        """,
        (cut,),
    ) or {}
    return {"built": True, "families": rows,
            "unnamed_samples": unnamed.get("n") or 0}
