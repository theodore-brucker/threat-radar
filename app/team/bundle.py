"""One Eastern day of sensor activity, gathered for the team.

build() opens nothing itself: it is handed a read-only connection and answers
a document with two halves.

`sections` is what the reader stage is shown. It uses the section shapes of
app/analytics/export.py and is rendered by that module, so every recorded
value is cleaned, every list is capped with the cap reported, and all of it
sits inside the fence.

`index` is for code. It holds the day's numbers for the charts and the
report, the command clusters by shape, and the set of indicators that
appeared in the day. Later stages may only name an indicator or a shape that
is in the index, which is how a value a model made up, or was talked into,
is kept out of the web lookups and the knowledge base.

A day's numbers are compared with the days before it only as far back as the
current persona and the last cutover, because earlier days measured a
different host.
"""

import datetime as dt
import hashlib
import json
import re
import statistics

from app.analytics import clock, db, export, fingerprints, health, persona, tunnels

SCHEMA = "threat-radar.team-bundle/1"

BASELINE_DAYS = 14          # days of history a day is compared with, at most
MAX_COMMAND_EVENTS = 50000  # command events read for one day
MAX_CLUSTERS = 15           # command clusters listed
MAX_EXEMPLARS = 8           # sessions expanded into a full event record
MAX_DOCUMENT_CHARS = 160000  # size of the document the reader is shown

METRICS = ("events", "addresses", "sessions", "logins", "successes",
           "commands", "downloads", "uploads", "tunnels")
COMMAND_EVENTS = ("cowrie.command.input", "cowrie.command.failed")
CONNECT_EVENT = "cowrie.session.connect"

FUNNEL = [
    ("connected", "Sessions"),
    ("attempted", "Tried a login"),
    ("authed", "Logged in"),
    ("ran_commands", "Ran commands"),
    ("moved_files", "Moved files"),
]

# What varies between two runs of the same script: where it fetches from and
# what it names things. Replacing those leaves the script's shape.
_VARIABLE = [
    (re.compile(r"(?i)\b(?:https?|ftp|tftp)://\S+"), "<url>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hex>"),
    (re.compile(r"[A-Za-z0-9+/=]{24,}"), "<blob>"),
    (re.compile(r"\d{4,}"), "<n>"),
]


def shape_id(commands):
    """A stable name for a command sequence with its variable parts removed.

    Two sessions get the same id when they typed the same script, even if
    each fetched from a different address or wrote to a different random
    file name.
    """
    lines = []
    for command in commands:
        text = " ".join(str(command or "").split())
        for pattern, token in _VARIABLE:
            text = pattern.sub(token, text)
        lines.append(text)
    digest = hashlib.sha256("\n".join(lines).encode("utf-8", "replace")).hexdigest()
    return "c-" + digest[:10]


def _first_day(con, day):
    """The first day `day` can be compared with, and the persona live on it."""
    d = dt.date.fromisoformat(day)
    first = (d - dt.timedelta(days=BASELINE_DAYS)).isoformat()
    epoch = persona.epoch_for(con, day)
    if epoch:
        first = max(first, epoch["start_day"])
    floor = db.data_floor(con)
    if floor:
        first = max(first, clock.day(floor) or floor[:10])
    return first, epoch


def _daily(con, first, day):
    return db.qall(con, """
        SELECT day, SUM(events) events, COUNT(DISTINCT src_ip) addresses,
               SUM(sessions) sessions, SUM(logins) logins, SUM(successes) successes,
               SUM(commands) commands, SUM(downloads) downloads,
               SUM(uploads) uploads, SUM(tunnels) tunnels
          FROM asn_ip_daily WHERE day >= ? AND day <= ?
         GROUP BY day ORDER BY day""", (first, day))


def _metrics(rows, day):
    today = next((r for r in rows if r["day"] == day), None)
    before = [r for r in rows if r["day"] < day]
    out = {}
    for name in METRICS:
        history = [r[name] or 0 for r in before]
        out[name] = {
            "value": (today or {}).get(name) or 0,
            "median": statistics.median(history) if history else None,
            "days": len(history),
        }
    return out


def _funnel(con, day):
    row = db.qone(con, """
        SELECT COUNT(*) connected, SUM(attempted > 0) attempted, SUM(authed > 0) authed,
               SUM(commands > 0) ran_commands, SUM(downloads + uploads > 0) moved_files
          FROM session_facts WHERE day = ?""", (day,)) or {}
    return [{"key": key, "label": label, "sessions": row.get(key) or 0}
            for key, label in FUNNEL]


def _hours(con, ts, lo, hi):
    """Sessions opened in each Eastern hour of the day, 24 values."""
    rows = db.qall(con, f"""
        SELECT substr({ts.iso}, 1, 13) hour, COUNT(*) n FROM v_events
         WHERE eventid = ? AND ts >= ? AND ts < ? GROUP BY hour""",
                   (CONNECT_EVENT, lo, hi))
    counts = [0] * 24
    for r in rows:
        local = clock.local(str(r["hour"]) + ":00:00Z")
        if local is not None:
            counts[local.hour] += r["n"]
    return counts


def _stages(con, day):
    rows = db.qall(con, "SELECT stage, COUNT(*) addresses FROM source_stage_daily "
                        "WHERE day = ? GROUP BY stage ORDER BY stage", (day,))
    names = export.STAGES
    return [{"stage": r["stage"], "addresses": r["addresses"],
             "meaning": names[r["stage"]] if 0 <= r["stage"] < len(names) else ""}
            for r in rows]


def _furthest(con, day):
    return db.qall(con, """
        SELECT d.src_ip, d.stage, d.sessions, d.commands, d.transfers,
               s.asn, s.org, s.country, s.first_seen
          FROM source_stage_daily d LEFT JOIN source_stage s ON s.src_ip = d.src_ip
         WHERE d.day = ? AND d.stage >= 2
         ORDER BY d.stage DESC, d.sessions DESC LIMIT 15""", (day,))


def _networks(con, first, day):
    rows = db.qall(con, """
        SELECT asn, MAX(org) org, MAX(country) country, COUNT(*) addresses,
               SUM(sessions) sessions, SUM(logins) logins, SUM(successes) successes,
               SUM(commands) commands
          FROM asn_ip_daily WHERE day = ? GROUP BY asn
         ORDER BY sessions DESC LIMIT 12""", (day,))
    seen = {r["asn"] for r in db.qall(
        con, "SELECT DISTINCT asn FROM asn_ip_daily WHERE day >= ? AND day < ?",
        (first, day))}
    for r in rows:
        r["new_in_window"] = r["asn"] not in seen if first < day else None
    return rows


def _countries(con, day):
    return db.qall(con, """
        SELECT country, COUNT(*) addresses, SUM(sessions) sessions
          FROM asn_ip_daily WHERE day = ? GROUP BY country
         ORDER BY sessions DESC LIMIT 8""", (day,))


def _credentials(con, day, lo, hi):
    top = db.qall(con, """
        SELECT username, password, attempts, successes, src_ips
          FROM cred_pair_daily WHERE day = ? ORDER BY attempts DESC LIMIT 15""", (day,))
    accepted = db.qall(con, """
        SELECT username, password, successes, src_ips
          FROM cred_pair_daily WHERE day = ? AND successes > 0
         ORDER BY successes DESC LIMIT 15""", (day,))
    new = db.qall(con, """
        SELECT username, password, attempts, distinct_ips
          FROM cred_pairs WHERE first_seen >= ? AND first_seen < ?
         ORDER BY attempts DESC LIMIT 20""", (lo, hi))
    new_total = (db.qone(con, "SELECT COUNT(*) n FROM cred_pairs "
                              "WHERE first_seen >= ? AND first_seen < ?", (lo, hi))
                 or {}).get("n") or 0
    themes = db.qall(con, """
        SELECT t.tag, SUM(d.attempts) attempts, COUNT(*) pairs
          FROM cred_pair_daily d JOIN cred_pair_tags t
            ON t.username = d.username AND t.password = d.password
         WHERE d.day = ? GROUP BY t.tag ORDER BY attempts DESC LIMIT 10""", (day,))
    return top, accepted, new, new_total, themes


def _clients(con, first, day):
    rows = db.qall(con, """
        SELECT hassh, version, sessions, src_ips FROM client_fp_daily
         WHERE day = ? ORDER BY sessions DESC LIMIT 10""", (day,))
    seen = {r["hassh"] for r in db.qall(
        con, "SELECT DISTINCT hassh FROM client_fp_daily WHERE day >= ? AND day < ?",
        (first, day))}
    for r in rows:
        r["new_in_window"] = r["hassh"] not in seen if first < day else None
        r["known_as"] = (fingerprints.describe(r["hassh"]) or {}).get("name")
    return rows


def _tunnels(con, day):
    rows = db.qall(con, """
        SELECT dst_ip, dst_port, requests, sessions, src_ips FROM tunnel_targets
         WHERE day = ? ORDER BY requests DESC LIMIT 15""", (day,))
    for r in rows:
        r["service"], r["likely_use"] = tunnels.port_intent(int(r["dst_port"] or 0))
    return rows


def _files(con, day, lo, hi):
    rows = db.qall(con, """
        SELECT p.shasum, p.direction, p.url, p.host, p.filename, p.hits,
               p.sessions, p.src_ips, v.delivery, v.first_seen
          FROM payload_daily p LEFT JOIN sample_provenance v ON v.sha256 = p.shasum
         WHERE p.day = ? AND p.shasum <> '' ORDER BY p.hits DESC LIMIT 25""", (day,))
    for r in rows:
        first = r.pop("first_seen") or ""
        r["new_today"] = bool(first) and lo <= first < hi
        intel = db.qall(con, "SELECT source, verdict, malicious, label FROM payload_intel "
                             "WHERE indicator = ?", (r["shasum"],))
        r["verdicts"] = ", ".join(
            "%s: %s%s" % (i["source"], i["verdict"],
                          " (%d engines)" % i["malicious"] if i["malicious"] else "")
            for i in intel) or "not looked up yet"
        family = (db.qone(con, "SELECT family FROM payload_families WHERE shasum = ?",
                          (r["shasum"],)) if db.table_exists(con, "payload_families")
                  else None)
        r["family"] = (family or {}).get("family")
    return rows


def _session_meta(con, day):
    """session -> its session_facts row, for sessions of this day and the day
    before, since a session that opens before midnight types after it."""
    before = (dt.date.fromisoformat(day) - dt.timedelta(days=1)).isoformat()
    rows = db.qall(con, """
        SELECT session, src_ip, username, client, downloads, uploads, tunnels, commands
          FROM session_facts WHERE day IN (?, ?)""", (before, day))
    return {r["session"]: r for r in rows}


def _clusters(con, lo, hi, meta, networks_of, known, watch, limits):
    """Group the day's shell sessions by the shape of what they typed."""
    events = db.qall(con, """
        SELECT session, src_ip, ts, json_extract(payload, '$.input') input
          FROM v_events WHERE eventid IN (?, ?) AND ts >= ? AND ts < ?
         ORDER BY session, ts, id LIMIT ?""",
                     (*COMMAND_EVENTS, lo, hi, MAX_COMMAND_EVENTS))
    if len(events) >= MAX_COMMAND_EVENTS:
        limits.append("Command clusters: the first %d command events of the day "
                      "were read, and there were more." % MAX_COMMAND_EVENTS)

    sessions = {}
    for e in events:
        s = sessions.setdefault(e["session"], {"src_ip": e["src_ip"], "first": e["ts"],
                                               "last": e["ts"], "commands": []})
        s["commands"].append(e["input"] or "")
        s["last"] = e["ts"]

    clusters = {}
    for sid, s in sessions.items():
        shape = shape_id(s["commands"])
        c = clusters.setdefault(shape, {
            "shape": shape, "sessions": 0, "ips": set(), "users": {}, "clients": {},
            "networks": {}, "files": 0, "first_seen": s["first"], "last_seen": s["last"],
            "commands": len(s["commands"]), "example": sid, "watch": []})
        c["sessions"] += 1
        c["ips"].add(s["src_ip"])
        c["first_seen"] = min(c["first_seen"], s["first"])
        c["last_seen"] = max(c["last_seen"], s["last"])
        facts = meta.get(sid) or {}
        for bucket, value in (("users", facts.get("username")),
                              ("clients", facts.get("client")),
                              ("networks", networks_of.get(s["src_ip"]))):
            if value:
                c[bucket][value] = c[bucket].get(value, 0) + 1
        if (facts.get("downloads") or 0) + (facts.get("uploads") or 0) > 0:
            c["files"] += 1
        text = "\n".join(s["commands"])
        for needle in watch:
            if needle in text and needle not in c["watch"]:
                c["watch"].append(needle)
                c["example"] = sid

    def top(counts, n):
        return ", ".join("%s (%d)" % (k, v) for k, v in
                         sorted(counts.items(), key=lambda kv: -kv[1])[:n])

    out = []
    for c in sorted(clusters.values(), key=lambda c: (-c["sessions"], c["shape"])):
        out.append({
            "shape": c["shape"],
            "known_as": (known.get(c["shape"]) or {}).get("campaign") or "",
            "sessions": c["sessions"],
            "addresses": len(c["ips"]),
            "networks": top(c["networks"], 3),
            "logins": top(c["users"], 3),
            "clients": top(c["clients"], 2),
            "commands_typed": c["commands"],
            "sessions_with_files": c["files"],
            "first_seen": c["first_seen"], "last_seen": c["last_seen"],
            "example_session": c["example"],
            "watched": ", ".join(c["watch"]),
            "ips": sorted(c["ips"]),
        })
    return out


def _file_only_sessions(con, day):
    return db.qall(con, """
        SELECT session, src_ip, first_seen, username, client, downloads, uploads
          FROM session_facts
         WHERE day = ? AND commands = 0 AND downloads + uploads > 0
         ORDER BY first_seen LIMIT 25""", (day,))


def _exemplars(clusters, file_only):
    """Which sessions to expand: watched paths first, then clusters that moved
    files, then clusters the knowledge base has not seen, then the rest."""
    def rank(c):
        return (not c["watched"], c["sessions_with_files"] == 0,
                bool(c["known_as"]), -c["sessions"])
    ids = [c["example_session"] for c in sorted(clusters, key=rank)]
    return ids[:MAX_EXEMPLARS - 2] + [s["session"] for s in file_only[:2]] \
        + ids[MAX_EXEMPLARS - 2:]


def _file_summaries(con, shas, limits):
    """What each new file is. The worker reads samples through a group, and
    a file it cannot open must not cost the day's report."""
    try:
        return export.file_summaries(con, shas, limits)
    except OSError as exc:
        limits.append("File summaries: the sample files could not be read (%s), so "
                      "the new files are described by their lookups only."
                      % type(exc).__name__)
        return export.file_summaries(con, [], limits)


def _pipeline(con, hi):
    status = health.status(con)
    times = {i["key"]: i for i in status["items"]}
    facts_at = clock.parse((times.get("facts") or {}).get("at"))
    day_end = clock.parse(hi)
    return {
        "newest_event": (times.get("events") or {}).get("at_local"),
        "newest_login_attempt": (times.get("login_attempt") or {}).get("at_local"),
        "daily_facts_rebuilt": (times.get("facts") or {}).get("at_local"),
        "reputation_lookups_ran": (times.get("intel") or {}).get("at_local"),
        "complete": bool(facts_at and day_end and facts_at >= day_end),
    }


def build(con, day, known=None, watch=()):
    """The bundle for one Eastern day.

    known maps a shape id to the knowledge base's record of it, and watch is
    a list of strings (decoy paths, for instance) whose appearance in a
    command is called out. Both come from the private knowledge base.
    """
    known = known or {}
    watch = [w for w in watch if w]
    limits = []
    ts = db.TsExpr(con)
    lo, hi = ts.day_range(day)
    first, epoch = _first_day(con, day)

    daily = _daily(con, first, day)
    metrics = _metrics(daily, day)
    funnel = _funnel(con, day)
    networks = _networks(con, first, day)
    top, accepted, new_pairs, new_total, themes = _credentials(con, day, lo, hi)
    clients = _clients(con, first, day)
    relay = _tunnels(con, day)
    files = _files(con, day, lo, hi)
    furthest = _furthest(con, day)
    meta = _session_meta(con, day)
    networks_of = {r["src_ip"]: r["asn"] for r in db.qall(
        con, "SELECT src_ip, asn FROM asn_ip_daily WHERE day = ?", (day,))}
    clusters = _clusters(con, lo, hi, meta, networks_of, known, watch, limits)
    file_only = _file_only_sessions(con, day)
    pipeline = _pipeline(con, hi)
    spike = db.qone(con, "SELECT events, baseline, ratio, headline FROM spike_annotations "
                         "WHERE day = ?", (day,))

    if len(clusters) > MAX_CLUSTERS:
        limits.append("Command clusters: the %d largest of %d are listed."
                      % (MAX_CLUSTERS, len(clusters)))
    if not pipeline["complete"]:
        limits.append("The per-day tables were last rebuilt at %s, before this day "
                      "ended, so its last hours may be missing from the counts."
                      % (pipeline["daily_facts_rebuilt"] or "an unknown time"))
    if metrics["sessions"]["days"] < 3:
        limits.append("%s comparable with this one, because the sensor changed "
                      "recently. Treat the medians as weak."
                      % {0: "No earlier day is", 1: "Only one earlier day is",
                         2: "Only two earlier days are"}[metrics["sessions"]["days"]])

    shown = clusters[:MAX_CLUSTERS]
    examples = _exemplars(shown, file_only)
    if len(examples) > MAX_EXEMPLARS:
        limits.append("Session records: %d of %d example sessions are expanded, those "
                      "that touched a watched path or moved a file first."
                      % (MAX_EXEMPLARS, len(examples)))
    table, facts = export.table_section, export.facts_section
    cluster_rows = [{k: v for k, v in c.items() if k != "ips"} for c in shown]
    sections = [
        facts("totals", "The day in numbers", {
            name: {"value": m["value"], "median_of_earlier_days": m["median"]}
            for name, m in metrics.items()},
            "Each count beside its median over the %d earlier comparable days."
            % metrics["sessions"]["days"]),
        table(limits, "funnel", "How far sessions got", funnel),
        table(limits, "stages", "Addresses by furthest stage", _stages(con, day)),
        table(limits, "furthest", "Addresses that reached a shell or moved files",
              furthest, "Stage 2 and above, furthest first."),
        table(limits, "networks", "Networks", networks,
              "By sessions. new_in_window means the network sent nothing in the "
              "earlier comparable days, and is empty when there are none."),
        table(limits, "countries", "Countries", _countries(con, day)),
        table(limits, "credentials", "Credential pairs tried most", top),
        table(limits, "accepted", "Credential pairs the sensor accepted", accepted),
        table(limits, "new_pairs", "Credential pairs first seen this day", new_pairs,
              "%d pairs were new this day. The most tried are listed." % new_total),
        table(limits, "themes", "Credential themes", themes,
              "Attempts grouped by the rule each pair matched."),
        table(limits, "clients", "SSH clients", clients,
              "hassh is a hash of the SSH algorithm offer. known_as names a "
              "library many unrelated tools share."),
        table(limits, "clusters", "Command clusters", cluster_rows,
              "Shell sessions grouped by the shape of what they typed, with "
              "addresses, URLs and long numbers removed before comparing. "
              "known_as is the campaign the knowledge base already files this "
              "shape under. example_session is expanded below when it is one "
              "of the sessions chosen."),
        table(limits, "file_only", "Sessions that moved files without a shell", file_only),
        table(limits, "files", "Files moved", files,
              "A file with no URL was pushed in-band or uploaded."),
        table(limits, "relay", "Relay requests", relay,
              "Port-forwarding requests. The sensor records them and carries "
              "none of them out."),
        export.session_records(con, examples[:MAX_EXEMPLARS], limits, cap=MAX_EXEMPLARS),
        _file_summaries(con, [f["shasum"] for f in files if f["new_today"]], limits),
        facts("pipeline", "When the pipeline last ran", pipeline),
    ]
    if spike:
        sections.insert(1, facts("spike", "Volume spike", spike))

    indicators = {
        "ip": sorted({r["src_ip"] for r in furthest}
                     | {ip for c in shown for ip in c["ips"][:5]}
                     | {s["src_ip"] for s in file_only}),
        "sha256": sorted({f["shasum"] for f in files}),
        "host": sorted({f["host"] for f in files if f["host"]}),
        "family": sorted({f["family"] for f in files if f["family"]}),
        "asn": sorted({r["asn"] for r in networks if r["asn"] and r["asn"] != "unknown"}),
        "hassh": sorted({r["hassh"] for r in clients}),
    }
    sections = clock.localize(sections)
    if export.REDACT:
        sections = export.redact(sections)

    return {
        "schema": SCHEMA,
        "day": day,
        "generated_at": clock.iso(clock.now()),
        "context": export.reading_context(con),
        "sections": sections,
        "limits": limits,
        "index": {
            "day": day,
            "empty": metrics["events"]["value"] == 0,
            "persona": epoch["name"] if epoch else None,
            "persona_since": epoch["start_day"] if epoch else None,
            "compared_from": first,
            "metrics": metrics,
            "series": [{"day": r["day"], "sessions": r["sessions"] or 0,
                        "addresses": r["addresses"] or 0} for r in daily],
            "hours": _hours(con, ts, lo, hi),
            "funnel": funnel,
            "networks": [{k: r[k] for k in ("asn", "org", "country", "sessions",
                                            "addresses", "new_in_window")}
                         for r in networks],
            "clusters": [{k: c[k] for k in ("shape", "known_as", "sessions", "addresses",
                                            "sessions_with_files", "watched")}
                         for c in clusters],
            "files": [{k: f[k] for k in ("shasum", "new_today", "verdicts", "family")}
                      for f in files],
            "indicators": indicators,
            "pipeline": pipeline,
        },
    }


def document(bundle, tag=None):
    """The bundle as the text the reader stage is shown, and the fence tag."""
    tag = tag or export.new_tag()
    ctx = bundle["context"]
    index = bundle["index"]
    sections = list(bundle["sections"])
    limits = list(bundle["limits"])

    def render():
        out = ["# Threat Radar daily record: %s" % bundle["day"], "",
               "## How to read this", ""]
        out += ["- " + line for line in ctx["reading"]]
        if index["persona"]:
            out.append("- Since %s the sensor has presented itself as: %s."
                       % (index["persona_since"], index["persona"]))
        out.append("- Earlier days are compared from %s onward." % index["compared_from"])
        out += ["", "### Escalation stages", ""]
        out += ["- %d: %s" % (s["stage"], s["meaning"]) for s in ctx["stages"]]
        out += ["", ctx["stage_note"], "", "### Data handling", "",
                "- " + export.fence_rule(tag)]
        out += ["- " + line for line in ctx["handling"][1:]]
        out.append("")
        out += export.render_sections(sections, tag)
        out += ["## Limits of this record", ""]
        out += ["- " + line for line in limits] or ["No list reached its cap."]
        return "\n".join(out) + "\n"

    text = render()
    # The session records are the only part without a fixed size. Drop them
    # from the end until the document fits, and say how many went.
    position = next((i for i, s in enumerate(sections) if s["kind"] == "sessions"), None)
    dropped = 0
    while len(text) > MAX_DOCUMENT_CHARS and position is not None \
            and sections[position]["data"]:
        sections[position] = dict(sections[position],
                                  data=sections[position]["data"][:-1])
        dropped += 1
        limits = list(bundle["limits"]) + [
            "Session records: %d were left out to keep this record within %d "
            "characters." % (dropped, MAX_DOCUMENT_CHARS)]
        text = render()
    return text, tag


def dumps(bundle):
    return json.dumps(bundle, indent=1, sort_keys=True, ensure_ascii=True)
