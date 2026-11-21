"""Incidents, vendors and organizations as documents for a language model.

The bundle has the same shape as app/analytics/export.py (schema, subject,
generated_at, context, sections, limits) so one reader can handle both. The
context describes this dataset and what it cannot support.
"""

import re

from app.analytics import clock
from app.trends import STATUS_LABEL, read

SCHEMA = "threat-radar.trends-export/1"
TYPES = {"incident": "incident", "vendor": "vendor", "organization": "organization"}

CONTEXT = [
    "This is a record from the incident trends section of Threat Radar, a "
    "personal project. It tracks disruptive incidents at US organizations "
    "from public reporting and tags each with the cause its sources stated.",
    "Cause status has three values: a malicious cause was stated; no cause or "
    "a vague one was stated; a non-malicious or precautionary cause was "
    "stated. It records what was said, not what happened.",
    "Rows with source seed came from the DysruptionHub registry, and their "
    "cause status was assigned by a model from a one-line summary, so their "
    "confidence is low. Rows from feeds were labelled by keyword rules, and "
    "ambiguous headlines by a small model; those are also low confidence.",
    "Leak-site claims appear as the group name and a link only. The claim "
    "data belongs to Ransomware.live (https://ransomware.live), whose terms "
    "do not allow republishing it.",
    "Dates are US Eastern days. Times are US Eastern, written as ISO 8601 "
    "with their UTC offset.",
]

BRIEF = [
    "You are reviewing this as an incident analyst. Work only from the "
    "evidence above, and say so when it does not support a conclusion.",
    "1. Summary: what happened and when, in two to four sentences.",
    "2. Cause: does the evidence support the recorded cause status? Name the "
    "statement that decides it, or say that none does.",
    "3. Related activity: other organizations, suppliers or vulnerabilities "
    "this record points to, and what would confirm a link.",
    "4. Gaps: what is missing, and where it would most likely be published.",
]


def _clean(rows, keep):
    return [{k: r.get(k) for k in keep} for r in rows]


def build(con, etype, value):
    rec = read.lookup(con, etype, value)
    if rec is None:
        return None
    sections = []
    if etype == "incident":
        facts = {k: rec.get(k) for k in ("id", "kind", "title", "started", "state", "sector", "scope",
                                         "source", "confidence", "org_name", "source_url")}
        facts["cause_status"] = STATUS_LABEL[rec["cause_status"]]
        if rec.get("delay"):
            facts["days_to_first_stated_cause"] = rec["delay"]["days"]
        sections.append({"key": "incident", "kind": "facts", "title": "Incident", "data": facts})
        sections.append({"key": "statements", "kind": "table", "title": "Statements",
                         "rows": _clean(rec["statements"], ("stated_at", "cause_status", "text", "source", "url"))})
        if rec["vendors"]:
            sections.append({"key": "suppliers", "kind": "table", "title": "Suppliers",
                             "rows": _clean(rec["vendors"], ("name", "product", "customers", "note"))})
        if rec["cves"]:
            sections.append({"key": "cves", "kind": "table", "title": "Known exploited vulnerabilities",
                             "rows": _clean(rec["cves"], ("cve_id", "vendor", "product", "kev_added",
                                                          "ransomware_use"))})
        if rec["claims"]:
            sections.append({"key": "claims", "kind": "table", "title": "Leak-site claims",
                             "rows": _clean(rec["claims"], ("actor", "discovered", "post_url"))})
    else:
        facts = {k: rec.get(k) for k in ("name", "product", "state", "sector") if k in rec}
        sections.append({"key": etype, "kind": "facts", "title": TYPES[etype].capitalize(), "data": facts})
        sections.append({"key": "incidents", "kind": "table", "title": "Incidents",
                         "rows": _clean(rec["incidents"], ("id", "started", "title", "cause_status",
                                                           "source", "confidence"))})
    return {
        "schema": SCHEMA,
        "subject": {"type": etype, "label": TYPES[etype], "id": str(value)},
        "generated_at": clock.iso(clock.now()),
        "window_days": None,
        "context": {"about": CONTEXT},
        "sections": clock.localize(sections),
        "limits": [],
    }


def filename(bundle, ext):
    ident = re.sub(r"[^A-Za-z0-9-]", "-", bundle["subject"]["id"])[:64]
    stamp = re.sub(r"[^0-9]", "", bundle["generated_at"])[:12]
    return "threat-radar-%s-%s-%s.%s" % (bundle["subject"]["type"], ident, stamp, ext)


def _cell(v):
    s = "" if v is None else str(v)
    return s.replace("|", "\\|").replace("\n", " ")


def to_markdown(bundle, brief=True):
    out = [f"# Threat Radar {bundle['subject']['label']} {bundle['subject']['id']}", "",
           f"Generated {bundle['generated_at']}.", "", "## About this data", ""]
    out += [f"- {p}" for p in bundle["context"]["about"]]
    for sec in bundle["sections"]:
        out += ["", f"## {sec['title']}", ""]
        if sec["kind"] == "facts":
            out += [f"- {k}: {_cell(v)}" for k, v in sec["data"].items() if v not in (None, "")]
        elif not sec["rows"]:
            out.append("None recorded.")
        else:
            cols = list(sec["rows"][0])
            out.append("| " + " | ".join(cols) + " |")
            out.append("|" + "---|" * len(cols))
            out += ["| " + " | ".join(_cell(r[c]) for c in cols) + " |" for r in sec["rows"]]
    if brief:
        out += ["", "## Request", ""] + BRIEF
    return "\n".join(out) + "\n"
