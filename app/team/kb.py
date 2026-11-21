"""The knowledge base: Markdown pages a person reads, and the state the next
run reads.

The knowledge base is a private git repository. The worker never writes into
it. load() reads the publisher's clone, and apply() answers the files one day
changes as {relative path: text}. The worker leaves those in its outbox, and
the publisher copies in only the paths app/team/outbox.py allows.

Layout, with who writes each part:

  campaigns/<slug>.md     one page per campaign                    this module
  techniques/<id>.md      one page per ATT&CK technique seen        this module
  INDEX.md                the front page                            this module
  state/campaigns.json    shape to campaign, and activity by day    this module
  state/lessons.json      lessons already given                     this module
  state/suggestions.json  suggestions already raised                publisher
  daily/, charts/, drafts/                                          report.py, charts.py
  feedback.md, context/   the operator's steering and private       the operator
                          detail about the sensor

A page is front matter of `key: value` lines followed by `## ` sections. This
module owns that format in both directions, so model text only ever lands
inside a section body, after md_text() has taken out anything that could
start a heading, an image or markup.
"""

import copy
import datetime as dt
import json
import os
import re

from app.analytics.sessions import defang

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,59}\Z")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?\Z")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")

ACTIVE_DAYS = 1         # seen this recently: active
QUIET_DAYS = 14         # seen this recently: quiet, and after that dormant
HISTORICAL = "historical"
MAX_LESSONS = 60

STATUS_ORDER = {"active": 0, "quiet": 1, "dormant": 2, HISTORICAL: 3}


# ---------------------------------------------------------------------------
# text
# ---------------------------------------------------------------------------

def md_text(value, limit=2000, headings=False):
    """Model text made safe to sit inside a section of a page.

    The text may have been shaped by an attacker, so it must not be able to
    open a section, close the front matter, embed an image that calls out
    when the page is viewed, carry markup, or leave a live link to attacker
    infrastructure. headings lets a draft keep its own headings, on a page
    nothing parses.
    """
    text = "".join(ch for ch in str(value or "")[:limit]
                   if ch.isprintable() or ch == "\n")
    text = defang(text).replace("<", "&lt;").replace("![", "[")
    blocked = ("---", "```") if headings else ("#", "---", "```")
    lines = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith(blocked):
            line = "\\" + stripped
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def one_line(value, limit=200):
    return " ".join(md_text(value, limit).split())


def code(value, limit=200):
    """A recorded value as inline code, which a page shows without reading."""
    return "`%s`" % one_line(value, limit).replace("`", "'")


# ---------------------------------------------------------------------------
# pages
# ---------------------------------------------------------------------------

def parse_page(text):
    """(front matter as a dict, sections as {title: body})."""
    meta, body = {}, text
    if text.startswith("---\n"):
        head, found, rest = text[4:].partition("\n---\n")
        if found:
            for line in head.splitlines():
                key, colon, value = line.partition(":")
                if colon:
                    meta[key.strip()] = value.strip()
            body = rest
    sections, current = {}, None
    for line in body.splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return meta, {k: "\n".join(v).strip() for k, v in sections.items()}


def _front(meta):
    return ["---"] + ["%s: %s" % (k, one_line(v, 300)) for k, v in meta.items()] + ["---", ""]


def _split(value):
    return [v.strip() for v in str(value or "").split(",") if v.strip()]


def _lines(body):
    return [ln for ln in (body or "").splitlines() if ln.startswith("- ")]


def _put_day(lines, day, line):
    """Add a dated list line, replacing one already there for that day, so a
    day that is run twice is recorded once."""
    kept = [ln for ln in lines if not ln.startswith("- %s:" % day)]
    return sorted(kept + [line])


def read_campaign(slug, text):
    meta, sections = parse_page(text)

    def number(key):
        try:
            return int(meta.get(key) or 0)
        except ValueError:
            return 0

    return {
        "slug": slug,
        "title": meta.get("title") or slug,
        "status": meta.get("status") or "quiet",
        "persona": meta.get("persona") or "",
        "first_seen": meta.get("first_seen") or "",
        "last_seen": meta.get("last_seen") or "",
        "days_seen": number("days_seen"),
        "sessions": number("sessions"),
        "techniques": [t for t in _split(meta.get("techniques")) if TECHNIQUE_RE.match(t)],
        "shapes": _split(meta.get("shapes")),
        "related": [r for r in _split(meta.get("related")) if SLUG_RE.match(r)],
        "publishable": meta.get("publishable") == "yes",
        "summary": sections.get("Summary", ""),
        "angle": sections.get("Why it may be worth writing up", ""),
        "timeline": _lines(sections.get("Timeline")),
        "indicators": _lines(sections.get("Indicators")),
        "notes": sections.get("Notes", ""),
    }


def _technique_link(technique, pages, up="../"):
    """A link to the technique's own page when there is one, and to MITRE
    until the technique has been seen and has a page."""
    if technique in pages:
        return "[%s](%stechniques/%s.md)" % (technique, up, technique)
    return "[%s](%s)" % (technique, mitre_url(technique))


def mitre_url(technique):
    return "https://attack.mitre.org/techniques/%s/" % technique.replace(".", "/")


def render_campaign(c, pages=()):
    """A campaign page. pages holds the technique ids that have a page."""
    out = _front({
        "title": c["title"], "status": c["status"], "persona": c["persona"],
        "first_seen": c["first_seen"], "last_seen": c["last_seen"],
        "days_seen": c["days_seen"], "sessions": c["sessions"],
        "techniques": ", ".join(c["techniques"]), "shapes": ", ".join(c["shapes"]),
        "related": ", ".join(c["related"]),
        "publishable": "yes" if c["publishable"] else "no",
    })
    out += ["# %s" % one_line(c["title"]), ""]
    if c["status"] != HISTORICAL:
        out += ["![Sessions per day](../charts/campaigns/%s.png)" % c["slug"], ""]
    out += ["## Summary", "", c["summary"] or "No summary yet.", ""]
    if c["publishable"] and c["angle"]:
        out += ["## Why it may be worth writing up", "", c["angle"], ""]
    out += ["## Timeline", ""] + (c["timeline"] or ["- Nothing recorded yet."]) + [""]
    if c["indicators"]:
        out += ["## Indicators", ""] + c["indicators"] + [""]
    if c["techniques"]:
        out += ["## Techniques", ""]
        out += ["- " + _technique_link(t, pages) for t in c["techniques"]] + [""]
    if c["related"]:
        out += ["## Related", ""]
        out += ["- [%s](%s.md)" % (r, r) for r in c["related"]] + [""]
    if c["notes"]:
        out += ["## Notes", "", c["notes"], ""]
    return "\n".join(out)


def status_for(campaign, day):
    if campaign["status"] == HISTORICAL or not campaign["last_seen"]:
        return campaign["status"]
    try:
        gap = (dt.date.fromisoformat(day) - dt.date.fromisoformat(campaign["last_seen"])).days
    except ValueError:
        return campaign["status"]
    if gap <= ACTIVE_DAYS:
        return "active"
    return "quiet" if gap <= QUIET_DAYS else "dormant"


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def _read(root, rel, default=""):
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return default


def _read_json(root, rel, default):
    try:
        value = json.loads(_read(root, rel) or "null")
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def load(root):
    """Everything a run needs from the knowledge base. A missing directory or
    file reads as empty, so the first run and a broken clone both still
    produce a report."""
    campaigns = {}
    try:
        names = sorted(os.listdir(os.path.join(root, "campaigns")))
    except OSError:
        names = []
    for name in names:
        slug = name[:-3]
        if name.endswith(".md") and SLUG_RE.match(slug):
            campaigns[slug] = read_campaign(slug, _read(root, "campaigns/" + name))
    state = _read_json(root, "state/campaigns.json", {})
    techniques = {}
    try:
        pages = sorted(os.listdir(os.path.join(root, "techniques")))
    except OSError:
        pages = []
    for name in pages:
        if name.endswith(".md") and TECHNIQUE_RE.match(name[:-3]):
            techniques[name[:-3]] = _read(root, "techniques/" + name)
    return {
        "root": root,
        "campaigns": campaigns,
        "techniques": techniques,
        "shapes": {k: v for k, v in (state.get("shapes") or {}).items()
                   if isinstance(v, str)},
        "activity": {k: v for k, v in (state.get("activity") or {}).items()
                     if isinstance(v, dict)},
        "lessons": _read_json(root, "state/lessons.json", []),
        "suggestions": _read_json(root, "state/suggestions.json", []),
        "feedback": _read(root, "feedback.md").strip(),
        "persona": _read(root, "context/persona.md").strip(),
        "watch": [ln.strip() for ln in _read(root, "context/watch.txt").splitlines()
                  if ln.strip() and not ln.startswith("#")],
    }


def known_shapes(kb):
    return {shape: {"campaign": slug} for shape, slug in kb["shapes"].items()}


def campaign_index(kb, limit=60):
    """The campaigns as the tracker stage sees them, current ones first."""
    rows = sorted(kb["campaigns"].values(), key=lambda c: c["last_seen"], reverse=True)
    rows.sort(key=lambda c: STATUS_ORDER.get(c["status"], 9))
    return [{
        "slug": c["slug"], "title": c["title"], "status": c["status"],
        "persona": c["persona"], "first_seen": c["first_seen"],
        "last_seen": c["last_seen"], "days_seen": c["days_seen"],
        "techniques": c["techniques"], "shapes": c["shapes"],
        "summary": c["summary"][:700],
    } for c in rows[:limit]]


# ---------------------------------------------------------------------------
# one day's changes
# ---------------------------------------------------------------------------

def _new_campaign(slug, persona):
    return {"slug": slug, "title": slug, "status": "active", "persona": persona or "",
            "first_seen": "", "last_seen": "", "days_seen": 0, "sessions": 0,
            "techniques": [], "shapes": [], "related": [], "publishable": False,
            "summary": "", "angle": "", "timeline": [], "indicators": [], "notes": ""}


def _technique_page(existing, tech, day, linked):
    meta, sections = parse_page(existing) if existing else ({}, {})
    name = meta.get("name") or one_line(tech.get("name"), 120) or tech["id"]
    seen = _put_day(_lines(sections.get("Seen on this sensor")), day,
                    "- %s: %s%s" % (day, one_line(tech.get("seen_as"), 700) or "Seen.",
                                    " Campaigns: %s." % ", ".join(
                                        "[%s](../campaigns/%s.md)" % (s, s) for s in linked)
                                    if linked else ""))
    url = mitre_url(tech["id"])
    out = _front({"id": tech["id"], "name": name,
                  "first_seen": meta.get("first_seen") or day, "last_seen": day,
                  "days_seen": len(seen)})
    out += ["# %s %s" % (tech["id"], name), "", "[MITRE ATT&CK page](%s)" % url, "",
            "## Seen on this sensor", ""] + seen + [""]
    return "\n".join(out)


def index_page(campaigns, techniques, day, overview=True):
    """INDEX.md: the page to open first. overview says whether the campaign
    activity chart exists to be shown."""
    out = ["# Threat Radar knowledge base", "",
           "Updated for %s. The latest report is [daily/%s/%s.md](daily/%s/%s.md)."
           % (day, day[:4], day, day[:4], day), ""]
    if overview:
        out += ["![Campaign activity over the last 30 days](charts/overview.png)", ""]
    out += ["## Campaigns", "",
           "| Campaign | Status | Last seen | Days seen | Sessions | Techniques |",
           "|---|---|---|---|---|---|"]
    rows = sorted(campaigns.values(), key=lambda c: c["last_seen"], reverse=True)
    rows.sort(key=lambda c: STATUS_ORDER.get(c["status"], 9))
    for c in rows:
        out.append("| [%s](campaigns/%s.md)%s | %s | %s | %d | %d | %s |" % (
            one_line(c["title"], 80).replace("|", "/"), c["slug"],
            " (write-up candidate)" if c["publishable"] else "",
            c["status"], c["last_seen"] or "", c["days_seen"], c["sessions"],
            ", ".join(_technique_link(t, techniques, up="") for t in c["techniques"])))
    if not rows:
        out.append("| None yet | | | | | |")
    out += ["", "## Techniques", ""]
    out += ["- [%s](techniques/%s.md)" % (t, t) for t in sorted(techniques)] \
        or ["- None yet."]
    out += ["", "## Steering", "",
            "Edit [feedback.md](feedback.md) to correct the team. Every run reads it "
            "before it writes anything.", ""]
    return "\n".join(out)


def apply(kb, tracked, index, day):
    """The files this day changes, the campaigns that were active, and the
    knowledge base as it stands afterwards (for the charts and INDEX.md).

    tracked is the tracker stage's checked answer, or None when that stage
    did not run. A shape the knowledge base already files under a campaign is
    counted for that campaign either way, so the record of when a campaign
    was seen does not depend on a model answering.
    """
    tracked = tracked or {"campaigns": [], "techniques": []}
    campaigns = copy.deepcopy(kb["campaigns"])
    shapes = dict(kb["shapes"])
    activity = copy.deepcopy(kb["activity"])
    today = {c["shape"]: c for c in index["clusters"]}
    by_slug = {t["slug"]: t for t in tracked["campaigns"]}

    for slug, t in by_slug.items():
        for shape in t["shapes"]:
            shapes.setdefault(shape, slug)

    sessions_today = {}
    for shape, cluster in today.items():
        slug = shapes.get(shape)
        if slug:
            sessions_today[slug] = sessions_today.get(slug, 0) + cluster["sessions"]

    files, active, changed = {}, [], set()
    for slug in sorted(set(by_slug) | set(sessions_today)):
        existing = campaigns.get(slug)
        if existing and existing["status"] == HISTORICAL:
            continue
        c = existing or _new_campaign(slug, index.get("persona"))
        t = by_slug.get(slug, {})
        count = sessions_today.get(slug, 0)
        activity.setdefault(slug, {})[day] = count
        days = activity[slug]

        if t.get("title") and not existing:
            c["title"] = one_line(t["title"], 100)
        if t.get("summary"):
            c["summary"] = md_text(t["summary"], 2000)
        if slug in by_slug:
            c["publishable"] = bool(t.get("publishable"))
            c["angle"] = md_text(t.get("publish_angle"), 600) if c["publishable"] else ""
        c["techniques"] = sorted(set(c["techniques"]) | set(t.get("techniques") or []))
        c["shapes"] = sorted(s for s, owner in shapes.items() if owner == slug)
        c["related"] = sorted(set(c["related"]) | set(t.get("related") or []))
        c["first_seen"] = min(days)
        c["last_seen"] = max(days)
        c["days_seen"] = len(days)
        c["sessions"] = sum(days.values())
        c["status"] = "active"
        note = one_line(t.get("today"), 600)
        c["timeline"] = _put_day(c["timeline"], day, "- %s: %s%s" % (
            day, "%d session%s. " % (count, "" if count == 1 else "s") if count else "",
            note or "Seen again."))
        wanted = ["- %s %s" % (i["kind"], code(i["value"])) for i in t.get("indicators") or []]
        c["indicators"] = sorted(set(c["indicators"]) | set(wanted))[:200]
        campaigns[slug] = c
        changed.add(slug)
        active.append({"slug": slug, "title": c["title"], "status": c["status"],
                       "new": existing is None, "sessions_today": count,
                       "days_seen": c["days_seen"], "first_seen": c["first_seen"],
                       "publishable": c["publishable"]})

    for slug, c in campaigns.items():
        status = status_for(c, day)
        if status != c["status"]:
            c["status"] = status
            changed.add(slug)

    techniques = dict(kb["techniques"])
    for tech in tracked["techniques"]:
        linked = sorted(s for s, t in by_slug.items()
                        if tech["id"] in t["techniques"] and s in campaigns)
        page = _technique_page(techniques.get(tech["id"]), tech, day, linked)
        techniques[tech["id"]] = page
        files["techniques/%s.md" % tech["id"]] = page

    # Pages are rendered last, so a campaign links to a technique page that
    # this same day created.
    for slug in sorted(changed):
        files["campaigns/%s.md" % slug] = render_campaign(campaigns[slug], techniques)

    files["state/campaigns.json"] = json.dumps(
        {"shapes": shapes, "activity": activity}, indent=1, sort_keys=True) + "\n"
    return files, active, {"campaigns": campaigns, "activity": activity,
                           "techniques": techniques}


def with_lesson(kb, lesson, day):
    """state/lessons.json with this day's lesson recorded once."""
    kept = [entry for entry in kb["lessons"]
            if isinstance(entry, dict) and entry.get("day") != day]
    if lesson:
        kept.append({"day": day, "technique": lesson["technique"],
                     "title": lesson["title"]})
    return json.dumps(kept[-MAX_LESSONS:], indent=1) + "\n"
