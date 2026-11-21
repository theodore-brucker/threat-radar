"""The model stages: what each one is shown, and what is kept of its answer.

Each stage function builds a document, asks the model, and returns a checked
structure. The check is where trust is decided, and it follows one rule for
every stage: a value that names something (a command shape, an indicator, a
campaign) is kept only when the code already holds that value, and free text
is cut to a length and kept as text for a renderer to escape. An item that
fails is dropped. An answer with nothing left in it is still an answer.

What each stage can reach:

  reader    the day's record, attacker text included      no tools
  research  indicators the reader named and the record    WebSearch only
            contains, with no free text from the reader
  tracker   the reader's and researcher's checked output  no tools
  editor    the same, and the day's numbers               no tools
  writer    campaign pages marked for a write-up          no tools

Text that derives from an attacker or a web page is fenced in every document,
with a tag made for that document, so the stage before cannot close the fence
of the stage after.
"""

import hashlib
import json
import os
import re

from app.analytics import export
from . import AREAS, bundle as bundlemod, kb as kbmod, model, report as reportmod

RESEARCH_MODEL = os.environ.get("TR_TEAM_RESEARCH_MODEL", "sonnet")
HERE = os.path.dirname(os.path.abspath(__file__))
WRITING_RULES = os.path.join(HERE, "..", "..", "docs", "WRITING.md")

KINDS = ("sha256", "ip", "host", "family", "asn", "hassh")
LEVELS = ("low", "medium", "high")


# ---------------------------------------------------------------------------
# prompts and documents
# ---------------------------------------------------------------------------

def prompt(name):
    with open(os.path.join(HERE, "prompts", name + ".md"), encoding="utf-8") as fh:
        return fh.read()


def _system(name, kb, feedback=False, writing=False):
    """A stage's instructions, followed by what the operator wrote for it."""
    parts = [prompt(name)]
    if kb.get("persona"):
        parts += ["## About the sensor", "",
                  "The operator wrote this. It is private and trusted.", "", kb["persona"], ""]
    if feedback and kb.get("feedback"):
        parts += ["## The operator's standing feedback", "",
                  "The operator wrote this. Follow it.", "", kb["feedback"], ""]
    if writing:
        with open(WRITING_RULES, encoding="utf-8") as fh:
            parts += ["## Writing rules", "", fh.read()]
    return "\n".join(parts)


def _block(title, value, tag, note=None):
    lines = ["## %s" % title, ""]
    if note:
        lines += [note, ""]
    body = json.dumps(value, indent=1, ensure_ascii=True, sort_keys=True).splitlines()
    return lines + export.fenced(body, tag) + [""]


def _document(heading, blocks):
    tag = export.new_tag()
    out = ["# %s" % heading, "", export.fence_rule(tag), ""]
    for title, value, note in blocks:
        out += _block(title, value, tag, note)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

def _text(value, limit):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    return str(value).strip()[:limit]


def _line(value, limit):
    return " ".join(_text(value, limit).split())


def _name(value):
    """A value used as a name, or None. A model can answer with a list or an
    object where a name belongs, and those cannot be looked up in a set."""
    return value if isinstance(value, str) else None


def _dicts(value, limit):
    return [v for v in value if isinstance(v, dict)][:limit] if isinstance(value, list) else []


def _strings(value, limit, each):
    if not isinstance(value, list):
        return []
    return [t for t in (_text(v, each) for v in value) if t][:limit]


def _choice(value, options, default):
    return value if value in options else default


def _techniques(value, limit=8):
    return [t for t in _strings(value, 20, 12) if kbmod.TECHNIQUE_RE.match(t)][:limit]


def _indicator_set(index):
    return {(kind, v) for kind in KINDS for v in index["indicators"].get(kind, [])}


def suggestion_id(title):
    """The same id for the same suggestion however it is punctuated, so one
    idea is raised as one issue."""
    words = re.findall(r"[a-z0-9]+", title.lower())
    return hashlib.sha256(" ".join(words).encode()).hexdigest()[:12]


def check_reading(raw, index):
    shapes = {c["shape"] for c in index["clusters"]}
    known = _indicator_set(index)
    values = {v for _, v in known}
    out = {
        "summary": _text(raw.get("summary"), 1500),
        "background": _text(raw.get("background"), 600),
        "clusters": [], "observations": [], "lookups": [],
        "honeypot_checks": _strings(raw.get("honeypot_checks"), 8, 400),
        "emulation_gaps": _strings(raw.get("emulation_gaps"), 8, 400),
    }
    seen = set()
    for c in _dicts(raw.get("clusters"), 20):
        shape = _name(c.get("shape"))
        if shape not in shapes or shape in seen:
            continue
        seen.add(shape)
        out["clusters"].append({
            "shape": shape,
            "label": _line(c.get("label"), 100),
            "what_it_does": _text(c.get("what_it_does"), 1500),
            "objective": _text(c.get("objective"), 400),
            "automation": _choice(c.get("automation"),
                                  ("automated", "hands-on", "mixed", "unclear"), "unclear"),
            "techniques": _techniques(c.get("techniques"), 6),
            "confidence": _choice(c.get("confidence"), LEVELS, "low"),
            "evidence": _text(c.get("evidence"), 800),
        })
    out["clusters"] = out["clusters"][:10]
    for o in _dicts(raw.get("observations"), 8):
        title, detail = _line(o.get("title"), 120), _text(o.get("detail"), 800)
        if title or detail:
            out["observations"].append({
                "title": title, "detail": detail,
                "indicators": [v for v in _strings(o.get("indicators"), 20, 300)
                               if v in values][:8]})
    for item in _dicts(raw.get("lookups"), 12):
        pair = (_name(item.get("kind")), _name(item.get("indicator")))
        if pair in known and pair not in [(x["kind"], x["indicator"]) for x in out["lookups"]]:
            out["lookups"].append({"kind": pair[0], "indicator": pair[1]})
    out["lookups"] = out["lookups"][:6]
    if not out["summary"]:
        raise model.StageError("the reader's answer had no summary")
    return out


def check_findings(raw, asked):
    wanted = {a["indicator"] for a in asked}
    out, seen = [], set()
    for f in _dicts(raw.get("findings"), 12):
        indicator = _name(f.get("indicator"))
        if indicator not in wanted or indicator in seen:
            continue
        seen.add(indicator)
        sources = [{"title": _line(s.get("title"), 150), "url": s["url"]}
                   for s in _dicts(f.get("sources"), 8)
                   if isinstance(s.get("url"), str) and reportmod.URL_RE.match(s["url"])][:4]
        out.append({
            "indicator": indicator,
            "known": _text(f.get("known"), 900) or "Nothing found.",
            "names": [_line(n, 60) for n in _strings(f.get("names"), 5, 60)],
            "sources": sources,
            "confidence": _choice(f.get("confidence"), LEVELS, "low"),
        })
    return out


def check_tracking(raw, kb, index):
    today = {c["shape"] for c in index["clusters"]}
    known = _indicator_set(index)
    existing = kb["campaigns"]
    out = {"campaigns": [], "techniques": []}
    taken = set()
    for c in _dicts(raw.get("campaigns"), 12):
        slug, related = _name(c.get("slug")), _strings(c.get("related"), 6, 60)
        if not slug or not kbmod.SLUG_RE.match(slug):
            continue
        if slug in existing and existing[slug]["status"] == kbmod.HISTORICAL:
            # The earlier persona's record is closed. Activity that looks like
            # it starts a current campaign that points back at it.
            related, slug = related + [slug], (slug + "-current")[:60]
        if slug in taken:
            continue
        shapes = [s for s in _strings(c.get("shapes"), 20, 12)
                  if s in today and kb["shapes"].get(s, slug) == slug]
        indicators = [{"kind": i["kind"], "value": i["value"]}
                      for i in _dicts(c.get("indicators"), 30)
                      if (_name(i.get("kind")), _name(i.get("value"))) in known][:20]
        summary = _text(c.get("summary"), 2000)
        if slug not in existing and not ((shapes or indicators) and summary):
            continue
        taken.add(slug)
        out["campaigns"].append({
            "slug": slug,
            "title": _line(c.get("title"), 100) or slug,
            "summary": summary,
            "today": _line(c.get("today"), 600),
            "shapes": shapes,
            "techniques": _techniques(c.get("techniques")),
            "indicators": indicators,
            "related": sorted({r for r in related if r in existing and r != slug}),
            "publishable": c.get("publishable") is True,
            "publish_angle": _text(c.get("publish_angle"), 600),
        })
    used = {t for c in out["campaigns"] for t in c["techniques"]}
    for t in _dicts(raw.get("techniques"), 20):
        if _name(t.get("id")) in used and t["id"] not in [x["id"] for x in out["techniques"]]:
            out["techniques"].append({"id": t["id"], "name": _line(t.get("name"), 120),
                                      "seen_as": _text(t.get("seen_as"), 700)})
    return out


def check_report(raw, kb, active):
    slugs = {a["slug"] for a in active}
    raised = {s.get("id") for s in kb["suggestions"] if isinstance(s, dict)}
    lesson = raw.get("lesson") if isinstance(raw.get("lesson"), dict) else {}
    body = _text(lesson.get("body"), 2500)
    technique = _text(lesson.get("technique"), 12)
    out = {
        "headline": _line(raw.get("headline"), 120),
        "bottom_line": _text(raw.get("bottom_line"), 700),
        "changes": _strings(raw.get("changes"), 5, 300),
        "campaign_notes": {n["slug"]: _line(n.get("note"), 300)
                           for n in _dicts(raw.get("campaign_notes"), 20)
                           if _name(n.get("slug")) in slugs},
        "lesson": {
            "title": _line(lesson.get("title"), 120) or "Lesson of the day",
            "technique": technique if kbmod.TECHNIQUE_RE.match(technique) else "",
            "technique_name": _line(lesson.get("technique_name"), 120),
            "body": body,
            "example": _text(lesson.get("example"), 800),
        } if body else None,
        "suggestions": [],
        "watch": _strings(raw.get("watch"), 3, 200),
    }
    for s in _dicts(raw.get("suggestions"), 6):
        title, text = _line(s.get("title"), 90), _text(s.get("body"), 1500)
        ident = suggestion_id(title)
        if not title or not text or ident in raised \
                or ident in [x["id"] for x in out["suggestions"]]:
            continue
        out["suggestions"].append({
            "id": ident, "title": title,
            "area": _choice(s.get("area"), AREAS, "sensor"),
            "body": text, "evidence": _text(s.get("evidence"), 600)})
    out["suggestions"] = out["suggestions"][:3]
    if not out["headline"]:
        raise model.StageError("the editor's answer had no headline")
    return out


# ---------------------------------------------------------------------------
# stages
# ---------------------------------------------------------------------------

def read(bundle, kb, ask=model.ask_json):
    document, _tag = bundlemod.document(bundle)
    raw = ask(_system("reader", kb, feedback=True), document)
    return check_reading(raw, bundle["index"])


def research(reading, bundle, kb, ask=model.ask_json):
    """Look up the indicators the reader asked about. Only the indicator and
    what the collector's own lookups said about it go to this stage."""
    asked = reading["lookups"]
    if not asked:
        return []
    verdicts = {f["shasum"]: f for f in bundle["index"]["files"]}
    items = [{"indicator": a["indicator"], "kind": a["kind"],
              "collector_lookups": (verdicts.get(a["indicator"]) or {}).get("verdicts"),
              "family": (verdicts.get(a["indicator"]) or {}).get("family")}
             for a in asked]
    document = _document("Indicators to research", [("Indicators", items, None)])
    raw = ask(_system("research", {}), document, tools=("WebSearch",), model=RESEARCH_MODEL)
    return check_findings(raw, asked)


def _numbers(bundle):
    index = bundle["index"]
    return {
        "day": index["day"], "persona": index["persona"],
        "persona_since": index["persona_since"], "compared_from": index["compared_from"],
        "metrics": index["metrics"], "funnel": index["funnel"],
        "networks": index["networks"][:6], "clusters": index["clusters"][:10],
        "files": index["files"][:10], "pipeline": index["pipeline"],
        "limits": bundle["limits"],
    }


def track(reading, findings, bundle, kb, ask=model.ask_json):
    index = bundle["index"]
    document = _document("Yesterday, to file under campaigns: %s" % index["day"], [
        ("Command shapes seen yesterday", index["clusters"],
         "known_as is the campaign a shape is already filed under."),
        ("Indicators seen yesterday", index["indicators"], None),
        ("Campaigns in the knowledge base", kbmod.campaign_index(kb),
         "The sensor now presents itself as: %s." % (index["persona"] or "unknown")),
        ("The analyst's reading", reading, None),
        ("The researcher's findings", findings, None),
    ])
    return check_tracking(ask(_system("tracker", kb), document), kb, index)


def edit(bundle, reading, findings, active, kb, ask=model.ask_json):
    document = _document("Material for the report on %s" % bundle["day"], [
        ("The day's numbers", _numbers(bundle),
         "median is over `days` earlier comparable days."),
        ("The analyst's reading", reading, None),
        ("The researcher's findings", findings, None),
        ("Campaigns active yesterday", active, None),
        ("Recent lessons", kb["lessons"][-14:], None),
        ("Suggestions already raised",
         [s.get("title") for s in kb["suggestions"] if isinstance(s, dict)][-80:], None),
    ])
    raw = ask(_system("editor", kb, feedback=True, writing=True), document)
    return check_report(raw, kb, active)


def draft(candidates, kb, ask=model.ask_json):
    """A blog draft from campaigns marked for a write-up, or None when there
    are none. candidates maps a slug to its rendered page."""
    if not candidates:
        return None
    document = _document("Campaigns marked for a write-up this week",
                         [("Campaign pages", candidates, None)])
    raw = ask(_system("writer", {}, writing=True), document)
    slug, body = _name(raw.get("campaign")), kbmod.md_text(raw.get("body"), 12000, headings=True)
    if slug not in candidates or not body:
        raise model.StageError("the writer's answer named no campaign it was given")
    return {"campaign": slug, "title": _line(raw.get("title"), 150) or slug, "body": body}
