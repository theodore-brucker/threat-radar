"""The daily report: assembled once, rendered three ways.

assemble() turns the stages' checked answers and the day's numbers into one
report dict, which is what the worker leaves in its outbox. The renderers
take that dict and nothing else:

  markdown()  the page filed under daily/ in the knowledge base
  email()     the HTML and plain-text parts of the message

Every string in a report may trace back to an attacker, so nothing here
trusts one. The HTML renderer escapes each value and defangs URLs and
addresses, because a mail client turns a bare URL into a link. The only live
links are ones this module builds: knowledge base pages, issues, MITRE
ATT&CK, and the sources the researcher cited.
"""

import datetime as dt
import html
import re

from app.analytics.sessions import defang
from . import AREAS, kb as kbmod

SCHEMA = "threat-radar.team-report/1"
CHARTS = ("volume", "hours", "networks")
CHART_ALT = {
    "volume": "Sessions per day across the comparable window",
    "hours": "Sessions opened in each Eastern hour of the day",
    "networks": "Sessions by network",
}
BASELINE_MIN_DAYS = 3
URL_RE = re.compile(r"^https?://[^\s<>\"'`]{4,300}\Z")
SUGGESTION_ID_RE = re.compile(r"^[0-9a-f]{12}\Z")
DRAFT_RE = re.compile(r"^drafts/\d{4}-W\d{2}\.md\Z")

FONT = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, Menlo, Consolas, monospace"
INK, DIM, LINE, SUNK, ACCENT = "#0F1A20", "#5A686E", "#D6DDDA", "#ECF0EE", "#1E4E9C"


def long_day(day):
    d = dt.date.fromisoformat(day)
    return "%s, %s %d, %d" % (d.strftime("%A"), d.strftime("%B"), d.day, d.year)


def _tiles(index):
    m, funnel = index["metrics"], {f["key"]: f["sessions"] for f in index["funnel"]}
    files = m["downloads"]["value"] + m["uploads"]["value"]
    tiles = [("Sessions", m["sessions"]), ("Addresses", m["addresses"]),
             ("Accepted logins", m["successes"]),
             ("Sessions with commands", {"value": funnel.get("ran_commands", 0)}),
             ("Files moved", {"value": files})]
    # days is None for a count that has no history to compare with.
    return [{"label": label, "value": v["value"], "median": v.get("median"),
             "days": v.get("days")} for label, v in tiles]


def assemble(bundle, reading, findings, active, edited, problems, charts):
    """One report dict from whatever the run produced.

    reading and edited are None when their stage did not run or failed. The
    report then carries the numbers and says what is missing, so a model
    outage costs the analysis and not the email.
    """
    index, day = bundle["index"], bundle["day"]
    edited = edited or {}
    notes = edited.get("campaign_notes") or {}
    if index["empty"]:
        headline = "The sensor recorded nothing on %s" % day
        bottom = ("No event is stored for this day. Check the pipeline times at the "
                  "foot of this report against the clock.")
    elif edited:
        headline, bottom = edited["headline"], edited["bottom_line"]
    else:
        headline = "Numbers for %s, without the written analysis" % day
        bottom = (reading or {}).get("summary") or \
            "The analysis stages did not finish, so this report carries the counts only."
    return {
        "schema": SCHEMA,
        "day": day,
        "generated_at": bundle["generated_at"],
        "persona": index["persona"],
        "persona_since": index["persona_since"],
        "headline": headline,
        "bottom_line": bottom,
        "changes": edited.get("changes") or [],
        "tiles": _tiles(index),
        "background": (reading or {}).get("background") or "",
        "campaigns": [dict(a, note=notes.get(a["slug"], "")) for a in active],
        "lesson": edited.get("lesson"),
        "suggestions": edited.get("suggestions") or [],
        "watch": edited.get("watch") or [],
        "research": [f for f in findings or [] if f["known"] != "Nothing found."],
        "limits": bundle["limits"],
        "pipeline": index["pipeline"],
        "problems": problems,
        "charts": [name for name in CHARTS if name in charts],
        "draft": None,
    }


def _baseline(tile):
    if tile["days"] is None:
        return ""
    if tile["median"] is None or tile["days"] < BASELINE_MIN_DAYS:
        return "no baseline yet"
    return "median {:,.0f}".format(tile["median"])


def _count(n, noun):
    return "{:,} {}{}".format(n, noun, "" if n == 1 else "s")




# ---------------------------------------------------------------------------
# markdown, for the knowledge base
# ---------------------------------------------------------------------------

def markdown(report):
    day, text = report["day"], kbmod.md_text
    charts = "../../charts/%s" % day
    out = ["# %s" % kbmod.one_line(report["headline"], 160), "",
           "%s. The sensor presented itself as: %s." % (
               long_day(day), kbmod.one_line(report["persona"] or "unknown")), "",
           text(report["bottom_line"]), ""]
    if report["changes"]:
        out += ["## What changed", ""] + ["- " + kbmod.one_line(c, 400)
                                          for c in report["changes"]] + [""]
    out += ["## The day in numbers", "", "| Measure | Count | Earlier days |", "|---|---|---|"]
    out += ["| %s | %s | %s |" % (t["label"], "{:,}".format(t["value"]), _baseline(t))
            for t in report["tiles"]] + [""]
    for name in report["charts"]:
        out += ["![%s](%s/%s.png)" % (CHART_ALT[name], charts, name), ""]
    if report["background"]:
        out += ["## Background", "", text(report["background"]), ""]
    if report["campaigns"]:
        out += ["## Campaigns", "", "| Campaign | Sessions | Days seen | Yesterday |",
                "|---|---|---|---|"]
        for c in report["campaigns"]:
            out.append("| [%s](../../campaigns/%s.md)%s | %d | %d | %s |" % (
                kbmod.one_line(c["title"], 80).replace("|", "/"), c["slug"],
                " (new)" if c["new"] else "", c["sessions_today"], c["days_seen"],
                kbmod.one_line(c["note"], 300).replace("|", "/")))
        out.append("")
    lesson = report["lesson"]
    if lesson:
        out += ["## Lesson: %s" % kbmod.one_line(lesson["title"], 120), ""]
        if lesson["technique"]:
            out += ["[%s %s](%s)" % (
                lesson["technique"], kbmod.one_line(lesson["technique_name"], 120),
                kbmod.mitre_url(lesson["technique"])), ""]
        out += [text(lesson["body"], 2500), ""]
        if lesson["example"]:
            out += ["Recorded example:", ""]
            out += ["    " + line for line in text(lesson["example"], 800).splitlines()] + [""]
    if report["suggestions"]:
        out += ["## Suggestions", ""]
        for s in report["suggestions"]:
            out += ["- **%s** (%s). %s%s" % (
                kbmod.one_line(s["title"], 90), s["area"], kbmod.one_line(s["body"], 1500),
                " Evidence: %s" % kbmod.one_line(s["evidence"], 600) if s["evidence"] else "")]
        out.append("")
    if report["watch"]:
        out += ["## Watch for", ""] + ["- " + kbmod.one_line(w, 200)
                                       for w in report["watch"]] + [""]
    if report["draft"]:
        out += ["## Blog draft", "", "This week's candidate: [%s](../../%s)." % (
            kbmod.one_line(report["draft"]["title"], 150).replace("]", ")"),
            report["draft"]["path"]), ""]
    if report["research"]:
        out += ["## What the web says", ""]
        for f in report["research"]:
            links = ", ".join("[%s](%s)" % (kbmod.one_line(s["title"], 80).replace("]", ")")
                                            or "source", s["url"]) for s in f["sources"])
            out += ["- %s: %s%s" % (kbmod.code(f["indicator"]), kbmod.one_line(f["known"], 900),
                                    " Sources: %s." % links if links else "")]
        out.append("")
    notes = report["limits"] + report["problems"]
    if notes:
        out += ["## Limits of this report", ""] + ["- " + kbmod.one_line(n, 400)
                                                   for n in notes] + [""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# email
# ---------------------------------------------------------------------------

def _e(value):
    """A recorded or model-written value as inert HTML text."""
    return html.escape(defang(str(value or "")), quote=True)


def _paragraphs(value, style):
    blocks = [b.strip() for b in str(value or "").split("\n\n") if b.strip()]
    return "".join('<p style="%s">%s</p>' % (style, _e(b).replace("\n", "<br>"))
                   for b in blocks)


def _link(url, label):
    return '<a href="%s" style="color:%s">%s</a>' % (html.escape(url, quote=True), ACCENT, label)


def subject(report):
    return "Threat Radar %s: %s" % (report["day"], " ".join(report["headline"].split())[:120])


def email_html(report, kb_url="", issues=None):
    """The HTML part. Charts are referenced as cid:<name>, which the sender
    attaches. issues maps a suggestion id to the URL of the issue filed for
    it."""
    issues = issues or {}
    day = report["day"]
    p = "margin:0 0 12px 0;font-size:15px;line-height:1.55;color:%s" % INK
    h2 = ("margin:28px 0 10px 0;font-size:13px;letter-spacing:.04em;text-transform:uppercase;"
          "color:%s;font-weight:600" % DIM)
    small = "font-size:12px;line-height:1.5;color:%s" % DIM
    cell = "padding:8px 10px;border-bottom:1px solid %s;font-size:13px;color:%s;vertical-align:top" % (LINE, INK)

    def page(path, label):
        return _link("%s/blob/main/%s" % (kb_url, path), label) if kb_url else label

    out = ['<div style="font-family:%s;max-width:680px;margin:0 auto;padding:20px 16px;color:%s">'
           % (FONT, INK),
           '<div style="%s">Threat Radar daily intel &middot; %s &middot; %s</div>'
           % (small, _e(long_day(day)), _e(report["persona"] or "persona unknown")),
           '<h1 style="margin:10px 0 12px 0;font-size:24px;line-height:1.2;color:%s">%s</h1>'
           % (INK, _e(report["headline"])),
           _paragraphs(report["bottom_line"], p)]

    out.append('<table role="presentation" cellspacing="0" cellpadding="0" '
               'style="width:100%;border-collapse:collapse;margin:16px 0 4px 0"><tr>')
    for t in report["tiles"]:
        out.append('<td width="20%%" style="padding:10px 8px;background:%s;border-right:3px solid #FFFFFF;'
                   'vertical-align:top"><div style="font-size:22px;font-weight:600;color:%s">'
                   '%s</div><div style="%s">%s</div><div style="%s">%s</div></td>'
                   % (SUNK, INK, "{:,}".format(t["value"]), small, _e(t["label"]),
                      small, _e(_baseline(t))))
    out.append("</tr></table>")

    if report["changes"]:
        out.append('<h2 style="%s">What changed</h2><ul style="margin:0;padding-left:20px">' % h2)
        out += ['<li style="%s">%s</li>' % (p, _e(c)) for c in report["changes"]]
        out.append("</ul>")

    for name in report["charts"]:
        out.append('<img src="cid:%s" alt="%s" width="648" style="display:block;width:100%%;'
                   'max-width:648px;height:auto;margin:18px 0 0 0;border:0">'
                   % (name, html.escape(CHART_ALT[name])))

    if report["campaigns"]:
        out.append('<h2 style="%s">Campaigns</h2><table role="presentation" cellspacing="0" '
                   'cellpadding="0" style="width:100%%;border-collapse:collapse">' % h2)
        for c in report["campaigns"]:
            out.append('<tr><td style="%s"><strong>%s</strong>%s<br><span style="%s">%s</span></td>'
                       '<td style="%s;white-space:nowrap;text-align:right">%s<br>'
                       '<span style="%s">day %d</span></td></tr>'
                       % (cell, page("campaigns/%s.md" % c["slug"], _e(c["title"])),
                          " &middot; new" if c["new"] else "", small, _e(c["note"]),
                          cell, _count(c["sessions_today"], "session"), small, c["days_seen"]))
        out.append("</table>")
    if report["background"]:
        out.append('<h2 style="%s">Background</h2>%s' % (h2, _paragraphs(report["background"], p)))

    lesson = report["lesson"]
    if lesson:
        out.append('<h2 style="%s">Lesson</h2><div style="font-size:17px;font-weight:600;'
                   'margin:0 0 6px 0;color:%s">%s</div>' % (h2, INK, _e(lesson["title"])))
        if lesson["technique"]:
            out.append('<div style="%s;margin:0 0 10px 0">%s</div>' % (small, _link(
                kbmod.mitre_url(lesson["technique"]),
                "%s %s" % (lesson["technique"], _e(lesson["technique_name"])))))
        out.append(_paragraphs(lesson["body"], p))
        if lesson["example"]:
            out.append('<pre style="margin:0 0 12px 0;padding:10px 12px;background:%s;'
                       'font-family:%s;font-size:12px;line-height:1.5;color:%s;'
                       'white-space:pre-wrap;word-break:break-word">%s</pre>'
                       % (SUNK, MONO, INK, _e(lesson["example"])))

    if report["suggestions"]:
        out.append('<h2 style="%s">Suggestions</h2>' % h2)
        for s in report["suggestions"]:
            title = _e(s["title"])
            if issues.get(s["id"]):
                title = _link(issues[s["id"]], title)
            out.append('<p style="%s"><strong>%s</strong> <span style="%s">%s</span><br>%s%s</p>'
                       % (p, title, small, _e(s["area"]), _e(s["body"]),
                          '<br><span style="%s">Evidence: %s</span>' % (small, _e(s["evidence"]))
                          if s["evidence"] else ""))

    if report["watch"]:
        out.append('<h2 style="%s">Watch for</h2><ul style="margin:0;padding-left:20px">' % h2)
        out += ['<li style="%s">%s</li>' % (p, _e(w)) for w in report["watch"]]
        out.append("</ul>")

    if report["draft"]:
        out.append('<h2 style="%s">Blog draft</h2><p style="%s">The candidate for this week: %s</p>'
                   % (h2, p, page(report["draft"]["path"], _e(report["draft"]["title"]))))

    if report["research"]:
        out.append('<h2 style="%s">What the web says</h2>' % h2)
        for f in report["research"]:
            links = " &middot; ".join(_link(s["url"], _e(s["title"] or "source"))
                                      for s in f["sources"])
            out.append('<p style="%s"><span style="font-family:%s;font-size:12px;'
                       'word-break:break-all">%s</span><br>%s%s</p>'
                       % (p, MONO, _e(f["indicator"]), _e(f["known"]),
                          '<br><span style="%s">%s</span>' % (small, links) if links else ""))

    foot = [_e(n) for n in report["limits"] + report["problems"]]
    pipe = report["pipeline"]
    foot.append("Newest event %s. Daily tables rebuilt %s." % (
        _e(pipe.get("newest_event") or "unknown"),
        _e(pipe.get("daily_facts_rebuilt") or "unknown")))
    if kb_url:
        foot.append("%s &middot; %s &middot; %s" % (
            page("daily/%s/%s.md" % (day[:4], day), "This report in the knowledge base"),
            page("INDEX.md", "All campaigns"),
            page("feedback.md", "Steer the team")))
    out.append('<div style="margin-top:28px;padding-top:12px;border-top:1px solid %s">' % LINE)
    out += ['<p style="margin:0 0 6px 0;%s">%s</p>' % (small, line) for line in foot]
    out.append("</div></div>")
    return "\n".join(out)


def email_text(report):
    """The plain-text part, for a client that shows no HTML."""
    t = lambda value: defang(str(value or ""))  # noqa: E731
    out = [t(report["headline"]), "", t(report["bottom_line"]), ""]
    out += ["%s: %s%s" % (x["label"], "{:,}".format(x["value"]),
                          " (%s)" % _baseline(x) if _baseline(x) else "")
            for x in report["tiles"]] + [""]
    out += ["- " + t(c) for c in report["changes"]]
    for c in report["campaigns"]:
        out.append("Campaign %s: %s, day %d. %s" % (
            t(c["title"]), _count(c["sessions_today"], "session"), c["days_seen"], t(c["note"])))
    if report["lesson"]:
        out += ["", "Lesson: " + t(report["lesson"]["title"]), t(report["lesson"]["body"])]
    for s in report["suggestions"]:
        out += ["", "Suggestion (%s): %s" % (s["area"], t(s["title"])), t(s["body"])]
    out += [""] + [t(n) for n in report["limits"] + report["problems"]]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# reading a report back
# ---------------------------------------------------------------------------

def _s(value, limit):
    return str(value)[:limit] if isinstance(value, (str, int, float)) \
        and not isinstance(value, bool) else ""


def _i(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def _list(value, limit):
    return value[:limit] if isinstance(value, list) else []


def _rows(value, limit):
    return [v for v in _list(value, limit) if isinstance(v, dict)]


def coerce(raw):
    """A report as read from the outbox, rebuilt field by field.

    The publisher renders mail from a file another account wrote. This gives
    every field the type the renderers expect and a length limit, drops what
    it does not know, and raises ValueError when the file is not a report.
    """
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA \
            or not kbmod.DAY_RE.match(_s(raw.get("day"), 10)):
        raise ValueError("not a report this version wrote")
    lesson = raw.get("lesson") if isinstance(raw.get("lesson"), dict) else None
    pipeline = raw.get("pipeline") if isinstance(raw.get("pipeline"), dict) else {}
    draft = raw.get("draft") if isinstance(raw.get("draft"), dict) else {}
    technique = _s((lesson or {}).get("technique"), 12)
    return {
        "schema": SCHEMA,
        "day": raw["day"],
        "persona": _s(raw.get("persona"), 120) or None,
        "headline": _s(raw.get("headline"), 160) or "Daily report",
        "bottom_line": _s(raw.get("bottom_line"), 1500),
        "changes": [_s(c, 400) for c in _list(raw.get("changes"), 5)],
        "tiles": [{"label": _s(t.get("label"), 40), "value": _i(t.get("value")),
                   "median": t.get("median") if isinstance(t.get("median"), (int, float))
                   and not isinstance(t.get("median"), bool) else None,
                   "days": None if t.get("days") is None else _i(t.get("days"))}
                  for t in _rows(raw.get("tiles"), 6)],
        "background": _s(raw.get("background"), 800),
        "campaigns": [{"slug": c["slug"], "title": _s(c.get("title"), 120),
                       "new": c.get("new") is True,
                       "sessions_today": _i(c.get("sessions_today")),
                       "days_seen": _i(c.get("days_seen")), "note": _s(c.get("note"), 400)}
                      for c in _rows(raw.get("campaigns"), 30)
                      if kbmod.SLUG_RE.match(_s(c.get("slug"), 60))],
        "lesson": {
            "title": _s(lesson.get("title"), 160),
            "technique": technique if kbmod.TECHNIQUE_RE.match(technique) else "",
            "technique_name": _s(lesson.get("technique_name"), 160),
            "body": _s(lesson.get("body"), 3000),
            "example": _s(lesson.get("example"), 1000),
        } if lesson else None,
        "suggestions": [{"id": s["id"], "title": _s(s.get("title"), 120),
                         "area": s.get("area") if s.get("area") in AREAS else "sensor",
                         "body": _s(s.get("body"), 2000), "evidence": _s(s.get("evidence"), 800)}
                        for s in _rows(raw.get("suggestions"), 3)
                        if SUGGESTION_ID_RE.match(_s(s.get("id"), 12))],
        "watch": [_s(w, 300) for w in _list(raw.get("watch"), 3)],
        "research": [{"indicator": _s(f.get("indicator"), 300), "known": _s(f.get("known"), 1000),
                      "sources": [{"title": _s(s.get("title"), 160), "url": s["url"]}
                                  for s in _rows(f.get("sources"), 4)
                                  if isinstance(s.get("url"), str) and URL_RE.match(s["url"])]}
                     for f in _rows(raw.get("research"), 8)],
        "limits": [_s(n, 500) for n in _list(raw.get("limits"), 12)],
        "pipeline": {"newest_event": _s(pipeline.get("newest_event"), 40),
                     "daily_facts_rebuilt": _s(pipeline.get("daily_facts_rebuilt"), 40)},
        "problems": [_s(n, 500) for n in _list(raw.get("problems"), 8)],
        "charts": [c for c in _list(raw.get("charts"), 3) if c in CHARTS],
        "draft": {"path": draft["path"], "title": _s(draft.get("title"), 160)}
        if DRAFT_RE.match(_s(draft.get("path"), 40)) else None,
    }
