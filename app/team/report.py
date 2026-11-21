"""The daily report: assembled once, rendered three ways.

assemble() turns the stages' checked answers and the day's numbers into one
report dict, which is what the worker leaves in its outbox. The renderers
take that dict and nothing else:

  markdown()  the page filed under daily/ in the knowledge base
  email_html(), email_text()  the two parts of the message

The report keeps one order every day, the order published threat
intelligence uses, so it can be skimmed from the top: an executive summary a
reader can stop after, the day in numbers against its baseline, key findings
with a confidence each, the campaigns ranked with how each moved, one
technique taught from the evidence, the techniques and indicators seen,
recommended actions, an outlook, and the limits of the collection.
docs/TEAM.md lists where each part comes from.

Every string in a report may trace back to an attacker, so nothing here
trusts one. The HTML renderer escapes each value and defangs URLs and
addresses, because a mail client turns a bare URL into a link. The only live
links are ones this module builds: knowledge base pages, issues, MITRE
ATT&CK, and the sources the researcher cited.
"""

import datetime as dt
import html
import os
import re

from app.analytics.sessions import defang
from . import AREAS, kb as kbmod

SCHEMA = "threat-radar.team-report/2"
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

# Confidence is stated for a judgment about what was recorded. Likelihood is
# stated only for what has not happened yet.
CONFIDENCES = ("low", "moderate", "high")
LIKELIHOODS = ("very likely", "likely", "roughly even", "unlikely", "very unlikely")
PRIORITIES = ("high", "medium", "low")
MOVEMENTS = ("new", "returning", "up", "down", "steady")
TLP = ("CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED")
CONFIDENCE_NOTE = (
    "Confidence is the team's own. High means several independent records agree "
    "and nothing points the other way. Moderate means the evidence is credible "
    "but thin or partly inferred. Low means it rests on a fragment or an "
    "assumption.")

# Indicators an attacker finds costly to change come first, addresses last.
INDICATOR_KINDS = {"sha256": "File hash", "host": "Host", "hassh": "SSH client",
                   "ip": "Address"}
MAX_INDICATORS = 12

FONT = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, Menlo, Consolas, monospace"
INK, DIM, LINE, SUNK, ACCENT = "#0F1A20", "#5A686E", "#D6DDDA", "#ECF0EE", "#1E4E9C"
# (text, background) pairs from the dashboard's light tokens.
TONE = {
    "neutral": (DIM, SUNK),
    "accent": (ACCENT, "#E5ECF7"),
    "ok": ("#1F6B4A", "#E7F3ED"),
    "warn": ("#8A5D00", "#F6EDDA"),
    "alert": ("#A6192E", "#F7E6E9"),
}
CONFIDENCE_TONE = {"high": "ok", "moderate": "warn", "low": "neutral"}
PRIORITY_TONE = {"high": "alert", "medium": "warn", "low": "neutral"}


def long_day(day):
    d = dt.date.fromisoformat(day)
    return "%s, %s %d, %d" % (d.strftime("%A"), d.strftime("%B"), d.day, d.year)


# ---------------------------------------------------------------------------
# assembling
# ---------------------------------------------------------------------------

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


def _technique_table(tracked, active):
    """Each technique the tracker named, with the campaigns that showed it."""
    titles = {a["slug"]: a["title"] for a in active}
    rows = []
    for t in tracked["techniques"]:
        seen_in = [titles[c["slug"]] for c in tracked["campaigns"]
                   if t["id"] in c["techniques"] and c["slug"] in titles]
        rows.append({"id": t["id"], "name": t["name"], "campaigns": seen_in})
    return sorted(rows, key=lambda r: r["id"])


def _indicators(tracked, active, index):
    """The day's indicators with what each one is tied to, most durable kind
    first. Flagged files come from the collector's own lookups, the rest from
    what the tracker filed under a campaign."""
    titles = {a["slug"]: a["title"] for a in active}
    found = {}
    for f in index["files"]:
        if "malicious" in f["verdicts"] or "suspicious" in f["verdicts"]:
            context = f["verdicts"] + (", family %s" % f["family"] if f["family"] else "")
            found[("sha256", f["shasum"])] = [context]
    for c in tracked["campaigns"]:
        for i in c["indicators"]:
            if i["kind"] in INDICATOR_KINDS and c["slug"] in titles:
                found.setdefault((i["kind"], i["value"]), []).append(titles[c["slug"]])
    order = list(INDICATOR_KINDS)
    rows = [{"kind": kind, "value": value, "context": "; ".join(dict.fromkeys(context))}
            for (kind, value), context in found.items()]
    return sorted(rows, key=lambda r: (order.index(r["kind"]), r["value"]))[:MAX_INDICATORS]


def assemble(bundle, reading, findings, active, edited, problems, charts, tracked=None):
    """One report dict from whatever the run produced.

    reading, tracked and edited are None when their stage did not run or
    failed. The report then carries the numbers and says what is missing, so
    a model outage costs the analysis and not the email.
    """
    index, day = bundle["index"], bundle["day"]
    edited = edited or {}
    tracked = tracked or {"campaigns": [], "techniques": []}
    notes = edited.get("campaign_notes") or {}
    if index["empty"]:
        headline = "The sensor recorded nothing on %s" % day
        summary = ("No event is stored for this day. Check the pipeline times at the "
                   "foot of this report against the clock.")
    elif edited:
        headline, summary = edited["headline"], edited["executive_summary"]
    else:
        headline = "Numbers for %s, without the written analysis" % day
        summary = (reading or {}).get("summary") or \
            "The analysis stages did not finish, so this report carries the counts only."
    tlp = os.environ.get("TR_TEAM_TLP", "AMBER").upper()
    ranked = sorted(active, key=lambda a: (-a["sessions_today"], a["title"]))
    return {
        "schema": SCHEMA,
        "day": day,
        "generated_at": bundle["generated_at"],
        "persona": index["persona"],
        "persona_since": index["persona_since"],
        "tlp": tlp if tlp in TLP else "AMBER",
        "headline": headline,
        "executive_summary": summary,
        "tiles": _tiles(index),
        "key_findings": edited.get("key_findings") or [],
        "campaigns": [{"slug": a["slug"], "title": a["title"], "new": a["new"],
                       "movement": a["movement"], "sessions_today": a["sessions_today"],
                       "sessions_before": a["sessions_before"], "gap_days": a["gap_days"],
                       "days_seen": a["days_seen"], "note": notes.get(a["slug"], "")}
                      for a in ranked],
        "background": (reading or {}).get("background") or "",
        "lesson": edited.get("lesson"),
        "techniques": _technique_table(tracked, active),
        "indicators": _indicators(tracked, active, index),
        "suggestions": edited.get("suggestions") or [],
        "outlook": edited.get("outlook") or [],
        "research": [f for f in findings or [] if f["known"] != "Nothing found."],
        "limits": bundle["limits"],
        "pipeline": index["pipeline"],
        "problems": problems,
        "charts": [name for name in CHARTS if name in charts],
        "draft": None,
    }


# ---------------------------------------------------------------------------
# wording shared by the renderers
# ---------------------------------------------------------------------------

def _count(n, noun):
    return "{:,} {}{}".format(n, noun, "" if n == 1 else "s")


def _baseline(tile):
    """How a count compares with the median of earlier days, in words."""
    if tile["days"] is None:
        return ""
    if tile["median"] is None or tile["days"] < BASELINE_MIN_DAYS:
        return "no baseline yet"
    median = tile["median"]
    if not median:
        return "median 0"
    change = round(100.0 * (tile["value"] - median) / median)
    if change == 0:
        return "at its median of {:,.0f}".format(median)
    return "{:+,d}% against a median of {:,.0f}".format(change, median)


def _trend(c):
    """How a campaign moved since the last day it was seen."""
    if c["movement"] == "new":
        return "new"
    if c["movement"] == "returning":
        return "back after %s" % _count(c["gap_days"], "day")
    if c["movement"] == "steady":
        return "steady"
    return "%s from %s" % (c["movement"], "{:,}".format(c["sessions_before"]))


def _label(title):
    """A link label: square brackets would end it early."""
    return kbmod.one_line(str(title or "").replace("[", "(").replace("]", ")"), 90) or "source"


# ---------------------------------------------------------------------------
# markdown, for the knowledge base
# ---------------------------------------------------------------------------

def _cell(value, limit=300):
    return kbmod.one_line(value, limit).replace("|", "/")


def markdown(report):
    day, text, line = report["day"], kbmod.md_text, kbmod.one_line
    charts = "../../charts/%s" % day
    out = ["# %s" % line(report["headline"], 160), "",
           "%s. Sensor persona: %s. TLP:%s." % (
               long_day(day), line(report["persona"] or "unknown"), report["tlp"]), "",
           "## Executive summary", "", text(report["executive_summary"]), "",
           "## The day in numbers", "", "| Measure | Count | Against earlier days |",
           "|---|---|---|"]
    out += ["| %s | %s | %s |" % (t["label"], "{:,}".format(t["value"]), _baseline(t))
            for t in report["tiles"]] + [""]
    if report["key_findings"]:
        out += ["## Key findings", ""]
        for n, f in enumerate(report["key_findings"], 1):
            out.append("%d. **%s**%s *Confidence: %s.*" % (
                n, line(f["finding"], 320), " %s" % line(f["why"], 320) if f["why"] else "",
                f["confidence"]))
        out.append("")
    if report["campaigns"]:
        out += ["## Campaigns", "", "| Campaign | Trend | Sessions | Days seen | Yesterday |",
                "|---|---|---|---|---|"]
        for c in report["campaigns"]:
            out.append("| [%s](../../campaigns/%s.md) | %s | %s | %d | %s |" % (
                _cell(c["title"], 80), c["slug"], _trend(c),
                "{:,}".format(c["sessions_today"]), c["days_seen"], _cell(c["note"])))
        out.append("")
    for name in report["charts"]:
        out += ["![%s](%s/%s.png)" % (CHART_ALT[name], charts, name), ""]
    lesson = report["lesson"]
    if lesson:
        out += ["## Technique of the day: %s" % line(lesson["title"], 120), ""]
        if lesson["technique"]:
            out += ["[%s %s](%s)" % (lesson["technique"], line(lesson["technique_name"], 120),
                                     kbmod.mitre_url(lesson["technique"])), ""]
        out += [text(lesson["body"], 2500), ""]
        if lesson["example"]:
            out += ["Recorded example:", ""]
            out += ["    " + ln for ln in text(lesson["example"], 800).splitlines()] + [""]
        if lesson["detection"]:
            out += ["**How to detect it.** " + text(lesson["detection"], 500), ""]
    if report["techniques"]:
        out += ["## ATT&CK techniques seen", "", "| Technique | Name | Seen in |", "|---|---|---|"]
        out += ["| [%s](../../techniques/%s.md) | %s | %s |" % (
            t["id"], t["id"], _cell(t["name"], 120),
            _cell(", ".join(t["campaigns"]), 300)) for t in report["techniques"]] + [""]
    if report["indicators"]:
        out += ["## Indicators", "", "| Type | Value | Tied to |", "|---|---|---|"]
        out += ["| %s | %s | %s |" % (INDICATOR_KINDS[i["kind"]], kbmod.code(i["value"]),
                                      _cell(i["context"])) for i in report["indicators"]] + [""]
    if report["suggestions"]:
        out += ["## Recommended actions", ""]
        for s in report["suggestions"]:
            out += ["- **%s** (%s priority, %s). %s%s" % (
                line(s["title"], 90), s["priority"], s["area"], line(s["body"], 1500),
                " Evidence: %s" % line(s["evidence"], 600) if s["evidence"] else "")]
        out.append("")
    if report["outlook"]:
        out += ["## Outlook", ""]
        out += ["- %s (%s).%s" % (line(o["expect"], 300).rstrip("."), o["likelihood"],
                                  " Watch for: %s" % line(o["watch_for"], 250)
                                  if o["watch_for"] else "") for o in report["outlook"]] + [""]
    if report["background"]:
        out += ["## Background", "", text(report["background"]), ""]
    if report["draft"]:
        out += ["## Blog draft", "", "The candidate for this week: [%s](../../%s)." % (
            _label(report["draft"]["title"]), report["draft"]["path"]), ""]
    if report["research"]:
        out += ["## What the web says", ""]
        for f in report["research"]:
            links = ", ".join("[%s](%s)" % (_label(s["title"]), s["url"]) for s in f["sources"])
            out += ["- %s: %s%s" % (kbmod.code(f["indicator"]), line(f["known"], 900),
                                    " Sources: %s." % links if links else "")]
        out.append("")
    out += ["## Collection notes", ""]
    out += ["- " + line(n, 400) for n in report["limits"] + report["problems"]]
    out += ["- " + CONFIDENCE_NOTE, ""]
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


def _chip(text, tone="neutral"):
    colour, background = TONE[tone]
    return ('<span style="display:inline-block;padding:1px 7px;border-radius:4px;'
            'background:%s;color:%s;font-size:11px;font-weight:600;letter-spacing:.03em;'
            'text-transform:uppercase;white-space:nowrap">%s</span>'
            % (background, colour, html.escape(text)))


def subject(report):
    return "Threat Radar %s: %s" % (report["day"], " ".join(report["headline"].split())[:120])


def email_html(report, kb_url="", issues=None):
    """The HTML part. Charts are referenced as cid:<name>, which the sender
    attaches. issues maps a suggestion id to the URL of the issue filed for
    it."""
    issues = issues or {}
    day = report["day"]
    p = "margin:0 0 12px 0;font-size:15px;line-height:1.55;color:%s" % INK
    h2 = ("margin:30px 0 10px 0;padding-top:14px;border-top:1px solid %s;font-size:12px;"
          "letter-spacing:.06em;text-transform:uppercase;color:%s;font-weight:600" % (LINE, DIM))
    small = "font-size:12px;line-height:1.5;color:%s" % DIM
    cell = ("padding:8px 10px 8px 0;border-bottom:1px solid %s;font-size:13px;line-height:1.45;"
            "color:%s;vertical-align:top" % (LINE, INK))
    head = ("padding:0 10px 6px 0;border-bottom:1px solid %s;font-size:11px;letter-spacing:.04em;"
            "text-transform:uppercase;color:%s;text-align:left;font-weight:600" % (LINE, DIM))
    table = ('<table role="presentation" cellspacing="0" cellpadding="0" '
             'style="width:100%;border-collapse:collapse">')

    def page(path, label):
        return _link("%s/blob/main/%s" % (kb_url, path), label) if kb_url else label

    out = ['<div style="font-family:%s;max-width:680px;margin:0 auto;padding:20px 16px;color:%s">'
           % (FONT, INK),
           '%s<tr><td style="%s;letter-spacing:.06em;text-transform:uppercase;font-weight:600">'
           'Threat Radar &middot; daily intel</td><td style="text-align:right">%s</td></tr></table>'
           % (table, small, _chip("TLP:" + report["tlp"],
                                  "warn" if report["tlp"].startswith("AMBER") else "neutral")),
           '<div style="%s;margin-top:4px">%s &middot; %s</div>'
           % (small, _e(long_day(day)), _e(report["persona"] or "persona unknown")),
           '<h1 style="margin:12px 0 14px 0;font-size:24px;line-height:1.25;color:%s">%s</h1>'
           % (INK, _e(report["headline"])),
           '<div style="padding:14px 16px;background:%s;border-left:4px solid %s;border-radius:4px">'
           '<div style="font-size:11px;letter-spacing:.06em;text-transform:uppercase;'
           'font-weight:600;color:%s;margin-bottom:6px">Executive summary</div>%s</div>'
           % (TONE["accent"][1], ACCENT, ACCENT,
              _paragraphs(report["executive_summary"],
                          "margin:0;font-size:16px;line-height:1.55;color:%s" % INK))]

    out.append('<table role="presentation" cellspacing="0" cellpadding="0" '
               'style="width:100%;border-collapse:collapse;margin:16px 0 0 0"><tr>')
    for t in report["tiles"]:
        out.append('<td width="20%%" style="padding:10px 8px;background:%s;'
                   'border-right:3px solid #FFFFFF;vertical-align:top">'
                   '<div style="font-size:21px;font-weight:600;color:%s">%s</div>'
                   '<div style="%s;color:%s">%s</div><div style="%s">%s</div></td>'
                   % (SUNK, INK, "{:,}".format(t["value"]), small, INK, _e(t["label"]),
                      small, _e(_baseline(t))))
    out.append("</tr></table>")

    if report["key_findings"]:
        out.append('<h2 style="%s">Key findings</h2>%s' % (h2, table))
        for n, f in enumerate(report["key_findings"], 1):
            out.append('<tr><td style="%s;width:26px;font-size:15px;font-weight:600;color:%s">%d'
                       '</td><td style="%s;font-size:15px"><strong>%s</strong>%s'
                       '<div style="margin-top:5px">%s</div></td></tr>'
                       % (cell, DIM, n, cell, _e(f["finding"]),
                          " %s" % _e(f["why"]) if f["why"] else "",
                          _chip(f["confidence"] + " confidence",
                                CONFIDENCE_TONE[f["confidence"]])))
        out.append("</table>")

    if report["campaigns"]:
        out.append('<h2 style="%s">Campaigns</h2>%s<tr><th style="%s">Campaign</th>'
                   '<th style="%s">Trend</th><th style="%s;text-align:right">Sessions</th></tr>'
                   % (h2, table, head, head, head))
        for c in report["campaigns"]:
            out.append('<tr><td style="%s"><strong>%s</strong><br><span style="%s">%s</span></td>'
                       '<td style="%s;white-space:nowrap">%s</td>'
                       '<td style="%s;white-space:nowrap;text-align:right">%s<br>'
                       '<span style="%s">day %d</span></td></tr>'
                       % (cell, page("campaigns/%s.md" % c["slug"], _e(c["title"])), small,
                          _e(c["note"]), cell,
                          _chip(_trend(c), "accent" if c["movement"] == "new" else "neutral"),
                          cell, "{:,}".format(c["sessions_today"]), small, c["days_seen"]))
        out.append("</table>")

    for name in report["charts"]:
        out.append('<img src="cid:%s" alt="%s" width="648" style="display:block;width:100%%;'
                   'max-width:648px;height:auto;margin:18px 0 0 0;border:0">'
                   % (name, html.escape(CHART_ALT[name])))

    lesson = report["lesson"]
    if lesson:
        out.append('<h2 style="%s">Technique of the day</h2><div style="font-size:18px;'
                   'font-weight:600;line-height:1.3;margin:0 0 6px 0;color:%s">%s</div>'
                   % (h2, INK, _e(lesson["title"])))
        if lesson["technique"]:
            out.append('<div style="%s;margin:0 0 10px 0">%s</div>' % (small, _link(
                kbmod.mitre_url(lesson["technique"]),
                "%s %s" % (lesson["technique"], _e(lesson["technique_name"])))))
        out.append(_paragraphs(lesson["body"], p))
        if lesson["example"]:
            out.append('<pre style="margin:0 0 12px 0;padding:10px 12px;background:%s;'
                       'border-radius:4px;font-family:%s;font-size:12px;line-height:1.5;color:%s;'
                       'white-space:pre-wrap;word-break:break-word">%s</pre>'
                       % (SUNK, MONO, INK, _e(lesson["example"])))
        if lesson["detection"]:
            out.append('<p style="%s"><strong>How to detect it.</strong> %s</p>'
                       % (p, _e(lesson["detection"])))

    if report["techniques"]:
        out.append('<h2 style="%s">ATT&amp;CK techniques seen</h2>%s' % (h2, table))
        for t in report["techniques"]:
            out.append('<tr><td style="%s;white-space:nowrap;font-family:%s;font-size:12px">%s</td>'
                       '<td style="%s">%s<br><span style="%s">%s</span></td></tr>'
                       % (cell, MONO, _link(kbmod.mitre_url(t["id"]), t["id"]), cell,
                          _e(t["name"]), small, _e(", ".join(t["campaigns"]))))
        out.append("</table>")

    if report["indicators"]:
        out.append('<h2 style="%s">Indicators</h2>%s' % (h2, table))
        for i in report["indicators"]:
            out.append('<tr><td style="%s;white-space:nowrap;color:%s;font-size:12px">%s</td>'
                       '<td style="%s"><span style="font-family:%s;font-size:12px;'
                       'word-break:break-all">%s</span><br><span style="%s">%s</span></td></tr>'
                       % (cell, DIM, INDICATOR_KINDS[i["kind"]], cell, MONO, _e(i["value"]),
                          small, _e(i["context"])))
        out.append("</table>")

    if report["suggestions"]:
        out.append('<h2 style="%s">Recommended actions</h2>' % h2)
        for s in report["suggestions"]:
            title = _e(s["title"])
            if issues.get(s["id"]):
                title = _link(issues[s["id"]], title)
            out.append('<p style="%s">%s <span style="%s">%s</span><br><strong>%s</strong><br>'
                       '%s%s</p>'
                       % (p, _chip(s["priority"] + " priority", PRIORITY_TONE[s["priority"]]),
                          small, _e(s["area"]), title, _e(s["body"]),
                          '<br><span style="%s">Evidence: %s</span>' % (small, _e(s["evidence"]))
                          if s["evidence"] else ""))

    if report["outlook"]:
        out.append('<h2 style="%s">Outlook</h2>' % h2)
        for o in report["outlook"]:
            out.append('<p style="%s">%s %s%s</p>'
                       % (p, _chip(o["likelihood"], "accent"), _e(o["expect"]),
                          '<br><span style="%s">Watch for: %s</span>' % (small, _e(o["watch_for"]))
                          if o["watch_for"] else ""))

    if report["background"]:
        out.append('<h2 style="%s">Background</h2>%s' % (h2, _paragraphs(report["background"], p)))

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

    foot = [_e(n) for n in report["limits"] + report["problems"]] + [_e(CONFIDENCE_NOTE)]
    pipe = report["pipeline"]
    foot.append("Newest event %s. Daily tables rebuilt %s." % (
        _e(pipe.get("newest_event") or "unknown"),
        _e(pipe.get("daily_facts_rebuilt") or "unknown")))
    if kb_url:
        foot.append("%s &middot; %s &middot; %s" % (
            page("daily/%s/%s.md" % (day[:4], day), "This report in the knowledge base"),
            page("INDEX.md", "All campaigns"),
            page("feedback.md", "Steer the team")))
    out.append('<h2 style="%s">Collection notes</h2>' % h2)
    out += ['<p style="margin:0 0 6px 0;%s">%s</p>' % (small, line) for line in foot]
    out.append("</div>")
    return "\n".join(out)


def email_text(report):
    """The plain-text part, for a client that shows no HTML."""
    t = lambda value: defang(str(value or ""))  # noqa: E731
    out = [t(report["headline"]), "", t(report["executive_summary"]), ""]
    out += ["%s: %s%s" % (x["label"], "{:,}".format(x["value"]),
                          " (%s)" % _baseline(x) if _baseline(x) else "")
            for x in report["tiles"]] + [""]
    out += ["%d. %s %s (%s confidence)" % (n, t(f["finding"]), t(f["why"]), f["confidence"])
            for n, f in enumerate(report["key_findings"], 1)]
    for c in report["campaigns"]:
        out.append("Campaign %s: %s, %s, day %d. %s" % (
            t(c["title"]), _count(c["sessions_today"], "session"), _trend(c), c["days_seen"],
            t(c["note"])))
    if report["lesson"]:
        out += ["", "Technique of the day: " + t(report["lesson"]["title"]),
                t(report["lesson"]["body"])]
    for s in report["suggestions"]:
        out += ["", "Action (%s priority, %s): %s" % (s["priority"], s["area"], t(s["title"])),
                t(s["body"])]
    out += ["Outlook (%s): %s" % (o["likelihood"], t(o["expect"])) for o in report["outlook"]]
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


def _one_of(value, options, default):
    return value if isinstance(value, str) and value in options else default


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
        "tlp": _one_of(raw.get("tlp"), TLP, "AMBER"),
        "headline": _s(raw.get("headline"), 160) or "Daily report",
        "executive_summary": _s(raw.get("executive_summary"), 1500),
        "tiles": [{"label": _s(t.get("label"), 40), "value": _i(t.get("value")),
                   "median": t.get("median") if isinstance(t.get("median"), (int, float))
                   and not isinstance(t.get("median"), bool) else None,
                   "days": None if t.get("days") is None else _i(t.get("days"))}
                  for t in _rows(raw.get("tiles"), 6)],
        "key_findings": [{"finding": _s(f.get("finding"), 400), "why": _s(f.get("why"), 400),
                          "confidence": _one_of(f.get("confidence"), CONFIDENCES, "low")}
                         for f in _rows(raw.get("key_findings"), 5)],
        "campaigns": [{"slug": c["slug"], "title": _s(c.get("title"), 120),
                       "new": c.get("new") is True,
                       "movement": _one_of(c.get("movement"), MOVEMENTS, "steady"),
                       "sessions_today": _i(c.get("sessions_today")),
                       "sessions_before": _i(c.get("sessions_before")),
                       "gap_days": _i(c.get("gap_days")),
                       "days_seen": _i(c.get("days_seen")), "note": _s(c.get("note"), 400)}
                      for c in _rows(raw.get("campaigns"), 30)
                      if kbmod.SLUG_RE.match(_s(c.get("slug"), 60))],
        "background": _s(raw.get("background"), 800),
        "lesson": {
            "title": _s(lesson.get("title"), 160),
            "technique": technique if kbmod.TECHNIQUE_RE.match(technique) else "",
            "technique_name": _s(lesson.get("technique_name"), 160),
            "body": _s(lesson.get("body"), 3000),
            "example": _s(lesson.get("example"), 1000),
            "detection": _s(lesson.get("detection"), 600),
        } if lesson else None,
        "techniques": [{"id": t["id"], "name": _s(t.get("name"), 160),
                        "campaigns": [_s(c, 120) for c in _list(t.get("campaigns"), 8)]}
                       for t in _rows(raw.get("techniques"), 20)
                       if kbmod.TECHNIQUE_RE.match(_s(t.get("id"), 12))],
        "indicators": [{"kind": i["kind"], "value": _s(i.get("value"), 300),
                        "context": _s(i.get("context"), 400)}
                       for i in _rows(raw.get("indicators"), MAX_INDICATORS)
                       if _one_of(i.get("kind"), tuple(INDICATOR_KINDS), "")],
        "suggestions": [{"id": s["id"], "title": _s(s.get("title"), 120),
                         "area": _one_of(s.get("area"), AREAS, "sensor"),
                         "priority": _one_of(s.get("priority"), PRIORITIES, "medium"),
                         "body": _s(s.get("body"), 2000), "evidence": _s(s.get("evidence"), 800)}
                        for s in _rows(raw.get("suggestions"), 3)
                        if SUGGESTION_ID_RE.match(_s(s.get("id"), 12))],
        "outlook": [{"expect": _s(o.get("expect"), 400),
                     "likelihood": _one_of(o.get("likelihood"), LIKELIHOODS, "roughly even"),
                     "watch_for": _s(o.get("watch_for"), 300)}
                    for o in _rows(raw.get("outlook"), 3)],
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
