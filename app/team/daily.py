"""One day's run, start to outbox.

run() is the whole of what the worker account does: read the knowledge base,
gather the day, ask the stages, and leave a report, charts and knowledge base
files in the outbox for the publisher.

A stage that fails costs its own contribution and nothing else. Without the
reader there is no written analysis, and the report carries the numbers and
says so. Without the tracker, shapes the knowledge base already knows are
still counted against their campaigns. The outbox is written in every case,
because a report that says what is missing is more use than no mail.
"""

import datetime as dt
import json
import os
import shutil

from . import KEEP_DAYS, bundle as bundlemod, charts, kb as kbmod, model, outbox
from . import report as reportmod, stages


def _save(work, name, value):
    with open(os.path.join(work, name + ".json"), "w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=1, sort_keys=True)


def _is_week_end(day):
    """The run after a Saturday is the Sunday run, which drafts the week."""
    return dt.date.fromisoformat(day).isoweekday() == 6


def _draft(after, kb, day, ask):
    """(path, page, title) of a blog draft, or None when no campaign seen
    this week is marked for a write-up."""
    first = (dt.date.fromisoformat(day) - dt.timedelta(days=6)).isoformat()
    candidates = {slug: kbmod.render_campaign(c, after["techniques"])
                  for slug, c in after["campaigns"].items()
                  if c["publishable"] and c["status"] != kbmod.HISTORICAL
                  and c["last_seen"] >= first}
    written = stages.draft(candidates, kb, ask)
    if not written:
        return None
    year, week, _ = dt.date.fromisoformat(day).isocalendar()
    page = "\n".join([
        "# %s" % kbmod.one_line(written["title"], 150), "",
        "Draft from the campaign [%s](../campaigns/%s.md), written by the team "
        "for the week ending %s. Check every statement against the campaign "
        "page before publishing." % (written["campaign"], written["campaign"], day),
        "", written["body"], ""])
    return "drafts/%d-W%02d.md" % (year, week), page, written["title"]


def prune(state_dir, day):
    """Remove stage outputs and outboxes older than KEEP_DAYS."""
    cutoff = (dt.date.fromisoformat(day) - dt.timedelta(days=KEEP_DAYS)).isoformat()
    for sub in ("work", "outbox"):
        root = os.path.join(state_dir, sub)
        for name in os.listdir(root) if os.path.isdir(root) else []:
            if kbmod.DAY_RE.match(name[:10]) and name[:10] < cutoff:
                shutil.rmtree(os.path.join(root, name), ignore_errors=True)


def run(con, day, kb_dir, state_dir, use_model=True, ask=model.ask_json, log=print):
    kb = kbmod.load(kb_dir)
    bundle = bundlemod.build(con, day, kbmod.known_shapes(kb), kb["watch"])
    index = bundle["index"]
    work = os.path.join(state_dir, "work", day)
    os.makedirs(work, exist_ok=True)
    _save(work, "bundle", bundle)

    problems = []

    def stage(name, call):
        try:
            answer = call()
        except model.StageError as exc:
            log("%s failed: %s" % (name, exc))
            problems.append("The %s stage failed: %s" % (name, exc))
            return None
        except Exception as exc:
            # A stage handles model output, which can take any shape. A fault
            # in handling it costs that stage, like any other failure, and is
            # named in the report so it gets fixed.
            log("%s crashed: %r" % (name, exc))
            problems.append("The %s stage crashed (%s). This is a bug in the team's code."
                            % (name, type(exc).__name__))
            return None
        _save(work, name, answer)
        log("%s done" % name)
        return answer

    reading = findings = tracked = edited = None
    if index["empty"]:
        log("no events for %s" % day)
    elif not use_model:
        problems.append("The analysis stages were switched off for this run.")
    else:
        reading = stage("reader", lambda: stages.read(bundle, kb, ask))
    if reading:
        findings = stage("research", lambda: stages.research(reading, bundle, kb, ask)) or []
        tracked = stage("tracker", lambda: stages.track(reading, findings, bundle, kb, ask))

    files, active, after = kbmod.apply(kb, tracked, index, day)
    if reading:
        edited = stage("editor",
                       lambda: stages.edit(bundle, reading, findings, active, kb, ask))

    drawn = {"volume": charts.volume(index["series"], day,
                                     index["metrics"]["sessions"]["median"]),
             "hours": charts.hours(index["hours"]),
             "networks": charts.networks(index["networks"])}
    drawn = {name: png for name, png in drawn.items() if png}
    for name, png in drawn.items():
        files["charts/%s/%s.png" % (day, name)] = png
    for a in active:
        files["charts/campaigns/%s.png" % a["slug"]] = charts.campaign(
            after["activity"][a["slug"]], day)
    overview = charts.overview(after["campaigns"], after["activity"], day)
    if overview:
        files["charts/overview.png"] = overview
    files["INDEX.md"] = kbmod.index_page(
        after["campaigns"], after["techniques"], day,
        overview=bool(overview) or os.path.exists(os.path.join(kb_dir, "charts", "overview.png")))

    report = reportmod.assemble(bundle, reading, findings, active, edited, problems, drawn)
    if edited and _is_week_end(day):
        written = stage("writer", lambda: _draft(after, kb, day, ask))
        if written:
            path, page, title = written
            files[path] = page
            report["draft"] = {"path": path, "title": title}
    files["daily/%s/%s.md" % (day[:4], day)] = reportmod.markdown(report)
    files["state/lessons.json"] = kbmod.with_lesson(kb, report["lesson"], day)

    where = outbox.write(state_dir, day, report, files)
    prune(state_dir, day)
    log("outbox written: %s (%d files)" % (where, len(files)))
    return report
