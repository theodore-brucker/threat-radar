"""Persona epochs.

The sensor has not presented the same host for its whole life. Each persona
change altered what attackers were being offered, so it altered what they
did. Trending across a boundary measures our own configuration change and
reports it as attacker behaviour.

This module answers three questions: which persona was live on a given day,
where the boundaries fall for drawing them, and whether a comparison spans
one. Same shape as outages.py, deliberately.
"""

import datetime as dt

from . import db


def epochs(con):
    if not db.table_exists(con, "persona_epochs"):
        return []
    return db.qall(
        con,
        "SELECT start_day, name, note FROM persona_epochs ORDER BY start_day",
    )


def epoch_for(con, day):
    """The persona live on `day`, or None for days before the first change."""
    if not day:
        return None
    live = None
    for e in epochs(con):
        if e["start_day"] <= day:
            live = e
        else:
            break
    return live


def spans_for_chart(con):
    """Boundary days, for drawing a rule on the activity chart."""
    return [{"day": e["start_day"], "name": e["name"], "note": e["note"]}
            for e in epochs(con)]


def boundary_between(con, start_day, end_day):
    """The persona change falling inside (start_day, end_day], if any.

    Used to mark a period-over-period comparison as not like-for-like. Only
    the most recent boundary in range is returned; two changes inside one
    window makes the comparison no more valid than one does.
    """
    if not start_day or not end_day:
        return None
    hit = [e for e in epochs(con) if start_day < e["start_day"] <= end_day]
    return hit[-1] if hit else None


def comparability(con, current_days, prior_days):
    """Describe whether two day lists can honestly be compared.

    Returns None when they can. Otherwise a dict naming the boundary and
    which side of it each window sits on, so the page can say so rather than
    printing a percentage that means nothing.
    """
    if not current_days or not prior_days:
        return None
    cur_lo, cur_hi = min(current_days), max(current_days)
    pri_lo = min(prior_days)

    # A window containing a boundary is the more specific problem, and it is
    # checked first: saying the window "ran as" one persona would be wrong
    # when it ran as two.
    inner = boundary_between(con, cur_lo, cur_hi)
    if inner:
        return {
            "comparable": False,
            "boundary": inner["start_day"],
            "persona": inner["name"],
            "reason": (f"This window opens before the sensor changed persona on "
                       f"{inner['start_day']} and closes after it, so it averages "
                       f"two different hosts together."),
        }

    cur_epoch = epoch_for(con, cur_hi)
    pri_epoch = epoch_for(con, pri_lo)
    cur_name = (cur_epoch or {}).get("name")
    pri_name = (pri_epoch or {}).get("name")
    if cur_name == pri_name:
        return None
    return {
        "comparable": False,
        "boundary": (boundary_between(con, pri_lo, cur_hi) or {}).get("start_day"),
        "persona": cur_name,
        "prior_persona": pri_name or "stock Cowrie profile",
        "reason": (f"The current window ran as {cur_name or 'a different persona'} "
                   f"and the prior one as {pri_name or 'a stock Cowrie profile'}. "
                   f"The movement between them reflects that change, not a change "
                   f"in attacker behaviour."),
    }


def day_span(start_day, end_day):
    """Inclusive YYYY-MM-DD list, for callers that need to iterate."""
    try:
        a = dt.date.fromisoformat(start_day)
        b = dt.date.fromisoformat(end_day)
    except (TypeError, ValueError):
        return []
    out, cur = [], a
    while cur <= b:
        out.append(cur.isoformat())
        cur += dt.timedelta(days=1)
    return out
