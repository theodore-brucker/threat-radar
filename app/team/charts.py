"""The report's charts, drawn as PNG files.

PNG because the two places these are read, an email client and a Markdown
page on GitHub, both show it everywhere, and mail clients do not show SVG.
Each function returns PNG bytes, or None when the data would make a chart
that says nothing (a single day of history, for instance), and the caller
leaves that chart out.

Colours are the dashboard's light tokens from app/static/css/tokens.css. Every
chart here has one series, so the marks use --mark and nothing needs a legend:
the title says what is plotted. Values a reader needs exactly are also in a
table on the page that shows the chart.
"""

import datetime as dt
import io

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, MaxNLocator  # noqa: E402

SURFACE = "#FFFFFF"
INK = "#0F1A20"
INK_DIM = "#5A686E"
GRID = "#D6DDDA"
AXIS = "#A9B5B0"
MARK = "#36454D"
MARK_QUIET = "#A9B5B0"

WIDTH = 6.4             # inches; 1280 px at the dpi below, sharp on a tablet
DPI = 200
MAX_LABEL = 38

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8.5,
    "axes.edgecolor": AXIS, "axes.linewidth": 0.8,
    "xtick.color": INK_DIM, "ytick.color": INK_DIM,
    "xtick.major.size": 0, "ytick.major.size": 0,
})


def _figure(height, title):
    # A constrained layout keeps every chart the same width whatever its
    # labels need, so they line up when stacked in a message.
    fig, ax = plt.subplots(figsize=(WIDTH, height), dpi=DPI, facecolor=SURFACE,
                           layout="constrained")
    ax.set_facecolor(SURFACE)
    ax.set_title(title, loc="left", color=INK, fontsize=9.5, fontweight="bold", pad=10)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    return fig, ax


def _value_axis(ax, axis="y"):
    """Whole-number ticks with thousands separators and a hairline grid."""
    target = ax.yaxis if axis == "y" else ax.xaxis
    target.set_major_locator(MaxNLocator(nbins=4, integer=True))
    target.set_major_formatter(FuncFormatter(lambda v, _pos: "{:,.0f}".format(v)))
    ax.grid(axis=axis, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def _png(fig):
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", facecolor=SURFACE)
    plt.close(fig)
    return buffer.getvalue()


def _short_day(day):
    d = dt.date.fromisoformat(day)
    return "%s %d" % (d.strftime("%b"), d.day)


def _span(day, days):
    last = dt.date.fromisoformat(day)
    return [(last - dt.timedelta(days=n)).isoformat() for n in range(days - 1, -1, -1)]


def volume(series, day, median):
    """Sessions per day across the comparable window, the report's day last.

    Earlier days are drawn quieter so the day in question reads first, and
    the median is one labelled line.
    """
    if len(series) < 3:
        return None
    fig, ax = _figure(2.3, "Sessions per day")
    values = [s["sessions"] for s in series]
    colours = [MARK if s["day"] == day else MARK_QUIET for s in series]
    ax.bar(range(len(series)), values, width=0.55, color=colours)
    step = max(1, len(series) // 7)
    ticks = list(range(len(series) - 1, -1, -step))
    ax.set_xticks(ticks, [_short_day(series[i]["day"]) for i in ticks])
    _value_axis(ax)
    top = max(values + [median or 0])
    ax.set_ylim(0, top * 1.18 if top else 1)
    ax.text(len(series) - 1, values[-1] + top * 0.025, "{:,}".format(values[-1]),
            ha="center", va="bottom", color=INK, fontsize=8.5)
    if median is not None:
        ax.axhline(median, color=INK_DIM, linewidth=0.8)
        ax.text(-0.45, median + top * 0.025, "median {:,.0f}".format(median),
                ha="left", va="bottom", color=INK_DIM, fontsize=7.5)
    return _png(fig)


def hours(counts):
    """Sessions opened in each Eastern hour of the day."""
    if not any(counts):
        return None
    fig, ax = _figure(2.1, "Sessions opened by hour, Eastern time")
    ax.bar(range(24), counts, width=0.6, color=MARK)
    ax.set_xticks([0, 6, 12, 18, 23], ["12 AM", "6 AM", "12 PM", "6 PM", "11 PM"])
    ax.set_xlim(-0.7, 23.7)
    _value_axis(ax)
    peak = max(range(24), key=lambda h: counts[h])
    ax.set_ylim(0, counts[peak] * 1.18)
    ax.text(peak, counts[peak] * 1.03, "{:,}".format(counts[peak]),
            ha="center", va="bottom", color=INK, fontsize=8.5)
    return _png(fig)


def _label(text):
    text = " ".join(str(text or "").split())
    return text if len(text) <= MAX_LABEL else text[:MAX_LABEL - 1].rstrip() + "…"


def networks(rows, limit=8):
    """The networks that opened the most sessions, largest first."""
    rows = [r for r in rows if r["sessions"]][:limit]
    if len(rows) < 2:
        return None
    fig, ax = _figure(0.55 + 0.27 * len(rows), "Sessions by network")
    names = [_label("%s %s%s" % (r["asn"], r["org"] or "",
                                 " (new)" if r["new_in_window"] else "")) for r in rows]
    values = [r["sessions"] for r in rows]
    spots = range(len(rows) - 1, -1, -1)
    ax.barh(spots, values, height=0.5, color=MARK)
    ax.set_yticks(spots, names, color=INK)
    ax.spines["bottom"].set_visible(False)
    ax.set_xticks([])
    ax.set_xlim(0, max(values) * 1.14)
    for spot, value in zip(spots, values):
        ax.text(value + max(values) * 0.012, spot, "{:,}".format(value),
                ha="left", va="center", color=INK, fontsize=8.5)
    return _png(fig)


def campaign(days, day, span=30):
    """One campaign's sessions per day over the last `span` days."""
    window = _span(day, span)
    values = [days.get(d, 0) for d in window]
    fig, ax = _figure(1.7, "Sessions per day, %s to %s" % (_short_day(window[0]),
                                                           _short_day(window[-1])))
    ax.bar(range(span), values, width=0.6, color=MARK)
    ticks = list(range(span - 1, -1, -7))
    ax.set_xticks(ticks, [_short_day(window[i]) for i in ticks])
    ax.set_xlim(-0.7, span - 0.3)
    _value_axis(ax)
    ax.set_ylim(0, max(values + [1]) * 1.15)
    return _png(fig)


def overview(campaigns, activity, day, span=30, limit=10):
    """Which campaigns were seen on which of the last `span` days.

    One row per campaign, a dot on each day it was seen, larger for more
    sessions. campaigns is the knowledge base's records by slug.
    """
    window = _span(day, span)
    rows = sorted((c for c in campaigns.values()
                   if any(d in window for d in activity.get(c["slug"], {}))),
                  key=lambda c: c["last_seen"], reverse=True)[:limit]
    if not rows:
        return None
    fig, ax = _figure(0.6 + 0.28 * len(rows), "Campaigns seen, %s to %s"
                      % (_short_day(window[0]), _short_day(window[-1])))
    largest = max(max(activity[c["slug"]].get(d, 0) for d in window) for c in rows) or 1
    for spot, c in zip(range(len(rows) - 1, -1, -1), rows):
        seen = [(i, activity[c["slug"]][d]) for i, d in enumerate(window)
                if d in activity[c["slug"]]]
        ax.scatter([i for i, _ in seen], [spot] * len(seen),
                   s=[22 + 70 * (n / largest) ** 0.5 for _, n in seen],
                   color=MARK, edgecolors=SURFACE, linewidths=1.0, zorder=3)
    ax.set_yticks(range(len(rows) - 1, -1, -1), [_label(c["title"]) for c in rows], color=INK)
    ax.set_ylim(-0.6, len(rows) - 0.4)
    ticks = list(range(span - 1, -1, -7))
    ax.set_xticks(ticks, [_short_day(window[i]) for i in ticks])
    ax.set_xlim(-0.7, span - 0.3)
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    return _png(fig)
