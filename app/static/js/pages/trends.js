/* pages/trends.js - disruptive incidents at US organizations, by week.
 *
 * Every figure on the page carries the incident ids behind it. Choosing a
 * figure, a bar or a point lists those rows in the panel at the foot of the
 * page, and each row opens its incident page.
 */

import { api, h, svg, num, pct, panel, table, tag, emptyState, routeLink, shortDate } from "../core.js";

export const TITLE = "Incident trends";

const LABEL = {
  malicious: "Malicious cause stated",
  undisclosed: "Undisclosed or vague",
  nonmalicious: "Non-malicious or precautionary",
};

export function statusTag(s) {
  return tag(LABEL[s] || s, s === "malicious" ? "bad" : "info");
}

/* ---------- rows behind a figure ---------- */

let rowsBox = null;

async function showRows(title, ids) {
  if (!rowsBox) return;
  rowsBox.replaceChildren(h("p", { class: "sub", text: `Loading ${num(ids.length)} rows.` }));
  rowsBox.scrollIntoView({ block: "start", behavior: "smooth" });
  if (!ids.length) {
    rowsBox.replaceChildren(h("p", { class: "sub", text: `${title}: no rows.` }));
    return;
  }
  let d;
  try {
    d = await api(`/api/v1/trends/rows?ids=${ids.join(",")}`);
  } catch (err) {
    rowsBox.replaceChildren(h("p", { class: "sub",
      text: `The rows could not be loaded (${err.message}). Choose the figure again to retry.` }));
    return;
  }
  rowsBox.replaceChildren(
    h("h3", { class: "rowshead", text: `${title}: ${num(d.rows.length)} rows` }),
    incidentTable(d.rows));
}

export function incidentTable(rows, empty = "No incidents.") {
  return table(
    [{ label: "Started" }, { label: "Incident" }, { label: "Sector" },
     { label: "State" }, { label: "Cause status" }, { label: "Source" }],
    rows,
    (r) => [
      shortDate(r.started),
      routeLink(`/incident/${r.id}`, r.title, "plain"),
      r.sector || "-",
      r.state || "-",
      statusTag(r.cause_status),
      `${r.source}, ${r.confidence} confidence`,
    ],
    empty);
}

/* A figure that lists its rows when chosen. */
function figure(label, value, ids, title) {
  return h("div", { class: "stat" }, [
    h("button", {
      type: "button", class: "n figbtn", text: value,
      title: "List the rows behind this figure",
      onclick: () => showRows(title || label, ids),
    }),
    h("div", { class: "k", text: label }),
  ]);
}

/* ---------- charts ----------
   The SVG scales to its box with preserveAspectRatio none, so it holds no
   text; labels and the tooltip are HTML beside it and stay legible at
   400 px. */

function tooltip(wrap) {
  const tip = h("div", { class: "ttip", role: "status", hidden: true });
  wrap.appendChild(tip);
  return {
    show(text, frac) {
      tip.textContent = text;
      tip.hidden = false;
      tip.style.left = `${Math.min(Math.max(frac * 100, 10), 90)}%`;
    },
    hide() { tip.hidden = true; },
  };
}

function hotspot(el, tip, text, frac, onChoose) {
  el.setAttribute("tabindex", "0");
  el.setAttribute("role", "button");
  el.setAttribute("aria-label", text);
  el.addEventListener("mouseenter", () => tip.show(text, frac));
  el.addEventListener("focus", () => tip.show(text, frac));
  el.addEventListener("mouseleave", () => tip.hide());
  el.addEventListener("blur", () => tip.hide());
  el.addEventListener("click", onChoose);
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onChoose(); }
  });
}

function axis(first, last, maxLabel) {
  return h("div", { class: "taxis sub2" }, [
    h("span", { text: `Week of ${shortDate(first)}` }),
    h("span", { text: maxLabel }),
    h("span", { text: `Week of ${shortDate(last)}` }),
  ]);
}

function countChart(weeks) {
  const W = 100 * weeks.length;
  const H = 100;
  const max = Math.max(1, ...weeks.map((w) => w.incidents), ...weeks.map((w) => w.fitted || 0));
  const y = (v) => H - (v / max) * (H - 4);
  const wrap = h("div", { class: "tchart" });
  const el = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "tsvg",
    role: "group", "aria-label": "Incidents per week, one bar a week" });
  const tip = tooltip(wrap);
  weeks.forEach((w, i) => {
    const r = svg("rect", { x: i * 100 + 12, y: y(w.incidents), width: 76, height: H - y(w.incidents),
      class: w.partial ? "tbar partial" : "tbar" });
    hotspot(r, tip,
      `Week of ${shortDate(w.week)}: ${num(w.incidents)} incidents${w.partial ? " so far" : ""}`,
      (i + 0.5) / weeks.length,
      () => showRows(`Incidents, week of ${shortDate(w.week)}`, w.ids));
    el.appendChild(r);
  });
  const pts = weeks.filter((w) => w.fitted !== null && w.fitted !== undefined)
    .map((w) => `${weeks.indexOf(w) * 100 + 50},${y(Math.max(0, w.fitted)).toFixed(1)}`);
  if (pts.length > 1) {
    el.appendChild(svg("polyline", { points: pts.join(" "), class: "tfit",
      "vector-effect": "non-scaling-stroke" }));
  }
  wrap.prepend(el);
  wrap.appendChild(axis(weeks[0].week, weeks[weeks.length - 1].week, `Peak ${num(max)}`));
  return wrap;
}

function shareChart(weeks) {
  const W = 100 * weeks.length;
  const H = 100;
  const y = (v) => H - 4 - v * (H - 8);
  const wrap = h("div", { class: "tchart" });
  const el = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "tsvg",
    role: "group", "aria-label": "Share of each week's incidents with no stated cause" });
  const tip = tooltip(wrap);
  const has = weeks.map((w, i) => [w, i]).filter(([w]) => w.share_undisclosed !== null);
  if (has.length > 1) {
    el.appendChild(svg("polyline", {
      points: has.map(([w, i]) => `${i * 100 + 50},${y(w.share_undisclosed).toFixed(1)}`).join(" "),
      class: "tline", "vector-effect": "non-scaling-stroke" }));
  }
  has.forEach(([w, i]) => {
    // A column-wide target, so a point is easy to hit on a phone.
    const r = svg("rect", { x: i * 100, y: 0, width: 100, height: H, class: "thit" });
    hotspot(r, tip,
      `Week of ${shortDate(w.week)}: ${pct(w.share_undisclosed * 100, 0)} with no stated cause `
        + `(${num(w.undisclosed)} of ${num(w.incidents)})`,
      (i + 0.5) / weeks.length,
      () => showRows(`No stated cause, week of ${shortDate(w.week)}`, w.undisclosed_ids));
    el.appendChild(r);
    el.appendChild(svg("line", { x1: i * 100 + 50, x2: i * 100 + 50, y1: y(w.share_undisclosed),
      y2: y(w.share_undisclosed) + 0.01, class: "tdot", "vector-effect": "non-scaling-stroke" }));
  });
  wrap.prepend(el);
  wrap.appendChild(axis(weeks[0].week, weeks[weeks.length - 1].week, "0 to 100 percent"));
  return wrap;
}

function delayChart(delays) {
  const buckets = [["Same day", 0, 0], ["1 to 2 days", 1, 2], ["3 to 7 days", 3, 7],
    ["8 to 30 days", 8, 30], ["Over 30 days", 31, Infinity]];
  const rows = buckets.map(([label, lo, hi]) => {
    const inb = delays.filter((d) => d.days >= lo && d.days <= hi);
    return { label, n: inb.length, ids: inb.map((d) => d.incident_id) };
  });
  const max = Math.max(1, ...rows.map((r) => r.n));
  return h("div", { class: "tbuckets" }, rows.map((r) => h("button", {
    type: "button", class: "tbucket", title: "List these incidents",
    onclick: () => showRows(`First cause stated ${r.label.toLowerCase()} after the incident`, r.ids),
  }, [
    h("span", { class: "tbl", text: r.label }),
    h("span", { class: "ttrack" }, [h("span", { class: "tfill", style: `width:${(r.n / max) * 100}%` })]),
    h("span", { class: "tbn", text: num(r.n) }),
  ])));
}

function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/* ---------- page ---------- */

export async function render() {
  const d = await api("/api/v1/trends/summary");
  if (!d.built || !d.weeks || !d.weeks.length) {
    return emptyState("Incident trends have not been built yet.", {
      hint: "The trends worker loads the seed files and builds these tables on its first run, "
        + "and then every two hours.",
    });
  }
  rowsBox = h("div", { class: "rowsbox" }, [
    h("p", { class: "sub", text: "Choose any figure, bar or point above to list the incidents behind it." }),
  ]);
  const t = d.totals;
  const delays = d.delays || [];
  const med = median(delays.map((x) => x.days));
  const slope = d.slope_per_week;
  const cluster = (d.clusters || [])[0];

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("p", { text:
        "Disruptive incidents at US organizations: local government, schools, courts, hospitals, "
        + "utilities, banks, airlines and software suppliers. Each is tagged with the cause its "
        + "sources stated, which is often none. The figures cover every week on record, so the "
        + "window selector does not apply here." }),
      h("p", { class: "sub2", text:
        "Rows before November 2026 come from the DysruptionHub registry, with cause status "
        + "assigned by a model from one-line summaries, and are marked low confidence." }),
    ]),

    cluster ? h("div", { class: "banner warn", role: "status" }, [
      h("div", {}, [
        h("b", { text: `${num(cluster.outages)} national outages between ${shortDate(cluster.first_day)} `
          + `and ${shortDate(cluster.last_day)}` }),
        h("p", {}, [
          "Three or more national outages landed within five days. Most of these share no "
            + "stated cause, and a cluster is not evidence that they are linked. ",
          h("button", { type: "button", class: "linkish", text: "List them",
            onclick: () => showRows("National outages in the cluster", cluster.ids) }),
        ]),
      ]),
    ]) : null,

    h("div", { class: "stats" }, [
      figure("Incidents on record", num(t.incidents), t.ids),
      figure("With no stated cause", t.incidents ? pct((t.undisclosed / t.incidents) * 100, 0) : "-",
        t.undisclosed_ids, "Incidents with no stated cause"),
      figure("Median days to a stated cause", med === null ? "-" : num(med),
        delays.map((x) => x.incident_id), "Incidents with a dated stated cause"),
      figure("Supplier outages", num((d.fanouts || []).length),
        (d.fanouts || []).map((f) => f.incident_id)),
      figure("National outages", num((d.national || []).length),
        (d.national || []).map((n) => n.id)),
    ]),

    panel("Incidents per week",
      slope === null ? "Too few full weeks for a trend line."
        : `Bars are weekly counts; the line is a least-squares trend over full weeks, `
          + `${slope >= 0 ? "rising" : "falling"} by ${Math.abs(slope).toFixed(2)} incidents a week. `
          + "The current week is outlined because it is not over.",
      [countChart(d.weeks)]),

    panel("Share with no stated cause", "Each point is one week's undisclosed or vague incidents "
      + "as a share of that week's total.", [shareChart(d.weeks)]),

    panel("Days from incident to first stated cause",
      "Counted only where a source dates the first statement of a cause. Seed rows carry no "
        + "statement dates, so this fills in from November 2026 as feeds report.",
      [delays.length ? delayChart(delays)
        : h("p", { class: "sub", text: "No incident has a dated stated cause yet." })]),

    panel("Supplier outages", "One supplier's outage reaching many customers. Linked counts "
      + "incidents tied to the same supplier within a week.",
      [table(
        [{ label: "Date" }, { label: "Supplier" }, { label: "Product" },
         { label: "Customers", num: true }, { label: "Linked", num: true }, { label: "Cause status" }],
        d.fanouts || [],
        (f) => [
          shortDate(f.started),
          routeLink(`/vendor/${f.vendor_slug}`, f.vendor, "plain"),
          f.product || "-",
          f.customers === null ? "-" : num(f.customers),
          h("button", { type: "button", class: "linkish", text: num(f.linked),
            onclick: () => showRows(`Incidents linked to ${f.vendor}`, f.ids) }),
          statusTag(f.cause_status),
        ],
        "No supplier outages recorded.")]),

    panel("National outages", "Outages felt across the country. They are listed apart from "
      + "the weekly counts, which would otherwise count some of them twice.",
      [table(
        [{ label: "Date" }, { label: "Outage" }, { label: "Scope" }, { label: "Cause status" }],
        d.national || [],
        (n) => [shortDate(n.started), routeLink(`/incident/${n.id}`, n.title, "plain"),
          n.scope || "-", statusTag(n.cause_status)],
        "No national outages recorded.")]),

    panel("Rows behind the figure", null, [rowsBox]),
  ]);
}
