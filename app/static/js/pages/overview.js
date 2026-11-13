/* pages/overview.js v5 - two audiences, one dataset.
 *
 * Summary mode answers three questions in order: how far do intruders get,
 * is that moving, and what should I take away. The escalation funnel is the
 * hero because it is the one thing this site is about; v4 opened with three
 * number cards that restated the funnel's first rows, so they are folded into
 * a line of trends under it. Analyst mode keeps the dense original.
 */

import {
  api, h, num, panel, stats, table, shortDate, dur, state, isExec,
  stageTag, ipLink, trendLine, takeaway, hbars, svg, emptyState, icon, place,
  routeLink, pageState,
} from "../core.js";
import { railFull, funnelExec, onStageChange } from "../rail.js";
import { escalationMap, applyFilter } from "../map.js";

export const TITLE = "Overview";

const GOAL_NAMES = {
  "crypto-solana": "Crypto and blockchain accounts",
  "crypto-general": "Crypto wallets and mining",
  "file-transfer": "File transfer accounts",
  "finance-erp": "Finance and ERP accounts",
  database: "Database accounts",
  "devops-ci": "Build and deployment accounts",
  "iot-default": "Default device passwords",
  "cloud-vm": "Cloud server defaults",
  "admin-generic": "Generic administrator accounts",
  "app-service": "Application service accounts",
  mail: "Mail server accounts",
  "vpn-remote": "Remote access accounts",
  backup: "Backup system accounts",
  "test-dev": "Test and demo accounts",
  "keyboard-walk": "Common weak passwords",
  "hostname-derived": "Passwords built from our own hostname",
  "shell-injection": "Commands hidden in the login field",
};

/* When the comparison window straddles a persona change, the percentages
   beside every signal describe our own reconfiguration. Print that instead of
   letting the number stand on its own. */
function personaNote(t) {
  const n = t && t.persona_note;
  if (!n || n.comparable) return null;
  return h("p", { class: "persona-note" }, [
    h("b", { text: "These changes are not like for like. " }),
    h("span", { text: n.reason }),
  ]);
}

/* Only a problem earns a banner. A healthy sensor is the normal state and the
   rail footer already says so; v4 drew a "Sensor healthy" box on every visit. */
function healthBanner(hl) {
  // A lagging pull already raises the bar across the top of every page, so
  // the overview only adds a banner for a fault, where it has more to say.
  if (!hl || hl.status !== "fault") return null;
  const fault = hl.status === "fault";
  return h("div", { class: `banner ${fault ? "fault" : "warn"}`, role: "status" }, [
    icon(fault ? "octagon-alert" : "triangle-alert", { size: 18 }),
    h("div", {}, [
      h("b", { text: fault ? "The sensor is not recording logins." : "Recent data may be behind." }),
      h("p", { text: hl.message }),
      fault
        ? h("p", { text: `The last successful login was recorded on ${hl.last_auth_day || "no date on file"}. `
            + "Every stage after the first is frozen until the sensor is fixed." })
        : null,
    ]),
  ]);
}

function pagehead(d) {
  const span = d.first_day && d.last_day ? `, between ${d.first_day} and ${d.last_day}` : "";
  return h("div", { class: "pagehead" }, [
    h("h2", { text: "What happens to a server left open on the public internet" }),
    h("p", { text:
      "This is a decoy SSH server, deliberately exposed and dressed up as a machine worth "
      + "breaking into. Nothing real runs on it, so everything that connects is uninvited, "
      + "and every attempt is recorded." }),
    h("p", { class: "sub2", text:
      `${num(d.events_total)} recorded events from ${num(d.sources_total)} addresses `
      + `in ${num(d.countries)} countries${span}.` }),
  ]);
}

/* A fresh install with nothing ingested yet. Say what the page will show and
   when, rather than drawing a funnel of zeroes and a map with no points. */
function firstRun() {
  return pageState({
    iconName: "compass",
    title: "No traffic has been recorded yet.",
    text: "Figures appear here after the first log pull from the sensor is ingested, "
      + "which normally happens within one pull cycle of the sensor going live. If it "
      + "has been longer than that, the Method page lists what each part of the "
      + "pipeline does.",
    actions: [routeLink("/method", "Read how the pipeline works", "action")],
  });
}

// The bars grow once per visit; switching windows or modes redraws them in place.
let revealed = false;

/* ---------------- executive ---------------- */

async function execView(d) {
  const head = d.headline;
  const t = d.trends || {};
  const odds = d.odds || {};
  const conc = d.concentration || {};
  const goals = d.goals || [];
  const spikes = (d.activity || []).filter((r) => r.spike);
  const { node: mapNode } = await escalationMap(d.map.points, d.map.legend);

  const topNet = (conc.top || [])[0] || {};
  const gotIn = odds.shell_sessions || 0;
  const reveal = !revealed;
  revealed = true;

  return h("div", {}, [
    healthBanner(d.health),
    pagehead(head),

    panel("How far intruders get",
      "Every connection to the sensor, and how many made it past each step.",
      [funnelExec(d.rail, odds, { reveal }),
       trendLine([
         { label: "Connections", trend: t.connections },
         { label: "Working logins", trend: t.authenticated },
         { label: "Malware captured", trend: t.captured, alarmOn: "up" },
       ]),
       personaNote(t)]),

    panel("Where the traffic comes from",
      "Hollow points stopped at the password prompt and filled points got inside. A "
        + "location is where the infrastructure is hosted, not where its operator is.",
      [mapNode,
       takeaway([
         "Attack traffic is not evenly spread: ",
         { b: `${conc.top_share_pct || 0}% of it` },
         " came from ",
         { b: `${(conc.top || []).length} network operators` },
         topNet.org
           ? `, led by ${topNet.org}${topNet.country ? ` in ${topNet.country}` : ""} with `
             + `${topNet.ips === 1 ? "a single address" : `${num(topNet.ips)} addresses`}.`
           : ".",
       ])]),

    h("div", { class: "grid g2" }, [
      panel("What they tried to log into",
        "Guessed usernames and passwords, grouped by the kind of account they suggest.",
        [goals.length
          ? hbars(goals.map((g) => ({
              label: GOAL_NAMES[g.tag] || g.tag,
              value: g.attempts,
              display: `${g.share_pct}%`,
            })), { alarmFirst: true })
          : emptyState("No tagged login attempts in this window.", { widen: true }),
         goals.length ? takeaway([
           "The most common target was ",
           { b: (GOAL_NAMES[goals[0].tag] || goals[0].tag).toLowerCase() },
           ", which says more about what attackers hope to monetise than about the "
             + "server they think they have found.",
         ]) : null]),

      panel("Who sends the most",
        "Share of all recorded events by network operator.",
        [(conc.top || []).length
          ? hbars((conc.top || []).map((c) => ({
              label: c.org || c.asn,
              title: place(c.asn, c.country),
              value: c.events,
              display: `${c.share_pct}%`,
            })), { alarmFirst: true })
          : emptyState("No traffic recorded in this window.", { widen: true }),
         (conc.top || []).length ? takeaway([
           "For anyone running an exposed service, blocking a handful of networks would "
             + "remove most of this traffic.",
         ]) : null]),
    ]),

    panel("Volume over time",
      spikes.length
        ? `${spikes.length} unusual surge${spikes.length > 1 ? "s" : ""} in this window, each marked on the chart.`
        : "No day in this window broke its own baseline.",
      [activityChart(d.activity || [], (d.health && d.health.outages) || [],
                     (d.health && d.health.personas) || []),
       spikes.length
         ? h("ul", { class: "spikes" }, spikes.slice(-2).reverse().map((r) =>
             h("li", {}, [h("b", { text: `${r.day}: ` }), r.spike.headline])))
         : null,
       takeaway([
         "A swing in volume is usually one operator changing behaviour rather than a broad "
           + "shift, and the chart marks any day that breaks its own baseline.",
       ])]),

    panel("What this shows", null, [
      h("p", { class: "lede", text:
        `About ${num(gotIn)} of ${num(odds.connections || 0)} connections reached a working shell. `
        + "Automated pressure on an exposed service is constant and cheap, most of it fails at "
        + "the password prompt, and the small share that gets through moves straight to "
        + "installing something. Credential quality and how much is exposed decide which side "
        + "of that line a real server lands on." }),
    ]),
  ]);
}

/* ---------------- analyst ---------------- */

async function analystView(d) {
  const head = d.headline;
  const spikes = (d.activity || []).filter((r) => r.spike);
  const { node: mapNode, svg: mapSvg } = await escalationMap(d.map.points, d.map.legend);
  onStageChange((s) => applyFilter(mapSvg, s));

  return h("div", {}, [
    healthBanner(d.health),
    pagehead(head),
    stats([
      { label: "Events", value: num(head.events_total) },
      { label: "Unique sources", value: num(head.sources_total) },
      { label: "Events in the last 24 hours", value: num(head.events_last_day) },
      { label: "Samples captured", value: num(head.unique_samples) },
      { label: "Flagged malicious", value: num(head.flagged_samples), tone: "bad" },
      { label: "Submitted upstream", value: num(head.submitted_samples) },
    ]),
    personaNote(d.trends || {}),
    panel("Escalation",
      "Select a stage to filter the map and the table below it to sources that reached it.",
      [railFull(d.rail)]),
    panel("Where the escalation happens",
      "One point per source, at most 60, ranked by stage and then volume. A location is "
        + "where the infrastructure is hosted, not where its operator is.",
      [mapNode]),
    panel("Daily volume",
      spikes.length
        ? `${spikes.length} labelled surge${spikes.length > 1 ? "s" : ""}.`
        : "No day crossed the surge threshold.",
      [activityChart(d.activity || [], (d.health && d.health.outages) || [],
                     (d.health && d.health.personas) || []),
       spikes.length ? h("ul", { class: "spikes" }, spikes.slice(-3).reverse().map((r) =>
         h("li", {}, [h("b", { text: `${r.day}: ` }), r.spike.headline]))) : null]),
    panel("Sessions worth reading",
      "Ranked by what the session did, at most two per source.",
      [table(
        [{ label: "Source" }, { label: "Stage", sort: (r) => Number(r.stage || 0) },
         { label: "User" }, { label: "Commands", num: true }, { label: "Files", num: true },
         { label: "Relays", num: true }, { label: "Held", num: true }, { label: "Started" }],
        d.notable,
        (r) => [
          [ipLink(r.src_ip),
           h("div", { class: "sub2", text: place(r.org, r.country) })],
          stageTag(r.stage),
          h("span", { class: "mono", text: r.username || "-" }),
          num(r.commands), num((r.downloads || 0) + (r.uploads || 0)), num(r.tunnels),
          dur(r.duration),
          h("span", { class: "mono sub2", text: shortDate(r.first_seen) }),
        ],
        "No sessions recorded in this window.")]),
  ]);
}

/* ---------------- shared chart ----------------
   Built entirely with createElementNS. v3 assigned innerHTML on a <defs>
   node to draw the hatch pattern, which was the last raw markup assignment in
   the codebase and the one thing that made the no-markup rule a convention
   rather than a property of the helpers. */

function activityChart(rows, outages, personas) {
  if (!rows.length) {
    return emptyState("No daily activity in this window.", {
      hint: "The chart draws once the window holds at least one day of events.", widen: true,
    });
  }
  const W = 1100; const H = 150; const pad = 20;
  const max = Math.max(...rows.map((r) => r.events), 1);
  const step = (W - pad * 2) / Math.max(rows.length - 1, 1);
  const x = (i) => pad + i * step;
  const y = (v) => H - pad - (v / max) * (H - pad * 2);
  const el = svg("svg", {
    viewBox: `0 0 ${W} ${H}`, class: "spark chart", role: "img",
    "aria-label": `Daily event volume from ${rows[0].day} to ${rows[rows.length - 1].day}, peaking at ${num(max)}`,
  });

  const defs = svg("defs", {});
  const pat = svg("pattern", {
    id: "hatch", width: 6, height: 6,
    patternTransform: "rotate(45)", patternUnits: "userSpaceOnUse",
  });
  pat.appendChild(svg("rect", { width: 6, height: 6, fill: "var(--alert-tint)" }));
  pat.appendChild(svg("line", {
    x1: 0, y1: 0, x2: 0, y2: 6, stroke: "var(--alert-line)", "stroke-width": 2,
  }));
  defs.appendChild(pat);
  el.appendChild(defs);

  // Outage windows drawn as a labelled gap rather than quietly averaged in.
  const index = {};
  rows.forEach((r, i) => { index[r.day] = i; });
  (outages || []).forEach((o) => {
    const a = index[o.start]; const b = index[o.end];
    if (a === undefined && b === undefined) return;
    const x1 = x(a === undefined ? 0 : a);
    const x2 = x(b === undefined ? rows.length - 1 : b);
    el.appendChild(svg("rect", {
      class: "gap", x: x1, y: 4, width: Math.max(2, x2 - x1), height: H - pad - 4,
    }));
    const lab = svg("text", { x: (x1 + x2) / 2, y: 14, "text-anchor": "middle" });
    lab.textContent = "Sensor fault";
    el.appendChild(lab);
  });

  // Persona boundaries: the day the sensor started presenting a different
  // host. Either side of that line the numbers are not the same measure.
  (personas || []).forEach((p) => {
    const i = index[p.day];
    if (i === undefined) return;
    el.appendChild(svg("line", { class: "persona", x1: x(i), x2: x(i), y1: 4, y2: H - pad }));
    const t = svg("text", { class: "persona-label", x: x(i) + 3, y: H - pad - 4 });
    t.textContent = `Persona: ${p.name}`;
    el.appendChild(t);
  });

  const path = rows.map((r, i) =>
    `${i ? "L" : "M"}${x(i).toFixed(1)},${y(r.events).toFixed(1)}`).join("");
  el.appendChild(svg("path", {
    class: "area",
    d: `${path}L${x(rows.length - 1).toFixed(1)},${H - pad}L${x(0).toFixed(1)},${H - pad}Z`,
  }));
  el.appendChild(svg("path", { class: "ln", d: path }));

  rows.forEach((r, i) => {
    if (!r.spike) return;
    el.appendChild(svg("line", { class: "mark", x1: x(i), x2: x(i), y1: 18, y2: H - pad }));
    const t = svg("text", { x: x(i), y: 26, "text-anchor": "middle", fill: "var(--warn)" });
    t.textContent = r.day.slice(5);
    el.appendChild(t);
  });

  [[0, rows[0].day], [rows.length - 1, rows[rows.length - 1].day]].forEach(([i, day], k) => {
    const t = svg("text", { x: k ? W - pad : pad, y: H - 4, "text-anchor": k ? "end" : "start" });
    t.textContent = day;
    el.appendChild(t);
  });
  return el;
}

export async function render() {
  const d = await api(`/api/v1/overview${state.minStage ? `?min_stage=${state.minStage}` : ""}`);
  if (!d.headline || !Number(d.headline.events_total)) return firstRun();
  return isExec() ? execView(d) : analystView(d);
}
