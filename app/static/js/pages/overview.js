/* pages/overview.js v4 - two audiences, one dataset.
 *
 * Executive mode answers three questions in order: is the sensor working, is
 * risk moving, and what should I take away. Analyst mode keeps the dense
 * original. The marketing-sized hero is gone: a tool opens with numbers, and
 * the framing sentence sits beside them rather than above the fold on its own.
 */

import {
  api, h, num, panel, stats, table, shortDate, dur, state, isExec,
  stageTag, ipLink, signalCard, takeaway, hbars, svg, emptyState,
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
  return h("div", { class: "persona-note" }, [
    h("b", { text: "Not a like-for-like comparison. " }),
    h("span", { text: n.reason }),
  ]);
}

function healthBanner(hl) {
  const cls = hl.status === "fault" ? "fault" : hl.status === "warn" ? "warn" : "ok";
  const title = hl.status === "fault" ? "Sensor fault"
    : hl.status === "warn" ? "Data may be behind" : "Sensor healthy";
  return h("div", { class: `banner ${cls}` }, [
    h("div", {}, [
      h("b", { text: title }),
      h("p", { text: hl.message }),
      hl.status === "fault"
        ? h("p", { text: `Last successful authentication: ${hl.last_auth_day || "never"}. `
            + "Numbers below the first stage are frozen until this is fixed." })
        : null,
    ]),
  ]);
}

function pagehead(d) {
  const span = d.first_day && d.last_day ? `${d.first_day} to ${d.last_day}` : "";
  return h("div", { class: "pagehead" }, [
    h("h2", { text: "What actually happens to a server left on the public internet." }),
    h("p", { text:
      "A decoy machine, deliberately exposed, dressed up as a working server that is "
      + "worth breaking into. Nothing real runs on it. Everything that touches it is uninvited, "
      + "and every attempt is recorded." }),
    h("p", { class: "sub2", text:
      `${num(d.events_total)} recorded attempts from ${num(d.sources_total)} separate machines `
      + `in ${d.countries} countries, ${span}.` }),
  ]);
}

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

  return h("div", {}, [
    healthBanner(d.health || { status: "ok", message: "" }),
    pagehead(head),

    h("div", { class: "signals" }, [
      signalCard({
        label: "Attempts to break in",
        value: num(t.connections && t.connections.current),
        trend: t.connections,
        note: "Every connection from a machine that was not invited.",
      }),
      signalCard({
        label: "Got past the password",
        value: num(t.authenticated && t.authenticated.current),
        trend: t.authenticated,
        note: "Guessed a working login on a decoy that accepts known-bad credentials.",
      }),
      signalCard({
        label: "Left malware behind",
        value: num(head.unique_samples),
        trend: t.captured,
        alarmOn: "up",
        note: `${num(head.flagged_samples)} confirmed malicious by external analysis.`,
      }),
    ]),

    personaNote(t),

    panel("How far intruders actually get",
      "Every connection to this machine, and what fraction of them survives each step.",
      [funnelExec(d.rail, odds)]),

    panel("Where the pressure comes from",
      "Hollow points stopped at the password prompt. Filled points got inside.",
      [mapNode,
       takeaway([
         "Attack traffic is not evenly spread. ",
         { b: `${conc.top_share_pct || 0}% of everything` },
         " came from just ",
         { b: `${(conc.top || []).length} network operators` },
         topNet.org
           ? `, led by ${topNet.org}${topNet.country ? ` in ${topNet.country}` : ""} with `
             + `${topNet.ips === 1 ? "a single machine" : `${num(topNet.ips)} machines`}.`
           : ".",
       ])]),

    h("div", { class: "grid g2" }, [
      panel("What they were trying to log into",
        "Guessed usernames and passwords, grouped by what they were after.",
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
           ", not system administration. Attackers go where the money is.",
         ]) : null]),

      panel("Concentration of attack traffic",
        "Share of all recorded attempts by network operator.",
        [(conc.top || []).length
          ? hbars((conc.top || []).map((c) => ({
              label: c.org || c.asn,
              title: `${c.asn} \u00b7 ${c.country || ""}`,
              value: c.events,
              display: `${c.share_pct}%`,
            })), { alarmFirst: true })
          : emptyState("No traffic recorded in this window.", { widen: true }),
         (conc.top || []).length ? takeaway([
           "Blocking a small number of networks would remove most of this traffic. ",
           "That is the practical takeaway for anyone running an exposed service.",
         ]) : null]),
    ]),

    panel("Attack volume over time",
      spikes.length
        ? `${spikes.length} unusual surge${spikes.length > 1 ? "s" : ""} detected and explained.`
        : "No unusual surge in this period.",
      [activityChart(d.activity || [], (d.health && d.health.outages) || [],
                     (d.health && d.health.personas) || []),
       spikes.length
         ? h("div", { style: "margin-top:12px" }, spikes.slice(-2).reverse().map((r) =>
             h("p", { class: "sub2", style: "margin:0 0 6px" }, [
               h("b", { text: `${r.day}: ` }), r.spike.headline])))
         : null,
       takeaway([
         "Volume swings are usually one operator changing behaviour rather than a broad shift. ",
         "The graph is annotated automatically when a day breaks its own baseline.",
       ])]),

    panel("What this demonstrates", null, [
      h("p", { class: "lede", style: "margin:0", text:
        `Roughly ${num(gotIn)} of ${num(odds.connections || 0)} connection attempts reached a working shell. `
        + "Cheap, automated pressure is constant, most of it fails against a password prompt, "
        + "and the small fraction that succeeds moves immediately to installing something. "
        + "Credential quality and exposure control are what separate the two outcomes." }),
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
    healthBanner(d.health || { status: "ok", message: "" }),
    pagehead(head),
    personaNote(d.trends || {}),
    stats([
      { label: "events", value: num(head.events_total) },
      { label: "unique sources", value: num(head.sources_total) },
      { label: "last 24h", value: num(head.events_last_day), tone: "accent" },
      { label: "samples captured", value: num(head.unique_samples) },
      { label: "flagged malicious", value: num(head.flagged_samples), tone: "bad" },
      { label: "submitted upstream", value: num(head.submitted_samples) },
    ]),
    panel("Escalation",
      "Click a stage to filter the map and the tables below it.",
      [railFull(d.rail)]),
    panel("Where the escalation happens",
      "One point per source, capped at 60, ranked by stage then volume.",
      [mapNode]),
    panel("Daily volume",
      spikes.length ? `${spikes.length} labelled surge(s).` : "No surge crossed the threshold.",
      [activityChart(d.activity || [], (d.health && d.health.outages) || [],
                     (d.health && d.health.personas) || []),
       spikes.length ? h("div", { style: "margin-top:12px" }, spikes.slice(-3).reverse().map((r) =>
         h("p", { class: "sub2", style: "margin:0 0 6px" }, [
           h("b", { class: "mono", text: `${r.day} ` }), r.spike.headline]))) : null]),
    panel("Sessions worth reading",
      "Ranked by what the session did, capped at two per source.",
      [table(
        [{ label: "source" }, { label: "stage", sort: (r) => Number(r.stage || 0) },
         { label: "user" }, { label: "cmds", num: true }, { label: "files", num: true },
         { label: "tunnels", num: true }, { label: "held", num: true }, { label: "started" }],
        d.notable,
        (r) => [
          [ipLink(r.src_ip),
           h("div", { class: "sub2", text: [r.org, r.country].filter(Boolean).join(" \u00b7 ") })],
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
  if (!rows.length) return emptyState("No activity recorded yet.", { widen: true });
  const W = 1100; const H = 150; const pad = 20;
  const max = Math.max(...rows.map((r) => r.events), 1);
  const step = (W - pad * 2) / Math.max(rows.length - 1, 1);
  const x = (i) => pad + i * step;
  const y = (v) => H - pad - (v / max) * (H - pad * 2);
  const el = svg("svg", {
    viewBox: `0 0 ${W} ${H}`, class: "spark chart", role: "img",
    "aria-label": `daily event volume, peak ${max}`,
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
    lab.textContent = "sensor fault";
    el.appendChild(lab);
  });

  // Persona boundaries: the day the sensor started presenting a different
  // host. Either side of that line the numbers are not the same measure.
  (personas || []).forEach((p) => {
    const i = index[p.day];
    if (i === undefined) return;
    el.appendChild(svg("line", { class: "persona", x1: x(i), x2: x(i), y1: 4, y2: H - pad }));
    const t = svg("text", { class: "persona-label", x: x(i) + 3, y: H - pad - 4 });
    t.textContent = `persona: ${p.name}`;
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
  return isExec() ? execView(d) : analystView(d);
}
