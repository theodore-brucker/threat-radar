/* map.js - the escalation map.
 *
 * Replaces the old 500-cluster red bubble field. One point per source, capped
 * at 60, ranked by how far the source got rather than by volume. Colour is the
 * escalation stage, size is session count. Most of the map is dim slate; the
 * handful of amber and red points are the story.
 */

import { h, num, state, isExec, url, STAGE_COLORS, STAGE_LABELS } from "./core.js";

const W = 720, H = 360;
let worldCache = null;

const project = (lon, lat) => [((Number(lon) + 180) / 360) * W, ((90 - Number(lat)) / 180) * H];

async function world() {
  if (worldCache) return worldCache;
  try {
    const res = await fetch(url("/static/vendor/world.json"));
    worldCache = res.ok ? await res.json() : { rings: [] };
  } catch { worldCache = { rings: [] }; }
  return worldCache;
}

function svgEl(tag, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}

export async function escalationMap(points, legend) {
  const wrap = h("div", { class: "mapwrap" });
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, role: "img",
    "aria-label": "attack sources by escalation stage" });

  for (let lon = -150; lon <= 150; lon += 30) {
    const [x] = project(lon, 0);
    svg.appendChild(svgEl("line", { class: "grat", x1: x, y1: 0, x2: x, y2: H }));
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const [, y] = project(0, lat);
    svg.appendChild(svgEl("line", { class: "grat", x1: 0, y1: y, x2: W, y2: y }));
  }

  const land = svgEl("g", {});
  const { rings } = await world();
  for (const ring of rings) {
    const d = ring.map((c, i) => {
      const [x, y] = project(c[0], c[1]);
      return `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
    }).join("") + "Z";
    land.appendChild(svgEl("path", { class: "land", d }));
  }
  svg.appendChild(land);

  const tip = h("div", { class: "maptip" });
  const maxSessions = Math.max(1, ...points.map((p) => p.sessions || 1));
  const layer = svgEl("g", {});

  // Lower stages first, so the dangerous points draw on top of the noise.
  [...points].sort((a, b) => (a.stage || 0) - (b.stage || 0)).forEach((p) => {
    const [x, y] = project(p.lon, p.lat);
    const stage = Math.min(Number(p.stage || 0), 4);
    const color = `var(${STAGE_COLORS[stage]})`;
    const r = 1.8 + Math.sqrt((p.sessions || 1) / maxSessions) * (stage >= 3 ? 7 : 5);
    const g = svgEl("g", { class: "pt", "data-stage": String(stage) });
    g.appendChild(svgEl("circle", { class: "halo", cx: x, cy: y, r: r * 2.4, fill: color }));
    if (stage <= 1) {
      // hollow: readable in greyscale and for a colour-blind reader
      g.appendChild(svgEl("circle", {
        class: "core", cx: x, cy: y, r, fill: "none",
        stroke: color, "stroke-width": 1.6,
      }));
    } else {
      g.appendChild(svgEl("circle", { class: "core", cx: x, cy: y, r, fill: color }));
      if (stage >= 4) {
        g.appendChild(svgEl("circle", {
          class: "ring", cx: x, cy: y, r: r + 2.6, fill: "none",
          stroke: color, "stroke-width": 1, "stroke-dasharray": "2 2",
        }));
      }
    }
    g.addEventListener("mousemove", (e) => {
      const rect = wrap.getBoundingClientRect();
      tip.replaceChildren(
        h("div", { class: "mono", text: p.src_ip }),
        h("div", { style: `color:var(${STAGE_COLORS[stage]})`,
                   text: `stage ${stage} \u00b7 ${STAGE_LABELS[stage]}` }),
        h("div", { text: `${num(p.sessions)} sessions · ${num(p.events)} events` }),
        h("div", { text: [p.org, p.country].filter(Boolean).join(" · ") || "unattributed" }),
        p.transfers ? h("div", { text: `${num(p.transfers)} file transfers` }) : null,
      );
      tip.style.left = `${Math.min(e.clientX - rect.left + 14, rect.width - 270)}px`;
      tip.style.top = `${e.clientY - rect.top + 14}px`;
      tip.style.opacity = "1";
    });
    g.addEventListener("mouseleave", () => { tip.style.opacity = "0"; });
    layer.appendChild(g);
  });
  svg.appendChild(layer);

  const counts = {};
  (legend || []).forEach((l) => { counts[l.stage] = l.sources; });

  // Executive mode: two entries, because five is a legend to memorise.
  const entries = isExec()
    ? [
        { color: "--stage-0", label: "stopped at the door", hollow: true,
          n: (counts[0] || 0) + (counts[1] || 0) },
        { color: "--stage-4", label: "got inside",
          n: (counts[2] || 0) + (counts[3] || 0) + (counts[4] || 0) },
      ]
    : STAGE_LABELS.map((label, i) => ({
        color: STAGE_COLORS[i], label: `${i} ${label}`, hollow: i <= 1, n: counts[i] || 0 }));

  const legendEl = h("div", { class: "legend" }, entries.map((e) =>
    h("span", {}, [
      h("span", { class: `sw${e.hollow ? " hollow" : ""}`,
                  style: `--stage:var(${e.color});background:var(${e.color})` }),
      h("b", { text: num(e.n) }),
      ` ${e.label}`,
    ])).concat([
      h("span", { style: "margin-left:auto",
        text: `${points.length} of the busiest sources shown` }),
    ]));

  wrap.append(svg, tip);
  applyFilter(svg, state.minStage);
  return { node: h("div", {}, [wrap, legendEl]), svg };
}

export function applyFilter(svg, minStage) {
  svg.querySelectorAll(".pt").forEach((g) => {
    const s = Number(g.dataset.stage || 0);
    g.classList.toggle("faded", s < Number(minStage || 0));
  });
}
