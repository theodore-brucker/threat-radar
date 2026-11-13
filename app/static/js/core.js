/* core.js v4 - shared plumbing.
 *
 * Two rules hold everywhere in this file and in every module that imports it.
 *
 * 1. Every value that came from an attacker reaches the DOM through
 *    textContent. h() no longer accepts an `html` key at all, so the rule is
 *    now a property of the helper rather than a convention the author has to
 *    remember. Trusted SVG is built with createElementNS instead.
 * 2. Nothing reads by colour alone. Stage is a numeral plus a word, filled or
 *    outlined by whether the source got inside.
 */

import { icon } from "./icons.js";

export { icon };

/* ---------- mount point --------------------------------------------------
   The site can be served at / or under a prefix such as /radar. The prefix is
   taken from this module's own URL, so it is correct without a build step and
   without trusting a <base> element. */

export const BASE = (() => {
  const m = /^(.*)\/static\/js\/core\.js(?:\?.*)?$/.exec(new URL(import.meta.url).pathname);
  return m ? m[1] : "";
})();

export const url = (p) => `${BASE}${p}`;

const raf = (fn) =>
  (window.requestAnimationFrame ? window.requestAnimationFrame(fn) : setTimeout(fn, 0));

/* Strip the prefix off location.pathname to get an app route. */
export function currentPath() {
  let p = location.pathname;
  if (BASE && p.startsWith(BASE)) p = p.slice(BASE.length);
  p = p.replace(/\/+$/, "");
  return p || "/";
}

/* ---------- constants ---------- */

export const STAGE_COLORS = ["--stage-0", "--stage-1", "--stage-2", "--stage-3", "--stage-4"];
export const STAGE_LABELS = [
  "connected only", "authenticated", "reached a shell",
  "moved a file", "flagged malware",
];
export const ALL_TIME = 3650;

export const state = {
  days: Number(localStorage.getItem("tr.days") || 30),
  minStage: 0,
  // exec is the default: a first-time visitor is far more likely to be a
  // hiring manager than an analyst.
  mode: localStorage.getItem("tr.mode") || "exec",
  density: localStorage.getItem("tr.density") || "compact",
};

export function setMode(m) {
  state.mode = m;
  localStorage.setItem("tr.mode", m);
  document.body.dataset.mode = m;
}
export const isExec = () => state.mode === "exec";

export function setDays(d) {
  state.days = d;
  localStorage.setItem("tr.days", String(d));
}

export function setDensity(d) {
  state.density = d;
  localStorage.setItem("tr.density", d);
  document.body.dataset.density = d;
  paintDensity();
  if (document.getElementById("view")) raf(() => fitTables());
}

/* ---------- plain language ---------- */

export const PLAIN = {
  ASN: "network operator",
  asn: "network operator",
  hassh: "attack tool signature",
  JA4H: "web client signature",
  "direct-tcpip": "attempts to relay traffic through us",
  payload: "malware file",
  shasum: "file fingerprint",
  sha256: "file fingerprint",
  session: "connection",
  src_ip: "attacker address",
  campaign: "guessing pattern",
  escalation: "how far they got",
  tunnel: "relay attempt",
  fingerprint: "tool signature",
};

export function term(technical, plainText) {
  const plain = plainText || PLAIN[technical] || technical;
  if (!isExec()) return h("span", { text: technical });
  return h("span", { class: "term", title: `technical term: ${technical}`, text: plain });
}

/* ---------- api ---------- */

const cache = new Map();

export function windowLabel() {
  if (state.days >= ALL_TIME) return "all time";
  if (state.days === 1) return "the last 24 hours";
  return `the last ${state.days} days`;
}

/* An API failure that knows what kind of failure it was, so a page can say
   "nothing recorded for this address" for a 404 and "the server could not
   build this view" for a 500, instead of printing the status line. status is
   0 when the request never got an answer at all. */
export class ApiError extends Error {
  constructor(status, path, detail) {
    super(detail || (status ? `HTTP ${status}` : "no response"));
    this.name = "ApiError";
    this.status = status;
    this.path = path;
    this.detail = detail || "";
  }
  get notFound() { return this.status === 404; }
}

export async function api(path, { fresh = false } = {}) {
  const rel = path.includes("?") ? `${path}&days=${state.days}` : `${path}?days=${state.days}`;
  if (!fresh && cache.has(rel)) return cache.get(rel);
  let res;
  try {
    res = await fetch(url(rel), { headers: { Accept: "application/json" } });
  } catch (err) {
    throw new ApiError(0, path, "The request did not reach the server.");
  }
  if (!res.ok) {
    let detail = "";
    try { const b = await res.json(); detail = b && typeof b.detail === "string" ? b.detail : ""; }
    catch (err) { /* not JSON: the status is all there is */ }
    throw new ApiError(res.status, path, detail);
  }
  let body;
  try { body = await res.json(); }
  catch (err) { throw new ApiError(res.status, path, "The server answered with something that is not JSON."); }
  const data = body && body.data !== undefined ? body.data : body;
  cache.set(rel, data);
  return data;
}

export function clearCache() { cache.clear(); }

/* ---------- format ---------- */

export const num = (n) =>
  n === null || n === undefined || n === "" ? "-" : Number(n).toLocaleString();

export const pct = (n, digits = 1) =>
  n === null || n === undefined ? "-" : `${Number(n).toFixed(digits)}%`;

export function shortDate(s) {
  if (!s) return "-";
  return String(s).slice(0, 16).replace("T", " ");
}

export function mid(s, head = 10, tail = 6) {
  s = String(s || "");
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}\u2026${s.slice(-tail)}`;
}

export function dur(sec) {
  if (sec === null || sec === undefined) return "-";
  const s = Number(sec);
  if (s < 60) return `${s.toFixed(1)}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

export function bytes(n) {
  if (n === null || n === undefined || n === "") return "-";
  const b = Number(n);
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

/* "Hetzner Online GmbH, DE". Commas rather than a dot leader, and nothing at
   all when neither half is known. */
export function place(...parts) {
  return parts.filter(Boolean).join(", ");
}

/* ---------- dom ---------- */

/* Attributes that navigate or load. Every value the app sets is a relative
   route, a fragment, or an https link to a public service, so anything else
   is refused rather than trusted: no javascript:, no data:, and no
   protocol-relative //host that would inherit the page's scheme. Today no
   attacker-controlled string reaches these, and this keeps it that way. */
const URL_ATTRS = new Set(["href", "src", "action", "formaction", "xlink:href"]);
function safeUrl(v) {
  const s = String(v).trim();
  return (s.startsWith("/") && !s.startsWith("//")) || s.startsWith("#")
    || s.startsWith("?") || /^https:\/\//i.test(s);
}

export function h(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    const key = k.toLowerCase();
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (key.startsWith("on")) {
      // Handlers are attached as functions only; a string would be inline
      // script, which the content security policy blocks anyway.
      if (typeof v === "function") el.addEventListener(k.slice(2), v);
    }
    else if (URL_ATTRS.has(key) && !safeUrl(v)) continue;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of [].concat(children)) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === "string" || typeof c === "number"
      ? document.createTextNode(String(c)) : c);
  }
  return el;
}

export function svg(tag, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined) continue;
    el.setAttribute(k, v);
  }
  return el;
}

/* ---------- clipboard ----------------------------------------------------
   navigator.clipboard is undefined outside a secure context, and this site is
   served over plain HTTP on the LAN. Calling it there threw before it could
   reject, so every copy button did nothing and said nothing. The fallback is
   the old selection trick, which still works on http origins. */

export function copyText(value) {
  const text = String(value);
  if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:-1000px;left:0;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, text.length);
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
    document.body.removeChild(ta);
    if (ok) resolve(); else reject(new Error("copy blocked"));
  });
}

/* A copy button names the action, then confirms it with the same verb:
   "Copy" becomes "Copied" with a tick, and a refusal says what to do. */
function setLabel(btn, name, text) {
  btn.replaceChildren(icon(name), document.createTextNode(text));
}

function wireCopy(btn, getText, restore) {
  setLabel(btn, "copy", restore);
  btn.addEventListener("click", () => {
    copyText(getText()).then(() => {
      setLabel(btn, "check", "Copied");
      btn.setAttribute("data-done", "");
      setTimeout(() => { setLabel(btn, "copy", restore); btn.removeAttribute("data-done"); }, 1400);
    }).catch(() => {
      setLabel(btn, "triangle-alert", "Clipboard blocked");
      btn.title = "The browser refused the clipboard on this connection. Select the "
        + "text and copy it by hand, or open the site over https.";
      setTimeout(() => { setLabel(btn, "copy", restore); }, 2600);
    });
  });
  return btn;
}

/* ---------- panels ----------
   A panel does not restate the window: the topbar already shows it. v3 stamped
   a "last N days" chip into every subtitle, which made each heading three
   lines tall for no new information.

   4.0 replaced that with a "lifetime" chip keyed off `scoped: false`, which
   was wrong. Several callers passed that flag to mean "do not show a window
   chip" rather than "this data is lifetime scoped", so a single session
   timeline came out labelled LIFETIME. The panels whose data really does
   ignore the window already say so in their subtitle, which is the honest
   place for it. The option is still accepted and now does nothing. */

export function panel(title, sub, body, _opts) {
  return h("section", { class: "panel" }, [
    title ? h("div", { class: "phead" }, [h("h2", { text: title })]) : null,
    sub ? h("p", { class: "sub", text: sub }) : null,
  ].concat([].concat(body)));
}

export function stats(items) {
  return h("div", { class: "stats" }, items.map((i) =>
    h("div", { class: "stat" }, [
      h("div", { class: `n ${i.tone === "bad" ? "bad" : ""}`.trim(), text: i.value }),
      h("div", { class: "k", text: i.label }),
    ])));
}

export function tag(text, tone) {
  return h("span", { class: `tag ${tone || ""}`.trim(), text });
}

export function bar(pctWidth) {
  return h("div", { class: "bar" }, [
    h("i", { style: `width:${Math.max(0, Math.min(100, pctWidth || 0))}%` }),
  ]);
}

/* Stage as a numeral, a fill state and a word. Three cues, no reliance on
   colour, and the numeral is what you scan in a sorted column. */
export function stageTag(stage, { short = false } = {}) {
  const s = Math.max(0, Math.min(4, Number(stage || 0)));
  return h("span", {
    class: `stage${short ? " short" : ""}`,
    "data-stage": String(s),
    style: `--stage:var(${STAGE_COLORS[s]})`,
    title: `stage ${s}: ${STAGE_LABELS[s]}`,
  }, [
    h("i", { text: String(s) }),
    h("span", { text: STAGE_LABELS[s] }),
  ]);
}

/* ---------- empty, error and not-found states --------------------------
   One shape for all three: a sentence saying what happened, a sentence
   saying why or what it means, and the action that fixes it. An empty view
   whose cause is the window selector offers to widen it. */

function stateBox(cls, iconName, title, text, actions) {
  return h("div", { class: `state ${cls}`.trim(), role: cls.includes("error") ? "alert" : null }, [
    iconName ? icon(iconName, { size: cls.includes("page") ? 28 : 18 }) : null,
    h("div", {}, [
      h("b", { text: title }),
      text ? h("p", { text }) : null,
      actions && actions.length ? h("div", { class: "actions" }, actions) : null,
    ]),
  ]);
}

export function widenButton() {
  if (state.days >= ALL_TIME) return null;
  const next = state.days < 7 ? 7 : state.days < 30 ? 30 : ALL_TIME;
  return h("button", {
    type: "button",
    text: next >= ALL_TIME ? "Show all time" : `Show the last ${next} days`,
    onclick: () => {
      setDays(next);
      const sel = document.getElementById("window-select");
      if (sel) sel.value = String(next);
      clearCache();
      render();
    },
  });
}

export function emptyState(message, { hint, widen, plain } = {}) {
  return stateBox(plain ? "plain" : "", null, message, hint,
    [widen ? widenButton() : null].filter(Boolean));
}

/* What went wrong, in the reader's terms, with the raw status kept as a
   detail line for whoever has to fix it. */
export function describeError(err) {
  const s = err && err.status !== undefined ? err.status : -1;
  if (s === 0) {
    return ["Threat Radar is not answering.",
      "The page could not reach its server. Check your connection, or try again "
      + "in a minute if the server is restarting."];
  }
  if (s === 404) {
    return ["Nothing is recorded here.", "The server has no data at this address."];
  }
  if (s === 400) {
    return ["That value is not one this view understands.",
      err.detail ? `The server said: ${err.detail}.` : "Check the address and try again."];
  }
  if (s === 503) {
    return ["The database is not available right now.",
      "It is usually being rebuilt or pruned, which takes a few minutes. Try again shortly."];
  }
  if (s >= 500) {
    return ["The server hit an error building this view.",
      "Trying again often works. If it keeps happening, the web service log on the "
      + "server will have the cause."];
  }
  return ["This view could not be loaded.",
    "Something in the page failed before it could draw. Reloading usually clears it."];
}

export function errorState(err, { retry = () => { clearCache(); render(); } } = {}) {
  const [title, text] = describeError(err);
  const box = stateBox("error", "triangle-alert", title, text, [
    h("button", { type: "button", onclick: retry }, [icon("refresh-cw"), "Try again"]),
  ]);
  const detail = err && err.path !== undefined
    ? `${err.status ? `HTTP ${err.status}` : "No response"} from ${err.path}`
      + `${err.detail ? `: ${err.detail}` : ""}`
    : String((err && err.message) || err || "");
  box.querySelector("div").appendChild(h("p", { class: "detail", text: detail }));
  return box;
}

/* A full-page state, used for 404 and for an entity nobody has seen. */
export function pageState({ iconName = "compass", title, text, actions = [] }) {
  return stateBox("page", iconName, title, text, actions);
}

/* ---------- tables ------------------------------------------------------
   One component behind every table on the site. Sticky header under the
   topbar, page scroll rather than an inner scroll box, sortable columns, a
   visible row count, keyboard row navigation with j and k, and a copy that
   puts the visible rows on the clipboard as TSV.

   cols:   [{label, num, cls, sort}]  sort is an optional (row) => value
   render: (row) => array of cell contents (string | Node | array)
*/

function cellText(td) {
  return (td.textContent || "").trim();
}

export function dataTable({ cols, rows, render: renderRow, empty, limit = 50, label }) {
  if (!rows || !rows.length) {
    return typeof empty === "string" || empty === undefined
      ? emptyState(empty || "Nothing in this window.", { widen: true })
      : empty;
  }

  const thead = h("thead", {});
  const headRow = h("tr", {});
  const tbody = h("tbody", {});
  const records = [];

  rows.forEach((row) => {
    const cells = renderRow(row);
    const tr = h("tr", { tabindex: "-1" });
    cells.forEach((cell, i) => {
      const col = cols[i] || {};
      const td = h("td", { class: [col.num ? "num" : "", col.cls || ""].join(" ").trim() || null });
      for (const part of [].concat(cell)) {
        if (part === null || part === undefined) continue;
        td.appendChild(typeof part === "object" ? part : document.createTextNode(String(part)));
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
    records.push({ row, tr });
  });

  let sortCol = -1;
  let sortDir = 1;

  const sortBy = (i) => {
    const col = cols[i];
    if (sortCol === i) sortDir = -sortDir;
    else { sortCol = i; sortDir = col.num ? -1 : 1; }

    const key = (rec) => {
      if (typeof col.sort === "function") return col.sort(rec.row);
      const t = cellText(rec.tr.children[i]);
      if (col.num) {
        const n = parseFloat(t.replace(/[^0-9.eE+-]/g, ""));
        return Number.isFinite(n) ? n : -Infinity;
      }
      return t.toLowerCase();
    };

    records.sort((a, b) => {
      const ka = key(a); const kb = key(b);
      if (ka < kb) return -sortDir;
      if (ka > kb) return sortDir;
      return 0;
    });
    records.forEach((r) => tbody.appendChild(r.tr));
    [...headRow.children].forEach((th, j) => {
      if (j === i) th.setAttribute("aria-sort", sortDir === 1 ? "ascending" : "descending");
      else th.removeAttribute("aria-sort");
      const mark = th.querySelector(".sortmark");
      if (mark) mark.replaceChildren(icon(j === i ? (sortDir === 1 ? "chevron-up" : "chevron-down") : "chevrons-up-down", { size: 14 }));
    });
    applyLimit();
  };

  cols.forEach((c, i) => {
    const th = h("th", {
      class: [c.num ? "num" : "", "sortable"].join(" ").trim(),
      scope: "col",
      tabindex: "0",
      title: `Sort by ${c.label}`,
      onclick: () => sortBy(i),
      onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sortBy(i); } },
    }, [
      h("span", { text: c.label }),
      h("span", { class: "sortmark" }, [icon("chevrons-up-down", { size: 14 })]),
    ]);
    headRow.appendChild(th);
  });
  thead.appendChild(headRow);

  /* Long result sets render in full but only show the first page, so the
     page stays a sane length while sort and find-in-page still see
     everything once expanded. */
  let showAll = records.length <= limit;
  const countEl = h("span", { class: "tbl-count" });
  const moreBtn = h("button", {
    type: "button", class: "quiet",
    text: `Show all ${num(records.length)}`,
    onclick: () => { showAll = true; moreBtn.hidden = true; applyLimit(); fitTables(); },
  });
  moreBtn.hidden = showAll;

  function applyLimit() {
    records.forEach((r, i) => { r.tr.hidden = !showAll && i >= limit; });
    const shown = showAll ? records.length : Math.min(limit, records.length);
    countEl.textContent = shown === records.length
      ? `${num(records.length)} row${records.length === 1 ? "" : "s"}`
      : `Showing ${num(shown)} of ${num(records.length)}`;
    const first = records.find((r) => !r.tr.hidden);
    records.forEach((r) => r.tr.setAttribute("tabindex", "-1"));
    if (first) first.tr.setAttribute("tabindex", "0");
  }

  const copyBtnEl = wireCopy(
    h("button", { type: "button", class: "quiet", title: "Copy the visible rows as tab-separated text" }),
    () => {
      const head = cols.map((c) => c.label).join("\t");
      const rowsOut = records.filter((r) => !r.tr.hidden)
        .map((r) => [...r.tr.children].map(cellText).join("\t")).join("\n");
      return `${head}\n${rowsOut}`;
    },
    "Copy rows");

  const table = h("table", { "aria-label": label || undefined }, [thead, tbody]);
  const wrap = h("div", { class: "tbl-wrap" }, [table]);

  /* j and k move a row cursor once the table has focus; Enter follows the
     first link in the focused row. Scoped to the table so it never fights
     with typing elsewhere on the page. */
  tbody.addEventListener("keydown", (e) => {
    const cur = e.target.closest("tr");
    if (!cur) return;
    if (e.key === "j" || e.key === "k" || e.key === "ArrowDown" || e.key === "ArrowUp") {
      const down = e.key === "j" || e.key === "ArrowDown";
      const visible = records.filter((r) => !r.tr.hidden).map((r) => r.tr);
      const i = visible.indexOf(cur);
      const next = visible[i + (down ? 1 : -1)];
      if (next) { e.preventDefault(); next.focus(); next.scrollIntoView({ block: "nearest" }); }
      return;
    }
    if (e.key === "Enter") {
      const link = cur.querySelector("a[href]");
      if (link) { e.preventDefault(); link.click(); }
    }
  });

  applyLimit();

  return h("div", { class: "tbl" }, [
    h("div", { class: "tbl-bar" }, [
      countEl,
      h("span", { class: "spacer" }),
      moreBtn,
      copyBtnEl,
    ]),
    wrap,
  ]);
}

/* Back-compatible signature used by every page module. */
export function table(cols, rows, renderRow, emptyText) {
  return dataTable({ cols, rows, render: renderRow, empty: emptyText });
}

/* ---------- headline numbers ---------- */

/* Direction is neutral unless the caller says which direction is bad. More
   scanning traffic against a honeypot is weather, not an incident. */
/* "Connections 12% above the prior period", with a trend icon. Direction is
   neutral unless the caller names the direction that is bad. */
export function trendEl(label, t, { alarmOn } = {}) {
  if (!t || t.change_pct === null || t.change_pct === undefined) {
    return h("li", { class: "trend" }, [
      icon("minus", { size: 14 }), h("b", { text: label }), "no earlier period to compare",
    ]);
  }
  const name = t.direction === "up" ? "trending-up" : t.direction === "down" ? "trending-down" : "minus";
  const word = t.direction === "flat"
    ? "level with the prior period"
    : `${Math.abs(t.change_pct)}% ${t.direction === "up" ? "above" : "below"} the prior period`;
  const tone = alarmOn && t.direction === alarmOn ? " alarm" : "";
  return h("li", { class: `trend${tone}` }, [icon(name, { size: 14 }), h("b", { text: label }), word]);
}

export function trendLine(items) {
  return h("ul", { class: "trendline", "aria-label": "Change against the prior period" },
    items.map((it) => trendEl(it.label, it.trend, { alarmOn: it.alarmOn })));
}

export function takeaway(parts) {
  return h("p", { class: "takeaway" }, [].concat(parts).map((p) =>
    typeof p === "string" ? document.createTextNode(p)
      : p.alarm ? h("span", { class: "alarm", text: p.alarm })
      : h("b", { text: p.b })));
}

export function hbars(rows, { alarmFirst = false } = {}) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return h("div", { class: "hbars" }, rows.map((r, i) =>
    h("div", { class: "hbar" }, [
      h("div", { class: "t", title: r.title || r.label, text: r.label }),
      h("div", { class: "track" }, [
        h("div", {
          class: `fill${alarmFirst && i === 0 ? " alarm" : ""}`,
          style: `width:${(r.value / max) * 100}%`,
        }),
      ]),
      h("div", { class: "v", text: r.display || num(r.value) }),
    ])));
}

/* A funnel is a sequence of narrowing counts. Counts sit outside the fill,
   because in light mode no stage colour carries white text at 4.5:1. */
export function funnel(steps, { reveal = false } = {}) {
  const top = Math.max(1, steps[0] ? steps[0].value : 1);
  return h("div", { class: `funnel${reveal ? " reveal" : ""}` }, steps.map((s, i) => {
    const prev = i === 0 ? null : steps[i - 1].value;
    const share = prev ? (prev === 0 ? 0 : (s.value / prev) * 100) : null;
    return h("div", { class: "funnel-step", style: `--stage:var(${s.color || "--mark"});--i:${i}` }, [
      h("div", { class: "fl" }, s.sub
        ? [h("b", { text: s.label }), h("span", { text: s.sub })]
        : [h("b", { text: s.label })]),
      h("div", { class: "track" }, [
        h("div", { class: "fill", style: `width:${(s.value / top) * 100}%` }),
      ]),
      h("div", { class: "fv", text: num(s.value) }),
      h("div", {
        class: "fs",
        text: share === null ? (s.baseLabel || "of all captures")
          : `${share.toFixed(share < 10 ? 1 : 0)}% of previous`,
      }),
    ]);
  }));
}

/* ---------- attacker-supplied command text ------------------------------
   Horizontal scroll, never break-all. v3 broke a command carrying sixty IP
   addresses across eight lines at arbitrary characters, which destroyed both
   reading and copying. */

export function cmdBlock(text, { clampLines = true } = {}) {
  const value = String(text || "");
  const long = value.length > 400 || value.split("\n").length > 6;
  const pre = h("pre", { class: `cmd${long && clampLines ? " clamped" : ""}` },
    [h("code", { text: value })]);
  const bits = [pre];
  if (long || value.length > 120) {
    const expand = long && clampLines
      ? h("button", {
          type: "button", class: "quiet", text: "Show all",
          "aria-expanded": "false",
          onclick: (e) => {
            const on = pre.classList.toggle("clamped");
            e.currentTarget.textContent = on ? "Show all" : "Show less";
            e.currentTarget.setAttribute("aria-expanded", String(!on));
          },
        })
      : null;
    bits.push(h("div", { class: "cmdbar" }, [
      expand,
      copyBtn(value),
      h("span", { class: "len", text: `${num(value.length)} characters` }),
    ]));
  }
  return h("div", {}, bits);
}

/* ---------- entities ----------
   Every indicator on the site is an entity with one canonical page. Labels
   stay textContent; nothing here relaxes the no-innerHTML rule. */

function b64u(s) {
  const b = new TextEncoder().encode(String(s));
  let bin = "";
  b.forEach((c) => { bin += String.fromCharCode(c); });
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const ENTITY_PATH = {
  ip: (v) => `/ip/${encodeURIComponent(v)}`,
  asn: (v) => `/asn/${encodeURIComponent(String(v).startsWith("AS") ? v : `AS${v}`)}`,
  session: (v) => `/session/${encodeURIComponent(v)}`,
  sample: (v) => `/sample/${encodeURIComponent(v)}`,
  hassh: (v) => `/hassh/${encodeURIComponent(v)}`,
  day: (v) => `/day/${encodeURIComponent(String(v).slice(0, 10))}`,
  credential: (v) => `/credential/${b64u(`${v.username || ""}\x00${v.password || ""}`)}`,
  url: (v) => `/url/${b64u(v)}`,
};

export function entityHref(type, value) {
  return ENTITY_PATH[type] ? ENTITY_PATH[type](value) : null;
}

export function entity(type, value, label) {
  const bad = value === null || value === undefined || value === "" ||
    value === "-" || value === "unknown" ||
    (type === "credential" && !value.username && !value.password);
  if (bad) return h("span", { class: "mono sub2", text: label || "-" });
  const route = ENTITY_PATH[type](value);
  const text = label !== undefined ? label
    : type === "credential" ? `${value.username || "(blank)"}:${value.password || "(blank)"}`
    : String(value);
  const id = type === "credential" || type === "url" ? route.split("/")[2] : String(value);
  return h("a", {
    href: url(route),
    "data-route": route,
    class: "mono ent",
    text,
    "data-ent": `${type}:${id}`,
    onclick: (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      e.preventDefault();
      navigate(route);
    },
  });
}

export function ipLink(ip) { return entity("ip", ip, ip || "-"); }

export function dayLink(ts) {
  const d = String(ts || "").slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return h("span", { class: "mono sub2", text: shortDate(ts) });
  return entity("day", d, shortDate(ts));
}

export function routeLink(route, label, cls) {
  return h("a", {
    href: url(route), class: cls || "mono", text: label,
    onclick: (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      e.preventDefault();
      navigate(route);
    },
  });
}

/* "<- Sources": where the reader came from, as a link with an arrow. */
export function backLink(route, label) {
  const a = routeLink(route, "", "backlink");
  a.replaceChildren(icon("arrow-left", { size: 14 }), document.createTextNode(label));
  return a;
}

export function copyBtn(value) {
  return wireCopy(
    h("button", { class: "copy", type: "button", title: "Copy to the clipboard" }),
    () => value, "Copy");
}

/* ---------- export -------------------------------------------------------
   Every entity page carries one control that turns its record into a document
   written for a language model: copy it, or save it as Markdown or JSON. The
   server builds the document; nothing is assembled from the DOM.

   The Markdown is fetched when the menu opens, not when copy is clicked. On
   the plain-HTTP origins this site is served from, the clipboard fallback
   only works inside the click itself, and a fetch in between would lose it.
   Opening the menu is also what shows the size, which is worth knowing
   before pasting into a context window. */

export function exportControl(type, id) {
  const path = `/api/v1/export/${encodeURIComponent(type)}/${encodeURIComponent(id)}`;
  let brief = true;
  try { brief = localStorage.getItem("tr.export.brief") !== "0"; } catch (err) { /* default */ }
  let text = null;
  let seq = 0;

  const link = (format, download) => url(
    `${path}?format=${format}&days=${state.days}&brief=${brief ? 1 : 0}${download ? "&download=1" : ""}`);

  const size = h("span", { class: "export-size", role: "status" });
  const copy = wireCopy(
    h("button", { type: "button", class: "primary", disabled: true }),
    () => text || "", "Copy for an AI model");
  const md = h("a", { download: true }, [icon("file-down"), "Download Markdown"]);
  const json = h("a", { download: true }, [icon("file-down"), "Download JSON"]);
  const ask = h("input", { type: "checkbox" });
  ask.checked = brief;

  async function load() {
    const mine = ++seq;
    text = null;
    copy.disabled = true;
    size.textContent = "Building the document";
    md.setAttribute("href", link("md", true));
    json.setAttribute("href", link("json", true));
    try {
      const res = await fetch(link("md", false), { headers: { Accept: "text/markdown" } });
      if (!res.ok) throw new Error(String(res.status));
      const body = await res.text();
      if (mine !== seq) return;
      text = body;
      // Four characters a token is the usual rough figure for English and
      // shell text. It is a guide for choosing a model, not a count.
      size.textContent = `${bytes(new Blob([body]).size)}, about ${num(Math.ceil(body.length / 400) * 100)} tokens`;
      copy.disabled = false;
    } catch (err) {
      if (mine === seq) {
        size.textContent = "The export could not be built. Close and reopen this menu to try again.";
        text = null;
      }
    }
  }

  ask.addEventListener("change", () => {
    brief = ask.checked;
    try { localStorage.setItem("tr.export.brief", brief ? "1" : "0"); } catch (err) { /* not kept */ }
    load();
  });

  const box = h("details", {
    class: "export",
    ontoggle: () => { if (box.open && text === null) load(); },
    onkeydown: (e) => {
      if (e.key !== "Escape" || !box.open) return;
      box.open = false;
      box.querySelector("summary").focus();
    },
  }, [
    h("summary", { title: "Export this record for an AI model (x)" }, [icon("file-down", { size: 14 }), "Export"]),
    h("div", { class: "export-menu" }, [
      h("p", { text: "This record as one document an AI analyst can read: what the sensor "
        + "is, the evidence, and what was left out." }),
      h("div", { class: "export-row" }, [copy, size]),
      h("label", { class: "export-ask" }, [ask, " End with a request for analysis and recommendations"]),
      h("div", { class: "export-row" }, [md, json]),
    ]),
  ]);
  return box;
}

export function vtLink(sha, label) {
  return h("a", {
    class: label ? null : "mono", target: "_blank", rel: "noreferrer noopener",
    href: `https://www.virustotal.com/gui/file/${encodeURIComponent(sha)}`,
    title: "Open the VirusTotal report in a new tab",
  }, [label || mid(sha, 12, 6), " ", icon("external-link", { size: 14 })]);
}

/* ---------- sparkline ---------- */

export function spark(rows, { width = 560, height = 56, key = "events" } = {}) {
  if (!rows || rows.length < 2) {
    return emptyState("Not enough days to draw a line.", {
      hint: "A daily line needs at least two days of activity in the window.",
      widen: true,
    });
  }
  const max = Math.max(1, ...rows.map((r) => Number(r[key]) || 0));
  const step = width / (rows.length - 1);
  const y = (v) => height - 4 - ((Number(v) || 0) / max) * (height - 10);
  const pts = rows.map((r, i) => `${(i * step).toFixed(1)},${y(r[key]).toFixed(1)}`);
  const el = svg("svg", {
    viewBox: `0 0 ${width} ${height}`, class: "spark",
    preserveAspectRatio: "none", role: "img",
    "aria-label": `Daily activity, peak ${max}`,
  });
  el.appendChild(svg("polyline", {
    points: `0,${height} ${pts.join(" ")} ${width},${height}`, class: "spark-fill",
  }));
  el.appendChild(svg("polyline", { points: pts.join(" "), class: "spark-line" }));
  const wrap = h("div", { class: "sparkwrap" }, []);
  wrap.appendChild(el);
  const peak = rows.reduce((a, b) => (Number(b[key]) > Number(a[key]) ? b : a), rows[0]);
  wrap.appendChild(h("div", { class: "sub2 sparkcap" }, [
    entity("day", rows[0].day, rows[0].day), " to ",
    entity("day", rows[rows.length - 1].day, rows[rows.length - 1].day),
    `. Busiest day ${num(peak[key])} events, on `, entity("day", peak.day, peak.day), ".",
  ]));
  return wrap;
}

/* ---------- table fitting ------------------------------------------------
   Only the tables that actually overflow become scroll containers, because a
   scroll container breaks the sticky header. Measured after layout, and again
   on resize and on any change that alters row widths. */

export function fitTables(root) {
  const scope = root || document;
  scope.querySelectorAll(".tbl-wrap").forEach((wrap) => {
    const t = wrap.querySelector("table");
    if (!t) return;
    wrap.classList.toggle("scrolls", t.scrollWidth > wrap.clientWidth + 1);
  });
}

let fitTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(fitTimer);
  fitTimer = setTimeout(() => fitTables(), 150);
});

export function skeleton(rows = 6) {
  return h("div", { class: "skel", "aria-hidden": "true" }, [
    h("div", { class: "skel-bar w40" }),
    h("div", { class: "skel-row w70" }),
    h("div", { class: "skel-table" }, Array.from({ length: rows }, (_, i) =>
      h("div", { class: `skel-row ${i % 3 === 0 ? "w90" : i % 3 === 1 ? "w75" : "w85"}` }))),
  ]);
}

/* ---------- breadcrumbs ---------- */

const TRAIL_MAX = 6;
let trail = [];

export function trailPush(path, label) {
  const at = trail.findIndex((t) => t.path === path);
  if (at >= 0) trail = trail.slice(0, at + 1);
  else trail.push({ path, label });
  if (trail.length > TRAIL_MAX) trail = trail.slice(-TRAIL_MAX);
}

export function trailReset() { trail = []; }

export function breadcrumbs() {
  if (trail.length < 2) return null;
  const out = [];
  trail.forEach((t, i) => {
    if (i) out.push(h("span", { class: "crumb-sep", text: "/" }));
    out.push(i === trail.length - 1
      ? h("span", { class: "crumb cur mono", text: t.label })
      : routeLink(t.path, t.label, "crumb mono"));
  });
  return h("nav", { class: "crumbs", "aria-label": "pivot trail" }, out);
}

/* ---------- router ---------- */

const ROUTES = {
  "/": () => import("./pages/overview.js"),
  "/sources": () => import("./pages/sources.js"),
  "/credentials": () => import("./pages/credentials.js"),
  "/payloads": () => import("./pages/payloads.js"),
  "/sessions": () => import("./pages/sessions.js"),
  "/tunnels": () => import("./pages/tunnels.js"),
  "/method": () => import("./pages/method.js"),
};

const PREFIXED = [
  ["/session/", () => import("./pages/session.js")],
  ["/sample/", () => import("./pages/sample.js")],
  ["/ip/", () => import("./pages/entity.js")],
  ["/asn/", () => import("./pages/entity.js")],
  ["/credential/", () => import("./pages/entity.js")],
  ["/hassh/", () => import("./pages/entity.js")],
  ["/url/", () => import("./pages/entity.js")],
  ["/day/", () => import("./pages/entity.js")],
];

/* v4 sent any path it did not recognise to the Overview, so a mistyped link
   looked like it worked and silently showed the wrong page. */
const NOT_FOUND = () => import("./pages/notfound.js");

const SITE = "Threat Radar";
// How long a view may take before the loading placeholder appears. Under this
// a cached or fast view swaps in without a flash of grey bars.
const SKELETON_DELAY_MS = 150;

let renderSeq = 0;
let navigated = false;

export function navigate(route) {
  history.pushState({}, "", url(route));
  navigated = true;
  render();
}

export async function render() {
  const mine = ++renderSeq;
  const path = currentPath();
  const prefixed = PREFIXED.find(([p]) => path.startsWith(p));
  if (prefixed) {
    const seg = path.split("/").filter(Boolean);
    let raw = seg[1] || "";
    try { raw = decodeURIComponent(raw); } catch (err) { /* keep it as it came */ }
    trailPush(path, raw.length > 18 ? `${raw.slice(0, 10)}…${raw.slice(-6)}` : raw);
  } else {
    trailReset();
  }

  const known = prefixed || ROUTES[path];
  document.body.dataset.page = prefixed ? prefixed[0] : known ? path : "404";
  document.querySelectorAll(".nav a[data-path]").forEach((a) => {
    if (a.dataset.path === path) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
    a.setAttribute("href", url(a.dataset.path));
  });
  const topbar = document.querySelector(".topbar");
  if (topbar) topbar.setAttribute("data-print-scope", windowLabel());

  const out = document.getElementById("view");
  const load = prefixed ? prefixed[1] : (ROUTES[path] || NOT_FOUND);
  out.setAttribute("aria-busy", "true");
  const skel = setTimeout(() => {
    if (mine === renderSeq) out.replaceChildren(skeleton());
  }, SKELETON_DELAY_MS);

  let node;
  let mod = null;
  try {
    mod = await load();
    node = await mod.render();
  } catch (err) {
    node = errorState(err);
  }
  clearTimeout(skel);
  if (mine !== renderSeq) return;      // a newer navigation already owns the view

  out.replaceChildren(node);
  out.setAttribute("aria-busy", "false");
  window.scrollTo({ top: 0 });
  raf(() => fitTables(out));
  import("./hovercard.js").then((hc) => hc.warmView(out)).catch(() => {});

  const title = mod ? (mod.DOC_TITLE || mod.TITLE) : "Something went wrong";
  document.title = title ? `${title} | ${SITE}` : SITE;
  const heading = document.getElementById("page-title");
  if (heading) heading.textContent = (mod && mod.TITLE) || "";
  // After an in-app navigation, move focus to the new content so a keyboard
  // or screen reader user starts at the top of the page they asked for.
  if (navigated) { navigated = false; out.focus({ preventScroll: true }); }
}

/* ---------- shell controls ---------- */

function paintDensity() {
  const btn = document.getElementById("density-toggle");
  if (!btn) return;
  const compact = state.density === "compact";
  btn.replaceChildren(icon(compact ? "rows-4" : "rows-3"));
  const label = `Row density: ${compact ? "compact" : "roomy"}. Switch to ${compact ? "roomy" : "compact"} (d)`;
  btn.setAttribute("aria-label", label);
  btn.title = label;
}

export function wireShell() {
  const go = (e, path) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(path);
  };
  document.querySelectorAll(".nav a[data-path]").forEach((a) => {
    a.setAttribute("href", url(a.dataset.path));
    a.addEventListener("click", (e) => go(e, a.dataset.path));
  });
  const brand = document.getElementById("brand");
  if (brand) brand.addEventListener("click", (e) => go(e, "/"));
  window.addEventListener("popstate", render);

  const omniIcon = document.getElementById("omni-icon");
  if (omniIcon) omniIcon.replaceChildren(icon("search"));

  document.body.dataset.mode = state.mode;
  setDensity(state.density);

  document.querySelectorAll(".modeswitch button").forEach((b) => {
    b.setAttribute("aria-pressed", String(b.dataset.mode === state.mode));
    b.addEventListener("click", () => {
      setMode(b.dataset.mode);
      document.querySelectorAll(".modeswitch button").forEach((x) =>
        x.setAttribute("aria-pressed", String(x.dataset.mode === state.mode)));
      render();
    });
  });

  const sel = document.getElementById("window-select");
  if (sel) {
    sel.value = String(state.days);
    sel.addEventListener("change", () => {
      setDays(Number(sel.value));
      clearCache();
      render();
    });
  }

  const dens = document.getElementById("density-toggle");
  if (dens) {
    dens.addEventListener("click", () =>
      setDensity(state.density === "compact" ? "comfortable" : "compact"));
  }
}
