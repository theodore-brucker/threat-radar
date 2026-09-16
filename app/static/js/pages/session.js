/* pages/session.js - one session, start to finish.

   Every string here came from an attacker and reaches the DOM through
   textContent. Commands render as inert text in a block that scrolls
   horizontally: v3 used word-break:break-all, which split IP addresses
   mid-octet across eight lines and made a command impossible to read. */

import { api, h, num, panel, shortDate, tag, mid, routeLink, ipLink,
         entity, cmdBlock, breadcrumbs, emptyState, currentPath } from "../core.js";

export const TITLE = "Session";

// Events that change what the session means, rather than protocol chatter.
const PIVOTAL = new Set([
  "cowrie.login.success",
  "cowrie.session.file_download",
  "cowrie.session.file_upload",
  "cowrie.command.input",
]);

const LONG_TEXT = new Set(["cowrie.command.input"]);

function clock(ts, base) {
  const ms = new Date(ts) - new Date(base);
  if (!isFinite(ms)) return "";
  const s = Math.max(0, ms / 1000);
  return s < 60
    ? `+${s.toFixed(0)}s`
    : `+${Math.floor(s / 60)}m${String(Math.floor(s % 60)).padStart(2, "0")}s`;
}

export async function render() {
  const id = currentPath().split("/").filter(Boolean)[1] || "";
  let d;
  try {
    d = await api(`/api/v1/sessions/${encodeURIComponent(id)}`);
  } catch (err) {
    return emptyState(`No session recorded with id ${id}.`, {
      hint: "It may have aged out of the raw event retention window.",
    });
  }
  const m = d.meta || {};
  const tl = d.timeline || [];
  const base = m.started;

  const facts = [
    ["source", m.src_ip ? ipLink(m.src_ip) : null],
    ["client", m.client],
    ["hassh", m.hassh ? entity("hassh", m.hassh, mid(m.hassh, 10, 6)) : null],
    ["credentials", m.username
      ? entity("credential", { username: m.username, password: m.password },
          `${m.username} / ${m.password}`) : null],
    ["host arch reported", m.arch],
    ["duration", m.duration_ms ? `${(m.duration_ms / 1000).toFixed(1)}s` : null],
  ].filter(([, v]) => v);

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      breadcrumbs(),
      h("p", {}, [routeLink("/sessions", "back to sessions", "")]),
      h("div", { class: "enthead" }, [h("h1", { text: `session ${id}` })]),
    ]),

    panel("What we know", null, [
      h("dl", { class: "facts" }, facts.flatMap(([k, v]) => [
        h("dt", { text: k }),
        h("dd", { class: "mono" }, [typeof v === "object" ? v : String(v)]),
      ])),
    ], { scoped: false }),

    panel("Timeline", `${num(tl.length)} events from ${shortDate(m.started)}.`, [
      tl.length
        ? h("ol", { class: "tl" }, tl.map((e) =>
            h("li", { class: PIVOTAL.has(e.eventid) ? "tl-item key" : "tl-item" }, [
              h("span", { class: "tl-clock mono", text: clock(e.ts, base) }),
              h("span", { class: "tl-dot" }),
              h("div", { class: "tl-body" }, [
                h("div", { class: "tl-label", text: e.label }),
                e.detail
                  ? (LONG_TEXT.has(e.eventid) || String(e.detail).length > 160
                      ? cmdBlock(e.detail)
                      : h("div", { class: "tl-detail mono", text: e.detail }))
                  : null,
              ]),
            ])))
        : emptyState("No events recorded for this session."),
    ], { scoped: false }),

    (d.files || []).length
      ? panel("Files moved", "Open a sample for its contents and standing.", [
          h("ul", { class: "filelist" }, d.files.map((f) =>
            h("li", {}, [
              tag(f.url ? "fetched" : "pushed in-band", "bad"),
              f.shasum
                ? entity("sample", f.shasum, mid(f.shasum, 16, 8))
                : h("span", { class: "mono", text: "(no hash)" }),
              f.url
                ? h("span", { class: "sub2 mono" }, [" via ", entity("url", f.url, mid(f.url, 34, 12))])
                : null,
            ]))),
        ], { scoped: false })
      : null,
  ]);
}
