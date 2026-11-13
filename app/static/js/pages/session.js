/* pages/session.js - one session, start to finish.

   Every string here came from an attacker and reaches the DOM through
   textContent. Commands render as inert text in a block that scrolls
   horizontally, so long commands keep their addresses intact. */

import { api, h, num, panel, shortDate, tag, mid, ipLink,
         entity, cmdBlock, breadcrumbs, emptyState, currentPath,
         exportControl, pageState, errorState, backLink, routeLink } from "../core.js";

export const TITLE = "Session";
export let DOC_TITLE = "Session";

// Events that change what the session means, rather than protocol chatter.
const KEY_EVENTS = new Set([
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
  DOC_TITLE = `Session ${id}`;
  let d;
  try {
    d = await api(`/api/v1/sessions/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err && (err.status === 404 || err.status === 400)) {
      return pageState({
        iconName: "search-x",
        title: "This session is not on record.",
        text: err.status === 400
          ? `${id} is not a session id. Session ids are 12 hexadecimal characters.`
          : `No events are stored for session ${id}. Raw events are kept for 30 days, `
            + "so an older session has aged out even if its rollups still mention it.",
        actions: [routeLink("/sessions", "Browse recent sessions", "action")],
      });
    }
    return errorState(err);
  }
  const m = d.meta || {};
  const tl = d.timeline || [];
  const base = m.started;

  const facts = [
    ["source", m.src_ip ? ipLink(m.src_ip) : null],
    ["client", m.client ? h("span", { class: "mono", text: m.client }) : null],
    ["hassh", m.hassh ? entity("hassh", m.hassh, mid(m.hassh, 10, 6)) : null],
    ["credentials", m.username
      ? entity("credential", { username: m.username, password: m.password },
          `${m.username} / ${m.password}`) : null],
    ["architecture reported", m.arch ? h("span", { class: "mono", text: m.arch }) : null],
    ["duration", m.duration_ms ? `${(m.duration_ms / 1000).toFixed(1)}s` : null],
  ].filter(([, v]) => v);

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      breadcrumbs() || backLink("/sessions", "Sessions"),
      h("div", { class: "enthead" }, [
        h("h1", { text: id }),
        h("span", { class: "scope", text: "Session" }),
        exportControl("session", id),
      ]),
    ]),

    panel("What we know", null, [
      h("dl", { class: "facts" }, facts.flatMap(([k, v]) => [
        h("dt", { text: k }),
        h("dd", {}, [typeof v === "object" ? v : String(v)]),
      ])),
    ], { scoped: false }),

    panel("Timeline", `${num(tl.length)} events, starting ${shortDate(m.started)} UTC.`, [
      tl.length
        ? h("ol", { class: "tl" }, tl.map((e) =>
            h("li", { class: KEY_EVENTS.has(e.eventid) ? "tl-item key" : "tl-item" }, [
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
      ? panel("Files moved", "Open a sample to see its contents and how vendors rate it.", [
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
