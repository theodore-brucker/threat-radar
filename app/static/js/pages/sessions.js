/* pages/sessions.js - the sessions that actually produced something.
   Roughly one in two thousand connections moves a file; those are the ones
   worth reading end to end. */

import { api, h, num, panel, table, shortDate, tag, mid, takeaway,
         routeLink, ipLink, entity } from "../core.js";

export const TITLE = "Sessions";

function span(a, b) {
  const ms = new Date(b) - new Date(a);
  if (!isFinite(ms) || ms < 0) return "-";
  const s = ms / 1000;
  return s < 60 ? `${s.toFixed(0)}s` : `${(s / 60).toFixed(1)}m`;
}

export async function render() {
  const d = await api("/api/v1/sessions");
  const rows = d.sessions || [];
  const inbound = rows.reduce((n, r) => n + (r.downloads || 0), 0);

  // A hash delivered by more than one source, or a source seen more than once,
  // is the part a flat list hides. Both are computed from what is on screen.
  const sourceCount = new Map();
  const hashSources = new Map();
  for (const r of rows) {
    sourceCount.set(r.src_ip, (sourceCount.get(r.src_ip) || 0) + 1);
    for (const sha of r.shasums || []) {
      if (!hashSources.has(sha)) hashSources.set(sha, new Set());
      hashSources.get(sha).add(r.src_ip);
    }
  }
  const sharedHashes = [...hashSources.values()].filter((v) => v.size > 1).length;

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("p", { text:
        "Connections that moved a file in either direction. Almost every session on the "
        + "sensor ends at a login prompt; these are the ones where someone got in and did "
        + "something. Open any row for the full timeline." }),
    ]),

    panel("Sessions that moved files", "Newest first.", [
      takeaway([
        { b: num(rows.length) }, " sessions carried file activity, accounting for ",
        { b: `${num(inbound)} inbound files` },
        sharedHashes
          ? [". ", { alarm: `${sharedHashes} samples arrived from more than one source` },
             ", which points at shared tooling rather than unrelated actors."]
          : ".",
      ].flat()),
      table(
        [{ label: "started" }, { label: "source" }, { label: "duration" },
         { label: "commands", num: true }, { label: "fetched", num: true },
         { label: "pushed", num: true }, { label: "first sample" },
         { label: "pattern" }],
        rows,
        (r) => [
          routeLink(`/session/${r.session}`, shortDate(r.started)),
          ipLink(r.src_ip || "-"),
          h("span", { class: "mono sub2", text: span(r.started, r.ended) }),
          num(r.commands), num(r.downloads), num(r.uploads),
          (r.shasums || []).length
            ? entity("sample", r.shasums[0], mid(r.shasums[0], 10, 6))
            : h("span", { class: "sub2", text: "-" }),
          [
            (r.shasums || []).some((sha) => (hashSources.get(sha) || new Set()).size > 1)
              ? tag("shared sample", "bad") : null,
            sourceCount.get(r.src_ip) > 1
              ? tag(`${sourceCount.get(r.src_ip)}x source`, "warn") : null,
          ],
        ],
        "No sessions moved files in this window."),
    ]),
  ]);
}
