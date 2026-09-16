/* pages/sources.js v4 - who is hitting the sensor, ranked by escalation and
   by abuse score rather than by raw event count.

   Two changes from v3. The stage filter no longer calls location.reload(),
   which threw away the whole page and every cached response to change one
   query parameter. And the basis for a category is printed on the row instead
   of the words "basis on hover", which was unreachable on touch and read as
   the design admitting it had nowhere to put the reason. */

import {
  api, h, num, pct, panel, table, stats, state, stageTag, bar, tag, mid,
  entity, ipLink, dayLink, clearCache, render as rerender,
} from "../core.js";
import { railStrip } from "../rail.js";

export const TITLE = "Sources";

export async function render() {
  const [d, rail] = await Promise.all([
    api(`/api/v1/sources?min_stage=${state.minStage}&limit=150`),
    api("/api/v1/rail"),
  ]);
  const root = h("div", {});
  const strip = railStrip(rail, {
    onChange: () => { clearCache(); rerender(); },
  });

  const totals = {};
  (d.stage_totals || []).forEach((s) => { totals[s.stage] = s.sources; });
  // d.sources is capped by the limit parameter, so its length is the row cap
  // rather than a population count. The stage totals are the real figure.
  const inWindow = (d.stage_totals || []).reduce((a, s) => a + (s.sources || 0), 0)
    || d.sources.length;

  root.append(
    h("div", { style: "margin-bottom:16px" }, [strip]),
    stats([
      { label: "sources in window", value: num(inWindow) },
      { label: "reached a shell", value: num((totals[2] || 0) + (totals[3] || 0) + (totals[4] || 0)) },
      { label: "moved a file", value: num((totals[3] || 0) + (totals[4] || 0)) },
      { label: "confirmed malware", value: num(totals[4] || 0), tone: "bad" },
    ]),

    panel("Networks by what their traffic did",
      "Ranked by how far this network's traffic got, then by how much of it there was. "
      + "Those are separate measurements rather than one blended score, because a loud "
      + "scanner and a quiet intruder are different problems and a single number cannot "
      + "say which you are looking at. The category describes observed behaviour, not "
      + "who operates the network.",
      [table(
        [{ label: "reached", sort: (r) => Number(r.depth || 0) },
         { label: "network" }, { label: "category" },
         { label: "events", num: true }, { label: "share", num: true },
         { label: "ips", num: true }, { label: "busiest address" },
         { label: "flags" }],
        (d.asn_abuse && d.asn_abuse.asns) || [],
        (r) => [
          stageTag(r.depth),
          [entity("asn", r.asn),
           h("div", { class: "sub2", text: [r.org, r.country].filter(Boolean).join(" \u00b7 ") })],
          [h("div", { text: r.class_label || "-" }),
           r.reason
             ? h("div", { class: "sub2 trunc", title: r.reason, text: r.reason })
             : null],
          num(r.events),
          [pct(r.share_pct, 2), bar(r.share_pct)],
          num(r.src_ips),
          [ipLink(r.top_ip || "-"),
           h("div", { class: "sub2", text: `${r.top_ip_share_pct}% of this network` })],
          (r.flags || []).map((f) =>
            tag(f, f.includes("single") ? "bad" : f === "dominant-volume" ? "warn" : "info")),
        ],
        "No networks matched this filter in this window.")]),

    panel("Sources by escalation",
      "Ranked by how far each address got, then by volume.",
      [table(
        [{ label: "address" }, { label: "stage", sort: (r) => Number(r.stage || 0) },
         { label: "sessions", num: true }, { label: "events", num: true },
         { label: "cmds", num: true }, { label: "files", num: true },
         { label: "network" }, { label: "last seen" }],
        d.sources,
        (r) => [
          ipLink(r.src_ip),
          stageTag(r.stage),
          num(r.sessions), num(r.events), num(r.commands), num(r.transfers),
          [entity("asn", r.asn, r.asn || "-"),
           h("div", { class: "sub2", text: [r.org, r.country].filter(Boolean).join(" \u00b7 ") })],
          dayLink(r.last_seen),
        ],
        "No sources matched this filter in this window.")]),

    h("div", { class: "grid g2" }, [
      panel("Client fingerprints",
        "hassh hashes the SSH client's algorithm offer, which identifies the library rather "
        + "than the tool built on it. Where that library is a common default it is marked as "
        + "such: shared use of it says nothing about shared tooling, and clustering on it "
        + "would invent a link.",
        [table(
          [{ label: "hassh" }, { label: "banner" }, { label: "events", num: true },
           { label: "share", num: true }],
          (d.fingerprints && d.fingerprints.fingerprints) || [],
          (r) => [
            [entity("hassh", r.hassh, mid(r.hassh, 12, 6)),
             r.known_as
               ? h("div", { class: "sub2", title: r.known_note || "" }, [
                   r.known_as,
                   r.known_kind === "library" ? tag("library default", "warn") : null,
                 ])
               : null],
            h("span", { class: "mono sub2", text: r.version || "-" }),
            num(r.events),
            pct(r.share_pct, 1),
          ],
          "No fingerprints recorded in this window.")]),

      panel("Source countries", "By event volume, from the geo enrichment.",
        [table(
          [{ label: "country" }, { label: "sources", num: true }, { label: "events", num: true }],
          d.countries || [],
          (r) => [r.country || r.code || "-", num(r.sources), num(r.events)],
          "No geolocated sources in this window.")]),
    ]),
  );
  return root;
}
