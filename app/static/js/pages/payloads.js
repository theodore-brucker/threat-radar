/* pages/payloads.js - the contribution loop: what got dropped here, what it
   turned out to be, and what went back upstream. */

import { api, h, num, bytes, panel, table, tag, mid, shortDate,
         funnel, takeaway, isExec, entity, dayLink, emptyState } from "../core.js";

export const TITLE = "Malware";

function verdictTag(v) {
  // "undetected" is not "clean": nothing flagged it, which for a sample we
  // submitted ourselves often means nobody has looked yet. No green tick.
  const tone = v === "malicious" ? "bad" : v === "suspicious" ? "warn" : "";
  return tag(v === "clean" ? "undetected" : (v || "unknown"), tone);
}

/* The derived family, with its confidence visible rather than implied. */
function familyTag(r) {
  if (!r.family) return h("span", { class: "sub2", text: "unnamed" });
  return h("span", {}, [
    h("b", { text: r.family }),
    r.family_confidence === "single-vendor"
      ? h("span", { class: "sub2", text: " one vendor" }) : null,
  ]);
}

export async function render() {
  const d = await api("/api/v1/payloads");
  const s = d.summary || {};
  const list = (d.payloads && d.payloads.payloads) || [];
  const subs = d.submissions || [];

  const captured = Number(s.distinct_hashes || 0);
  const flagged = Number(s.flagged_indicators || 0);
  const sent = subs.filter((x) => x.status === "submitted").length;
  const dupes = subs.filter((x) => x.status === "duplicate").length;

  const steps = [
    { label: "captured", value: captured, color: "--stage-3" },
    { label: "identified", value: flagged, color: "--stage-4" },
    { label: "new to VirusTotal", value: sent + dupes, color: "--accent" },
    { label: "contributed", value: sent, color: "--ok" },
  ];

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("p", { text: isExec()
        ? "Files that attackers pulled onto the decoy or pushed off it. Each one is "
          + "fingerprinted, checked against public malware databases, and anything the "
          + "industry has never seen before is sent upstream so other defenders benefit."
        : "Every file a session moved, rolled up by hash and source URL, with VirusTotal "
          + "and URLhaus standings attached. Hashes VirusTotal returns 404 on are uploaded "
          + "from here, which makes the sensor a contributor rather than only a consumer." }),
    ]),

    panel("Contribution loop", "From capture to upstream submission.", [
      captured
        ? funnel(steps)
        : emptyState("No files were captured in this window.", { widen: true }),
      captured
        ? takeaway([
            "Of ", { b: `${num(captured)} distinct files` }, " captured, ",
            { b: num(flagged) }, " carried a known malware standing and ",
            sent > 0
              ? { b: `${num(sent)} were new enough to contribute back` }
              : { alarm: "none were new to VirusTotal" },
            sent > 0 ? "." : " in this window, which is normal for commodity tooling.",
          ])
        : null,
    ]),

    panel("Families",
      "Derived from the labels detection engines already gave us: category and engine-noise "
      + "tokens are dropped and the best-supported name is kept. This follows vendor naming, "
      + "so it says what engines call a sample, not who wrote it.",
      [table(
        [{ label: "family" }, { label: "samples", num: true },
         { label: "transfers", num: true }, { label: "basis" }, { label: "last seen" }],
        (d.families && d.families.families) || [],
        (r) => [
          h("b", { text: r.family }),
          num(r.samples), num(r.transfers),
          h("span", { class: "sub2",
            text: r.confidence === "agreed" ? "vendors agree" : "one vendor" }),
          h("span", { class: "mono sub2", text: shortDate(r.last_seen) }),
        ],
        "No families derived in this window."),
       (d.families && d.families.unnamed_samples)
         ? h("p", { class: "sub2", text:
             `${num(d.families.unnamed_samples)} captured samples carry no family-shaped `
             + "label from any vendor, which is normal for commodity droppers and for "
             + "anything only this sensor has seen." })
         : null]),

    panel("Transfers", "One row per hash and source URL.",
      [table(
        [{ label: "verdict" }, { label: "family" }, { label: "dir" },
         { label: "sha256" }, { label: "source url", cls: "trunc" },
         { label: "hits", num: true }, { label: "ips", num: true },
         { label: "last seen" }],
        list,
        (r) => [
          verdictTag(r.verdict),
          [familyTag(r),
           (r.labels || []).length
             ? h("div", { class: "sub2 trunc", title: (r.labels || []).join(" | "),
                 text: (r.labels || []).slice(0, 3).join(", ") })
             : null],
          h("span", { class: "mono", text: r.direction }),
          [r.shasum ? entity("sample", r.shasum, mid(r.shasum, 12, 6))
             : h("span", { class: "mono", text: "-" }),
           r.filename ? h("div", { class: "sub2 mono", text: mid(r.filename, 24, 10) }) : null],
          entity("url", r.url, r.url || "-"),
          num(r.hits), num(r.src_ips),
          dayLink(r.last_seen),
        ],
        "No files moved in this window.")]),

    panel("Upstream submissions",
      "Samples VirusTotal had never seen, uploaded from here. Hashes already in their "
      + "corpus are skipped, so the count stays small by design.",
      [table(
        [{ label: "sha256" }, { label: "status" }, { label: "size", num: true }, { label: "when" }],
        subs,
        (r) => [
          entity("sample", r.sha256, mid(r.sha256, 12, 6)),
          tag(r.status, r.status === "submitted" ? "ok" : r.status === "error" ? "bad" : ""),
          bytes(r.size_bytes),
          dayLink(r.submitted_at),
        ],
        "No submissions in this window. Every captured file was already known upstream.")]),

    panel("Distribution hosts",
      "A host that also appears as an attacker is serving stagers from the same box it "
      + "scans with.",
      [table(
        [{ label: "verdict" }, { label: "host" }, { label: "urls", num: true },
         { label: "hits", num: true }, { label: "also scanning" }],
        (d.hosts && d.hosts.hosts) || [],
        (r) => [
          verdictTag(r.verdict),
          h("span", { class: "mono", text: r.host }),
          num(r.urls), num(r.hits),
          r.seen_as_attacker ? tag("yes", "bad") : h("span", { class: "sub2", text: "no" }),
        ],
        "No distribution hosts in this window.")]),
  ]);
}
