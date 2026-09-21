/* pages/payloads.js - the contribution loop: what got dropped here, what it
   turned out to be, and what went back upstream. */

import { api, h, num, bytes, panel, table, tag, mid, shortDate,
         funnel, takeaway, isExec, entity, dayLink, emptyState } from "../core.js";

export const TITLE = "Malware";

/* A link out to the public record for one contribution. External, so it opens
   in a new tab and carries no referrer. */
function serviceLink(key, svc, sha) {
  const href = svc.permalink || (key === "malwarebazaar"
    ? `https://bazaar.abuse.ch/sample/${encodeURIComponent(sha)}/`
    : `https://www.virustotal.com/gui/file/${encodeURIComponent(sha)}`);
  return h("a", {
    class: "tag ok", target: "_blank", rel: "noreferrer noopener", href,
    title: `uploaded ${svc.submitted_at || ""}`, text: svc.label || key,
  });
}

const ATTRIBUTION = {
  confirmed: ["first submitter", "ok",
    "VirusTotal's first submission date matches our upload."],
  preceded: ["preceded", "warn",
    "Someone else uploaded this to VirusTotal before our upload landed."],
  unverified: ["unverified", "",
    "VirusTotal has not reported a first submission date for this file yet."],
};

function attributionTag(a) {
  if (!a) return h("span", { class: "sub2", text: "not on VirusTotal" });
  const [text, tone, why] = ATTRIBUTION[a] || [a, "", ""];
  return h("span", { class: `tag ${tone}`.trim(), title: why, text });
}

/* Detections the day we uploaded against the latest lookup. */
function detectionCell(d) {
  if (!d || !d.current) return h("span", { class: "sub2", text: "no lookup yet" });
  const a = d.initial, b = d.current;
  const same = a.at === b.at;
  return h("span", { class: "mono" }, [
    same ? `${b.malicious}/${b.engines}` : `${a.malicious}/${a.engines} to ${b.malicious}/${b.engines}`,
    !same && d.lift > 0 ? h("span", { class: "sub2", text: ` +${d.lift}` }) : null,
  ]);
}

const DELIVERY = { url: "fetched from a URL", upload: "pushed over SFTP/SCP",
                   inband: "written in-band" };

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
  const c = d.contributions || {};
  const cs = c.summary || {};
  const items = c.items || [];

  const captured = Number(s.distinct_hashes || 0);
  const flagged = Number(s.flagged_indicators || 0);
  // Distinct samples we uploaded to at least one service inside the window.
  // A service that already held a file is never counted as a contribution.
  const sent = Number(cs.contributed_window || 0);

  const steps = [
    { label: "captured", value: captured, color: "--stage-3" },
    { label: "identified", value: flagged, color: "--stage-4" },
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
          + "there, and anything captured in the last ten days that at least one engine "
          + "flags goes to MalwareBazaar under a named account, which makes the sensor a "
          + "contributor rather than only a consumer." }),
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
              ? { b: `${num(sent)} went upstream as new samples` }
              : { alarm: "none were new upstream" },
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

    panel("Contributions",
      "All time. Samples this sensor uploaded that the service did not already hold. "
      + "Attribution compares our upload time with VirusTotal's own first submission date, "
      + "and detections show what engines said on the day against the latest lookup.",
      [cs.contributed_samples
        ? takeaway([
            { b: `${num(cs.contributed_samples)} samples` }, " contributed in total, ",
            { b: num(cs.confirmed_first || 0) }, " confirmed as the first VirusTotal submission",
            cs.preceded ? [", ", { alarm: `${num(cs.preceded)} preceded by another submitter` }] : "",
            ".",
          ].flat())
        : null,
       table(
        [{ label: "sample" }, { label: "family" }, { label: "published to" },
         { label: "attribution" }, { label: "detections" }, { label: "capture" },
         { label: "contributed" }],
        items,
        (r) => [
          [entity("sample", r.sha256, mid(r.sha256, 12, 6)),
           r.size_bytes ? h("div", { class: "sub2 mono", text: bytes(r.size_bytes) }) : null],
          familyTag(r),
          h("span", {}, Object.entries(r.services || {})
            .map(([k, v]) => serviceLink(k, v, r.sha256))
            .flatMap((el, i) => (i ? [" ", el] : [el]))),
          attributionTag(r.attribution),
          detectionCell(r.detections),
          r.capture
            ? [h("span", { class: "sub2", text: DELIVERY[r.capture.delivery] || "unknown" }),
               h("div", {}, [dayLink(r.capture.first_seen)])]
            : h("span", { class: "sub2", text: "capture record not kept" }),
          dayLink(r.first_contributed),
        ],
        "Nothing contributed yet. Every captured file was already known upstream.")]),

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
