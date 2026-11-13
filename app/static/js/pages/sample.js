/* pages/sample.js - one sample. Text is shown as text; binaries are described
   but never served. There is no download path anywhere on this page. */

import { api, h, num, bytes, panel, table, tag, mid, takeaway, routeLink,
         vtLink, ipLink, entity, dayLink, copyBtn, emptyState, currentPath,
         breadcrumbs, exportControl, pageState, errorState, backLink } from "../core.js";

export const TITLE = "Sample";
export let DOC_TITLE = "Sample";

function packerPanel(pk) {
  if (!pk) return null;
  const rows = [
    ["packer", pk.packer],
    ["version", pk.version],
    ["method", pk.method === 14 ? "14 (LZMA)" : pk.method],
    ["compression level", pk.level],
    ["header offset", pk.header_offset],
    ["unpacked size", pk.unpacked_size ? bytes(pk.unpacked_size) : null],
    ["trailer", pk.trailer_present ? "present" : "absent"],
  ].filter(([, v]) => v !== null && v !== undefined);

  return panel("Packing", null, [
    h("dl", { class: "facts" }, rows.flatMap(([k, v]) => [
      h("dt", { text: k }),
      h("dd", { text: String(v) }),
    ])),
    pk.note ? takeaway([{ alarm: pk.note }]) : null,
  ], { scoped: false });
}

/* Only for samples this sensor uploaded. Every fact here is linkable to the
   public record, so the claim can be checked without trusting this page. */
function contributionPanel(c) {
  if (!c) return null;
  const names = { virustotal: "VirusTotal", malwarebazaar: "MalwareBazaar" };
  const verdict = {
    confirmed: "first submitter, matched against VirusTotal's first submission date",
    preceded: "another submitter reached VirusTotal first",
    unverified: "VirusTotal has not reported a first submission date yet",
  };
  const det = c.detections || {};
  const rows = Object.entries(c.services || {}).map(([k, v]) => [
    `uploaded to ${names[k] || k}`,
    h("span", {}, [
      dayLink(v.submitted_at), " ",
      v.permalink
        ? h("a", { target: "_blank", rel: "noreferrer noopener", href: v.permalink,
                   text: "public record" })
        : h("span", { class: "sub2", text: "no public link recorded" }),
    ]),
  ]);
  if (c.attribution) rows.push(["attribution", verdict[c.attribution] || c.attribution]);
  if (det.initial) {
    rows.push(["detections then", `${det.initial.malicious} of ${det.initial.engines}`]);
    rows.push(["detections now", `${det.current.malicious} of ${det.current.engines}`]);
  }
  return panel("Contributed upstream", null, [
    h("dl", { class: "facts" }, rows.flatMap(([k, v]) => [
      h("dt", { text: k }),
      h("dd", {}, [typeof v === "object" ? v : String(v)]),
    ])),
  ], { scoped: false });
}

export async function render() {
  const sha = (currentPath().split("/").filter(Boolean)[1] || "").toLowerCase();
  DOC_TITLE = `Sample ${mid(sha, 10, 6)}`;
  let d;
  try {
    d = await api(`/api/v1/samples/${encodeURIComponent(sha)}`);
  } catch (err) {
    if (err && (err.status === 404 || err.status === 400)) {
      return pageState({
        iconName: "search-x",
        title: "This sensor has no record of that sample.",
        text: /^[0-9a-f]{64}$/.test(sha)
          ? "No session on record moved a file with this SHA-256. Its page on VirusTotal "
            + "may still exist if someone else submitted it."
          : "A sample is identified by its SHA-256: 64 hexadecimal characters.",
        actions: [routeLink("/payloads", "Back to malware", "action")],
      });
    }
    return errorState(err);
  }

  const vt = (d.intel || []).find((r) => r.source === "virustotal");
  const detected = vt ? Number(vt.malicious || 0) : null;
  const total = vt
    ? Number(vt.malicious || 0) + Number(vt.harmless || 0) + Number(vt.undetected || 0)
    : null;

  const facts = [
    ["size", d.present ? bytes(d.size_bytes) : "not held locally"],
    ["type", d.kind],
    ["entropy", d.trivial ? null : d.entropy],
    ["VirusTotal standing", vt ? vt.verdict : "not looked up yet"],
    ["VirusTotal detections", total ? `${detected} of ${total} engines` : null],
    ["family", d.family
      ? h("span", {}, [
          h("b", { text: d.family.family }),
          h("span", { class: "sub2", title: d.family.basis || "",
            text: d.family.confidence === "agreed" ? "  vendors agree" : "  one vendor" }),
        ])
      : (vt && vt.label && !/^\[[A-Za-z]+\]$/.test(vt.label.trim())
          ? h("span", { class: "sub2", title: vt.label,
              text: "no family derived from the vendor label" })
          : null)],
  ].filter(([, v]) => v !== null && v !== undefined);

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      breadcrumbs() || backLink("/payloads", "Malware"),
      h("div", { class: "enthead" }, [
        h("h1", { text: sha }),
        copyBtn(sha),
        exportControl("sample", sha),
      ]),
      h("p", {}, [vtLink(sha, "Open the VirusTotal report")]),
    ]),

    panel("Identification", null, [
      h("dl", { class: "facts" }, facts.flatMap(([k, v]) => [
        h("dt", { text: k }),
        h("dd", {}, [typeof v === "object" ? v : String(v)]),
      ])),
      d.note ? takeaway([d.trivial ? d.note : { b: d.note }]) : null,
    ], { scoped: false }),

    packerPanel(d.packer),

    contributionPanel(d.contribution),

    panel("Where it was seen", "Every session that moved this file.", [
      table(
        [{ label: "When" }, { label: "Session" }, { label: "Source" },
         { label: "Direction" }, { label: "Origin" }],
        d.sightings || [],
        (r) => [
          dayLink(r.ts),
          entity("session", r.session),
          ipLink(r.src_ip || "-"),
          tag(r.direction === "out" ? "uploaded to us" : "fetched by the host", "bad"),
          r.url
            ? entity("url", r.url, mid(r.url, 30, 10))
            : h("span", { class: "mono sub2", title: r.path || "",
                text: r.path ? `in-band to ${mid(r.path, 18, 10)}` : "pushed in-band" }),
        ],
        "No sightings recorded for this hash."),
    ], { scoped: false }),

    d.is_text
      ? panel(d.trivial ? "Recorded content" : "Source",
          d.trivial ? "Kept for the record; not a working payload."
            : d.truncated ? "Truncated for display." : `${num(d.line_count)} lines.`, [
          h("pre", { class: "code" }, [h("code", { text: d.text || "" })]),
        ], { scoped: false })
      : d.present
        ? panel("Strings",
            "Printable runs from the file, filtered to drop compression noise. "
            + "The binary itself is not served from this page.", [
            (d.strings || []).length
              ? h("pre", { class: "code" }, [h("code", { text: (d.strings || []).join("\n") })])
              : emptyState("No meaningful strings recovered.", {
                  hint: "Expected for a packed or encrypted file.",
                }),
            d.strings_capped ? h("p", { class: "sub2", text: "Output capped." }) : null,
          ], { scoped: false })
        : emptyState("This sample is referenced in the logs but is not held locally.", {
            hint: "The sensor only keeps files it was able to capture in full.",
          }),
  ]);
}
