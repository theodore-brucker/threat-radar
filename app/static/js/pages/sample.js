/* pages/sample.js - one sample. Text is shown as text; binaries are described
   but never served. There is no download path anywhere on this page. */

import { api, h, num, bytes, panel, table, tag, mid, takeaway, routeLink,
         vtLink, ipLink, entity, dayLink, copyBtn, emptyState, currentPath,
         breadcrumbs } from "../core.js";

export const TITLE = "Sample";

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
      h("dd", { class: "mono", text: String(v) }),
    ])),
    pk.note ? takeaway([{ alarm: pk.note }]) : null,
  ], { scoped: false });
}

export async function render() {
  const sha = (currentPath().split("/").filter(Boolean)[1] || "").toLowerCase();
  let d;
  try {
    d = await api(`/api/v1/samples/${encodeURIComponent(sha)}`);
  } catch (err) {
    return emptyState("That is not a sample this sensor has a record of.", {
      hint: "A sample id is a 64 character sha256.",
    });
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
    ["vt standing", vt ? vt.verdict : "not looked up"],
    ["vt detections", total ? `${detected} of ${total}` : null],
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
      breadcrumbs(),
      h("p", {}, [routeLink("/payloads", "back to malware", "")]),
      h("div", { class: "enthead" }, [
        h("h1", { text: sha }),
        copyBtn(sha),
      ]),
      h("p", {}, [vtLink(sha, "open the VirusTotal report")]),
    ]),

    panel("Identification", null, [
      h("dl", { class: "facts" }, facts.flatMap(([k, v]) => [
        h("dt", { text: k }),
        h("dd", { class: "mono" }, [typeof v === "object" ? v : String(v)]),
      ])),
      d.note ? takeaway([d.trivial ? d.note : { b: d.note }]) : null,
    ], { scoped: false }),

    packerPanel(d.packer),

    panel("Where it was seen", "Every session that moved this file.", [
      table(
        [{ label: "when" }, { label: "session" }, { label: "source" },
         { label: "dir" }, { label: "origin" }],
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
