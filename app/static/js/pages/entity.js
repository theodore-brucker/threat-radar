/* pages/entity.js - one page for every entity type.

   /ip, /asn, /credential, /hassh, /url and /day all land here. The API
   returns one shape (profile, timeseries, related) and this module renders
   it: identity header, activity sparkline, facts, then related-entity panels
   where every value is itself a link. Every value originated with an attacker
   and reaches the DOM through textContent only.

   Every panel is drawn even when its list is empty, and the empty state says
   so, so two entity pages of the same type always have the same sections and
   a reader can tell "nothing recorded" from "this page does not show that". */

import {
  api, h, num, panel, table, tag, mid, dur, entity, ipLink, dayLink, copyBtn,
  spark, stageTag, windowLabel, breadcrumbs, routeLink, cmdBlock, emptyState,
  currentPath, exportControl, place, pageState, errorState, widenButton, backLink,
} from "../core.js";

export let TITLE = "Entity";
export let DOC_TITLE = "";

const META = {
  ip: { label: "Address", back: ["/sources", "Sources"] },
  asn: { label: "Network", back: ["/sources", "Sources"] },
  credential: { label: "Credential pair", back: ["/credentials", "Credentials"] },
  hassh: { label: "Client fingerprint", back: ["/sources", "Sources"] },
  url: { label: "Fetch URL", back: ["/payloads", "Malware"] },
  day: { label: "Day", back: ["/", "Overview"] },
};

function facts(rows) {
  const keep = rows.filter(([, v]) => v !== null && v !== undefined && v !== "");
  return h("dl", { class: "facts" }, keep.flatMap(([k, v]) => [
    h("dt", { text: k }),
    h("dd", {}, [typeof v === "object" ? v : String(v)]),
  ]));
}

function ipTable(rows, empty) {
  return table(
    [{ label: "Address" }, { label: "Stage", sort: (r) => Number(r.stage || 0) },
     { label: "Network" }, { label: "Attempts", num: true },
     { label: "First seen" }, { label: "Last seen" }],
    rows,
    (r) => [
      ipLink(r.src_ip),
      r.stage !== null && r.stage !== undefined ? stageTag(r.stage) : "-",
      [entity("asn", r.asn, r.asn || "-"),
       h("div", { class: "sub2", text: place(r.org, r.country) })],
      num(r.attempts !== undefined ? r.attempts : r.events),
      dayLink(r.first_day || r.first_seen),
      dayLink(r.last_day || r.last_seen),
    ],
    empty || "No addresses recorded.");
}

function sessionsTable(rows) {
  return table(
    [{ label: "Session" }, { label: "Started" }, { label: "User" },
     { label: "Commands", num: true }, { label: "Files", num: true },
     { label: "Duration" }],
    rows,
    (r) => [
      entity("session", r.session),
      dayLink(r.first_seen),
      r.username ? h("span", { class: "mono", text: r.username }) : "-",
      num(r.commands),
      num((r.downloads || 0) + (r.uploads || 0)),
      h("span", { class: "mono sub2", text: dur(r.duration) }),
    ],
    "No sessions in this window.");
}

// ---------------------------------------------------------------------------
// per-type body builders: (d) -> [facts rows, panels]
// ---------------------------------------------------------------------------

const BODY = {
  ip(d) {
    const p = d.profile || {};
    const rel = d.related || {};
    return [
      [
        ["escalation", p.stage !== null && p.stage !== undefined ? stageTag(p.stage) : null],
        ["network", entity("asn", p.asn, p.asn || null)],
        ["operator", p.org || p.as_org],
        ["location", [p.city, p.country].filter(Boolean).join(", ") || null],
        ["sessions", num(p.sessions)],
        ["events", num(p.events)],
        ["first seen", dayLink(p.first_seen)],
        ["last seen", dayLink(p.last_seen)],
      ],
      [
        panel("Credentials tried", "Pairs this address pushed, most attempted first.", [
          table(
            [{ label: "Credential pair" }, { label: "Attempts", num: true },
             { label: "Succeeded", num: true }, { label: "First seen" }, { label: "Last seen" }],
            rel.credentials || [],
            (r) => [
              entity("credential", { username: r.username, password: r.password }),
              num(r.attempts), num(r.successes),
              dayLink(r.first_day), dayLink(r.last_day),
            ],
            "No login attempts from this address in this window."),
        ]),
        panel("Client fingerprints", "Tool signatures this address presented.", [
          table(
            [{ label: "HASSH" }, { label: "Events", num: true }, { label: "Last seen" }],
            rel.fingerprints || [],
            (r) => [
              [entity("hassh", r.hassh, mid(r.hassh, 12, 6)),
               r.known_as ? h("div", { class: "sub2", text: r.known_as }) : null],
              num(r.events), dayLink(r.last_day),
            ],
            "No key exchange recorded for this address in this window."),
        ]),
        panel("Files moved", "Lifetime, both directions.", [
          table(
            [{ label: "SHA-256" }, { label: "Direction" }, { label: "URL" },
             { label: "Sightings", num: true }, { label: "Last seen" }],
            rel.samples || [],
            (r) => [
              entity("sample", r.shasum, mid(r.shasum, 12, 6)),
              h("span", { class: "mono", text: r.direction }),
              entity("url", r.url, r.url ? mid(r.url, 28, 10) : "-"),
              num(r.sightings), dayLink(r.last_ts),
            ],
            "This address never moved a file."),
        ], { scoped: false }),
        panel("Recent commands", "Newest first, rendered as inert text.", [
          (rel.commands || []).length
            ? cmdBlock((rel.commands || []).map((c) => c.cmd).filter(Boolean).join("\n"))
            : emptyState("This address never reached a shell."),
        ], { scoped: false }),
        panel("Sessions", "Newest first.", [sessionsTable(rel.sessions || [])]),
      ],
    ];
  },

  asn(d) {
    const p = d.profile || {};
    return [
      [
        ["operator", p.org],
        ["addresses seen", num(p.addresses)],
        ["countries", p.countries],
        ["sessions", num(p.sessions)],
        ["events", num(p.events)],
        ["file transfers", num(p.transfers)],
        ["first seen", dayLink(p.first_seen)],
        ["last seen", dayLink(p.last_seen)],
      ],
      [panel("Member addresses", "Ranked by how far each one got.",
        [ipTable((d.related || {}).ips || [], "No addresses from this network on record.")],
        { scoped: false })],
    ];
  },

  credential(d) {
    const p = d.profile || {};
    return [
      [
        ["username", h("span", { class: "mono", text: p.username || "(blank)" })],
        ["password", h("span", { class: "mono", text: p.password || "(blank)" })],
        ["campaigns", (p.tags || []).length
          ? h("span", {}, (p.tags || []).map((t) => tag(t))) : null],
        ["attempts", num(p.attempts)],
        ["succeeded", num(p.successes)],
        ["distinct addresses", num(p.distinct_ips)],
        ["first seen", dayLink(p.first_seen)],
        ["last seen", dayLink(p.last_seen)],
      ],
      [panel("Addresses pushing this pair", "Lifetime of the daily rollup.",
        [ipTable((d.related || {}).ips || [], "No address is on record for this pair.")],
        { scoped: false })],
    ];
  },

  hassh(d) {
    const p = d.profile || {};
    return [
      [
        ["known as", p.known_as],
        ["signature type", p.known_kind === "library"
          ? "library default (not a cluster key)"
          : p.known_kind === "toolmark" ? "toolmark" : null],
        ["client banner", p.version ? h("span", { class: "mono", text: p.version }) : null],
        ["events", num(p.events)],
        ["sessions", num(p.sessions)],
        ["active days", num(p.active_days)],
        ["peak daily addresses", num(p.peak_daily_ips)],
        ["first seen", dayLink(p.first_seen)],
        ["last seen", dayLink(p.last_seen)],
      ],
      [
        p.known_kind === "library"
          ? h("p", { class: "persona-note", text:
              `${p.known_note || "A library default, not a toolmark."}`
              + " The addresses below share a library, which is not evidence they share"
              + " tooling or an operator." })
          : null,
        panel("Addresses presenting this fingerprint", "Lifetime of the daily rollup.",
          [ipTable((d.related || {}).ips || [], "No address is on record for this fingerprint.")],
          { scoped: false }),
      ],
    ];
  },

  url(d) {
    const p = d.profile || {};
    const rel = d.related || {};
    const bad = (d.intel || []).find((i) => i.verdict === "malicious" || i.verdict === "suspicious");
    return [
      [
        ["host", p.host ? h("span", { class: "mono", text: p.host }) : null],
        ["standing", bad ? tag(`${bad.verdict} (${bad.source})`, "bad")
          : (d.intel || []).length ? tag("no vendor flag", "") : null],
        ["family", bad && bad.label ? bad.label : null],
        ["fetches", num(p.hits)],
        ["sessions", num(p.sessions)],
        ["distinct files", num(p.distinct_hashes)],
        ["first seen", dayLink(p.first_seen)],
        ["last seen", dayLink(p.last_seen)],
      ],
      [
        panel("Files it delivered", null, [
          table(
            [{ label: "SHA-256" }, { label: "Direction" }, { label: "Filename" },
             { label: "Hits", num: true }, { label: "Last seen" }],
            rel.samples || [],
            (r) => [
              entity("sample", r.shasum, mid(r.shasum, 12, 6)),
              h("span", { class: "mono", text: r.direction }),
              h("span", { class: "mono sub2", text: r.filename ? mid(r.filename, 24, 8) : "-" }),
              num(r.hits), dayLink(r.last_seen),
            ],
            "Nothing fetched from this URL was hashed."),
        ], { scoped: false }),
        panel("Sightings", "Newest first.", [
          table(
            [{ label: "When" }, { label: "Session" }, { label: "Source" }],
            rel.sightings || [],
            (r) => [dayLink(r.ts), entity("session", r.session), ipLink(r.src_ip)],
            "No sightings recorded."),
        ], { scoped: false }),
      ],
    ];
  },

  day(d) {
    const p = d.profile || {};
    const rel = d.related || {};
    const sp = p.spike;
    return [
      [
        ["events", num(p.events)],
        ["addresses", num(p.addresses)],
        ["sessions", num(p.sessions)],
        ["commands", num(p.commands)],
        ["files moved", num((p.downloads || 0) + (p.uploads || 0))],
        ["spike", sp ? tag(`${Number(sp.ratio).toFixed(1)}x baseline`, "warn") : null],
      ],
      [
        sp && sp.headline ? h("p", { class: "takeaway" }, [sp.headline]) : null,
        panel("Sources that day", "Ranked by how far each address got.", [
          table(
            [{ label: "Address" }, { label: "Stage", sort: (r) => Number(r.stage || 0) },
             { label: "Sessions", num: true }, { label: "Commands", num: true },
             { label: "Files", num: true }, { label: "Network" }],
            rel.ips || [],
            (r) => [
              ipLink(r.src_ip), stageTag(r.stage),
              num(r.sessions), num(r.commands), num(r.transfers),
              [entity("asn", r.asn, r.asn || "-"),
               h("div", { class: "sub2", text: place(r.org, r.country) })],
            ],
            "No sources recorded on this day."),
        ], { scoped: false }),
        h("div", { class: "grid g2" }, [
          panel("Credentials that day", null, [
            table(
              [{ label: "Credential pair" }, { label: "Attempts", num: true }, { label: "Addresses", num: true }],
              rel.credentials || [],
              (r) => [
                entity("credential", { username: r.username, password: r.password }),
                num(r.attempts), num(r.src_ips),
              ],
              "No login attempts recorded."),
          ], { scoped: false }),
          panel("Files that day", null, [
            table(
              [{ label: "SHA-256" }, { label: "Direction" }, { label: "Hits", num: true }],
              rel.payloads || [],
              (r) => [
                entity("sample", r.shasum, mid(r.shasum, 12, 6)),
                h("span", { class: "mono", text: r.direction }),
                num(r.hits),
              ],
              "No files moved."),
          ], { scoped: false }),
        ]),
        panel("Sessions that moved files", null,
          [sessionsTable(rel.file_sessions || [])], { scoped: false }),
      ],
    ];
  },
};

// ---------------------------------------------------------------------------

export async function render() {
  const parts = currentPath().split("/").filter(Boolean);
  const etype = parts[0] || "";
  const raw = parts[1] || "";
  const meta = META[etype];
  TITLE = meta ? meta.label : "Page not found";
  DOC_TITLE = TITLE;
  if (!meta) {
    return pageState({ title: "There is no page at this address.",
      text: "Entity pages exist for addresses, networks, credentials, fingerprints, URLs and days." });
  }
  let shown = raw;
  try { shown = decodeURIComponent(raw); } catch (err) { /* keep it as it came */ }
  if (etype !== "credential" && etype !== "url") DOC_TITLE = `${shown} (${meta.label})`;
  let d;
  try {
    d = await api(`/api/v1/entity/${encodeURIComponent(etype)}/${encodeURIComponent(raw)}`);
  } catch (err) {
    if (err && err.status === 404) {
      return pageState({
        iconName: "search-x",
        title: `Nothing is recorded for this ${meta.label.toLowerCase()}.`,
        text: `The sensor has no record of ${etype === "credential" || etype === "url"
          ? `this ${meta.label.toLowerCase()}` : shown} in ${windowLabel()}. It may be older `
          + "than the window, or it may never have touched the sensor.",
        actions: [widenButton(), routeLink(meta.back[0], `Back to ${meta.back[1].toLowerCase()}`, "action")]
          .filter(Boolean),
      });
    }
    if (err && err.status === 400) {
      return pageState({
        iconName: "search-x",
        title: `That is not a ${meta.label.toLowerCase()} this site can look up.`,
        text: err.detail ? `The server said: ${err.detail}.` : "Check the value in the address bar.",
        actions: [routeLink(meta.back[0], `Back to ${meta.back[1].toLowerCase()}`, "action")],
      });
    }
    return errorState(err);
  }

  const p = d.profile || {};
  const display = etype === "credential"
    ? `${p.username || "(blank)"} : ${p.password || "(blank)"}`
    : etype === "url" ? (p.url || "")
    : String(d.value || decodeURIComponent(raw));
  const copyValue = etype === "credential"
    ? `${p.username || ""}:${p.password || ""}` : display;

  const [factRows, panels] = BODY[etype](d);

  // The path segment is still percent-encoded; the control encodes it again.
  let exportId = raw;
  try { exportId = decodeURIComponent(raw); } catch (err) { /* keep it as it came */ }

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      breadcrumbs() || backLink(meta.back[0], meta.back[1]),
      h("div", { class: "enthead" }, [
        h("h1", { text: display }),
        copyBtn(copyValue),
        h("span", { class: "scope", text: meta.label }),
        exportControl(etype, exportId),
      ]),
    ]),

    panel("Activity", etype === "day"
        ? "The two weeks either side, for context."
        : `Daily events, ${windowLabel()}.`,
      [spark(d.timeseries || [])], { scoped: false }),

    panel("What we know", null, [facts(factRows)], { scoped: false }),

    ...panels.filter(Boolean),
  ]);
}
