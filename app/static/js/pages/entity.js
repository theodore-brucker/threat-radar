/* pages/entity.js - one page for every entity type.

   /ip, /asn, /credential, /hassh, /url and /day all land here. The API
   returns one shape (profile, timeseries, related) and this module renders
   it: identity header, activity sparkline, facts, then related-entity panels
   where every value is itself a link. Every value originated with an attacker
   and reaches the DOM through textContent only.

   v3 dropped a panel entirely when its related list was empty, so two
   addresses produced pages of different shapes and a reader could not tell
   "nothing recorded" from "this page does not show that". Every panel is
   always present now and says which of the two it is. */

import {
  api, h, num, panel, table, tag, mid, dur, entity, ipLink, dayLink, copyBtn,
  spark, stageTag, windowLabel, breadcrumbs, routeLink, cmdBlock, emptyState,
  currentPath,
} from "../core.js";

export let TITLE = "Entity";

const META = {
  ip: { label: "Address", back: ["/sources", "back to sources"] },
  asn: { label: "Network", back: ["/sources", "back to sources"] },
  credential: { label: "Credential pair", back: ["/credentials", "back to credentials"] },
  hassh: { label: "Client fingerprint", back: ["/sources", "back to sources"] },
  url: { label: "Fetch URL", back: ["/payloads", "back to malware"] },
  day: { label: "Day", back: ["/", "back to overview"] },
};

function facts(rows) {
  const keep = rows.filter(([, v]) => v !== null && v !== undefined && v !== "");
  return h("dl", { class: "facts" }, keep.flatMap(([k, v]) => [
    h("dt", { text: k }),
    h("dd", { class: "mono" }, [typeof v === "object" ? v : String(v)]),
  ]));
}

function ipTable(rows, empty) {
  return table(
    [{ label: "address" }, { label: "stage", sort: (r) => Number(r.stage || 0) },
     { label: "network" }, { label: "attempts", num: true },
     { label: "first" }, { label: "last" }],
    rows,
    (r) => [
      ipLink(r.src_ip),
      r.stage !== null && r.stage !== undefined ? stageTag(r.stage) : "-",
      [entity("asn", r.asn, r.asn || "-"),
       h("div", { class: "sub2", text: [r.org, r.country].filter(Boolean).join(" \u00b7 ") })],
      num(r.attempts !== undefined ? r.attempts : r.events),
      dayLink(r.first_day || r.first_seen),
      dayLink(r.last_day || r.last_seen),
    ],
    empty || "No addresses recorded.");
}

function sessionsTable(rows) {
  return table(
    [{ label: "session" }, { label: "started" }, { label: "user" },
     { label: "cmds", num: true }, { label: "files", num: true },
     { label: "duration" }],
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
            [{ label: "pair" }, { label: "attempts", num: true },
             { label: "succeeded", num: true }, { label: "first" }, { label: "last" }],
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
            [{ label: "hassh" }, { label: "events", num: true }, { label: "last" }],
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
            [{ label: "sha256" }, { label: "dir" }, { label: "url" },
             { label: "sightings", num: true }, { label: "last" }],
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
        ["username", p.username || "(blank)"],
        ["password", p.password || "(blank)"],
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
        ["client banner", p.version],
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
        ["host", p.host],
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
            [{ label: "sha256" }, { label: "dir" }, { label: "filename" },
             { label: "hits", num: true }, { label: "last" }],
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
            [{ label: "when" }, { label: "session" }, { label: "source" }],
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
            [{ label: "address" }, { label: "stage", sort: (r) => Number(r.stage || 0) },
             { label: "sessions", num: true }, { label: "cmds", num: true },
             { label: "files", num: true }, { label: "network" }],
            rel.ips || [],
            (r) => [
              ipLink(r.src_ip), stageTag(r.stage),
              num(r.sessions), num(r.commands), num(r.transfers),
              [entity("asn", r.asn, r.asn || "-"),
               h("div", { class: "sub2", text: [r.org, r.country].filter(Boolean).join(" \u00b7 ") })],
            ],
            "No sources recorded on this day."),
        ], { scoped: false }),
        h("div", { class: "grid g2" }, [
          panel("Credentials that day", null, [
            table(
              [{ label: "pair" }, { label: "attempts", num: true }, { label: "ips", num: true }],
              rel.credentials || [],
              (r) => [
                entity("credential", { username: r.username, password: r.password }),
                num(r.attempts), num(r.src_ips),
              ],
              "No login attempts recorded."),
          ], { scoped: false }),
          panel("Files that day", null, [
            table(
              [{ label: "sha256" }, { label: "dir" }, { label: "hits", num: true }],
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
  if (!meta) return emptyState("Unknown entity type.");
  TITLE = meta.label;

  let d;
  try {
    d = await api(`/api/v1/entity/${encodeURIComponent(etype)}/${encodeURIComponent(raw)}`);
  } catch (err) {
    return emptyState(`Nothing recorded for this ${meta.label.toLowerCase()}.`, {
      hint: "It may be outside the current window, or it may never have been seen.",
      widen: true,
    });
  }

  const p = d.profile || {};
  const display = etype === "credential"
    ? `${p.username || "(blank)"} : ${p.password || "(blank)"}`
    : etype === "url" ? (p.url || "")
    : String(d.value || decodeURIComponent(raw));
  const copyValue = etype === "credential"
    ? `${p.username || ""}:${p.password || ""}` : display;

  const [factRows, panels] = BODY[etype](d);

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      breadcrumbs(),
      h("p", {}, [routeLink(meta.back[0], meta.back[1], "")]),
      h("div", { class: "enthead" }, [
        h("h1", { text: display }),
        copyBtn(copyValue),
        h("span", { class: "scope", text: meta.label }),
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
