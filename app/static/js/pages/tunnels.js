/* pages/tunnels.js - what operators tried to forward through the box. */

import { api, h, num, panel, table, stats, mid, ipLink, emptyState } from "../core.js";

export const TITLE = "Relay attempts";

export async function render() {
  const d = await api("/api/v1/tunnels");
  if (!d.built) {
    return emptyState("This view has not been built yet.", {
      hint: "Run the enrichment worker once and it will populate.",
    });
  }
  const t = d.totals || {};

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("p", { text:
        "Cowrie never actually forwards anything, but it records every request. The "
        + "destination and port say what the operator wanted the box for: an open relay, "
        + "a proxy check, a mining pool, or a way into someone else's network." }),
    ]),
    stats([
      { label: "forward requests", value: num(t.requests) },
      { label: "destinations", value: num(t.destinations) },
      { label: "ports", value: num(t.ports) },
      { label: "data events", value: num(t.data_events) },
    ]),

    h("div", { class: "grid g2" }, [
      panel("Intent", "Inferred from the destination port.",
        [table([{ label: "intent" }, { label: "requests", num: true }], d.by_intent,
          (r) => [r.intent, num(r.requests)],
          "No forward requests in this window.")]),
      panel("Ports", null,
        [table(
          [{ label: "port", num: true }, { label: "service" },
           { label: "requests", num: true }, { label: "hosts", num: true }],
          d.by_port,
          (r) => [h("span", { class: "mono", text: r.dst_port }), r.service,
                  num(r.requests), num(r.destinations)],
          "No ports requested in this window.")]),
    ]),

    panel("Destinations", null,
      [table(
        [{ label: "destination" }, { label: "port", num: true }, { label: "intent" },
         { label: "requests", num: true }, { label: "sessions", num: true }, { label: "last" }],
        d.by_destination,
        (r) => [
          h("span", { class: "mono", text: r.dst_ip }),
          h("span", { class: "mono", text: r.dst_port }),
          r.intent, num(r.requests), num(r.sessions),
          h("span", { class: "mono sub2", text: r.last_day }),
        ],
        "No destinations requested in this window.")]),

    h("div", { class: "grid g2" }, [
      panel("Client fingerprints on tunnel traffic",
        "JA4H when the client spoke HTTP through the forward, which is what separates a "
        + "proxy checker from a pivot attempt.",
        [table(
          [{ label: "fingerprint" }, { label: "hits", num: true }, { label: "ips", num: true }],
          d.fingerprints,
          (r) => [h("span", { class: "mono", text: mid(r.fingerprint, 22, 8) }),
                  num(r.hits), num(r.src_ips)],
          "No HTTP was spoken through a forward in this window.")]),
      panel("Who asked", null,
        [table(
          [{ label: "source" }, { label: "requests", num: true },
           { label: "destinations", num: true }, { label: "ports", num: true }],
          d.requesters,
          (r) => [ipLink(r.src_ip), num(r.requests), num(r.destinations), num(r.ports)],
          "Nobody requested a forward in this window.")]),
    ]),
  ]);
}
