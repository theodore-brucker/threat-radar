/* pages/tunnels.js - what operators tried to forward through the box. */

import { api, h, num, panel, table, stats, mid, ipLink, emptyState } from "../core.js";

export const TITLE = "Relay attempts";

export async function render() {
  const d = await api("/api/v1/tunnels");
  if (!d.built) {
    return emptyState("Relay attempts have not been analysed yet.", {
      hint: "This page fills in after the next scheduled analysis run, which happens a "
        + "few times a day.",
    });
  }
  const t = d.totals || {};

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("p", { text:
        "Some intruders ask the server to forward their traffic somewhere else. The "
        + "sensor never forwards anything, but it records every request, and the "
        + "destination and port say what the operator wanted the machine for: an open "
        + "relay, a proxy check, a mining pool, or a way into someone else's network." }),
    ]),
    stats([
      { label: "Forward requests", value: num(t.requests) },
      { label: "Destinations", value: num(t.destinations) },
      { label: "Ports", value: num(t.ports) },
      { label: "Data events", value: num(t.data_events) },
    ]),

    h("div", { class: "grid g2" }, [
      panel("Intent", "Inferred from the destination port.",
        [table([{ label: "Intent" }, { label: "Requests", num: true }], d.by_intent,
          (r) => [r.intent, num(r.requests)],
          "No forward requests in this window.")]),
      panel("Ports", null,
        [table(
          [{ label: "Port", num: true }, { label: "Service" },
           { label: "Requests", num: true }, { label: "Hosts", num: true }],
          d.by_port,
          (r) => [h("span", { class: "mono", text: r.dst_port }), r.service,
                  num(r.requests), num(r.destinations)],
          "No ports requested in this window.")]),
    ]),

    panel("Destinations", null,
      [table(
        [{ label: "Destination" }, { label: "Port", num: true }, { label: "Intent" },
         { label: "Requests", num: true }, { label: "Sessions", num: true }, { label: "Last seen" }],
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
          [{ label: "Fingerprint" }, { label: "Hits", num: true }, { label: "Addresses", num: true }],
          d.fingerprints,
          (r) => [h("span", { class: "mono", text: mid(r.fingerprint, 22, 8) }),
                  num(r.hits), num(r.src_ips)],
          "No HTTP was spoken through a forward in this window.")]),
      panel("Who asked", null,
        [table(
          [{ label: "Source" }, { label: "Requests", num: true },
           { label: "Destinations", num: true }, { label: "Ports", num: true }],
          d.requesters,
          (r) => [ipLink(r.src_ip), num(r.requests), num(r.destinations), num(r.ports)],
          "Nobody requested a forward in this window.")]),
    ]),
  ]);
}
