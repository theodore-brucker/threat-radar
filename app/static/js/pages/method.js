/* pages/method.js - the page that does the portfolio work. Static prose plus
   live coverage numbers, so it never goes stale.

   The prose here is a factual claim about the system and is worth re-reading
   against the deployment whenever either changes. See the upgrade note. */

import { api, h, panel, shortDate } from "../core.js";

const when = (v) => (v ? `${shortDate(v)} UTC` : "Not yet");

export const TITLE = "Method";

const P = (t) => h("p", { text: t });

export async function render() {
  const meta = await api("/api/v1/meta");
  const cov = meta.coverage || {};
  const w = meta.worker || {};

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("h2", { text: "How this works, and what it does not claim" }),
      P("A single Cowrie SSH honeypot runs on a public VPS with a custom persona: its "
        + "own hostname, banner, filesystem and hardware output, and a list of accepted "
        + "passwords taken from what attackers have tried before. Much commodity tooling "
        + "recognises a stock Cowrie install and disconnects, so the persona keeps those "
        + "tools talking to the sensor for longer."),
      P("Logs ship to a Raspberry Pi over Tailscale on a short timer. The Pi parses them "
        + "into SQLite, enriches source addresses with geo and ASN data, and a worker "
        + "rebuilds the summary tables this site reads. Pages read those summaries and "
        + "never scan the raw event table, so they load quickly on a Raspberry Pi with "
        + "over a million events stored."),
    ]),

    h("div", { class: "grid g2" }, [
      panel("Pipeline", null, [
        P("Sensor: Cowrie on a dedicated VPS, inbound limited to SSH, log rotation on a timer."),
        P("Transport: pull model over Tailscale against a forced-command key, so the sensor "
          + "holds no credentials for the Pi. Firewall rules stop the honeypot process from "
          + "reaching the tailnet, and nginx on the Pi rejects requests from the sensor's address."),
        P("Store: SQLite with WAL, deduplicated on a line hash so a re-pulled log never "
          + "double counts."),
        P("Enrich: geo and ASN per address, VirusTotal and URLhaus per sample, both rate "
          + "limited and cached with a TTL against a free tier."),
        P("Serve: FastAPI behind nginx. The dashboard opens the database "
          + "read-only; ingestion, enrichment and pruning are the only writers."),
      ]),
      panel("Analysis", null, [
        P("Escalation stage: every source is reduced to the furthest point it reached, "
          + "which is what colours the map and filters the tables."),
        P("Credential themes: credential pairs are tagged by rule, so a hundred "
          + "variations on one theme appear as one row. Two pairs in the same theme look "
          + "alike; that alone does not mean one operator sent both."),
        P("Abuse scoring: networks are ranked on volume share, single-address "
          + "concentration, per-address intensity, and whether traffic reached a shell."),
        P("Spike breakdown: detection uses a rolling median with median absolute "
          + "deviation, because a multi-day surge inflates its own standard deviation "
          + "enough to hide itself."),
      ]),
    ]),

    panel("Limitations", "What these numbers can and cannot support.", [
      P("A successful login does not mean a compromise. The sensor accepts a fixed list "
        + "of common passwords, so a successful login means the sensor let someone in, "
        + "and no real system was involved."),
      P("Geolocation of an attacking address identifies infrastructure, not an operator. "
        + "Most of what appears here is rented, compromised, or proxied."),
      P("This is one sensor on one address. It measures what finds it, which is untargeted "
        + "internet-wide scanning plus whatever the persona attracts. It is not a survey of "
        + "threats to any particular industry or sector."),
      P("Flagged malware means at least one VirusTotal engine called the sample "
        + "malicious or suspicious, or URLhaus lists it. One engine can be wrong, so "
        + "treat a flag as a reason to look closer."),
      P("Reputation verdicts come from free-tier APIs with per-day caps, so a recently "
        + "captured sample may sit at unknown for a cycle before it is looked up."),
      P("The persona changed during the period covered here. Figures either side of the "
        + "marked boundary on the activity chart describe different offered hosts and "
        + "should not be trended against each other."),
    ]),

    panel("How fresh this is", "When each part of the pipeline last ran.", [
      h("dl", { class: "facts" }, [
        ["Data covers", cov.first_day && cov.last_day ? `${cov.first_day} to ${cov.last_day}` : "No data yet"],
        ["Analysis last ran", when(w.last_run)],
        ["Daily facts rebuilt", when(w.facts_built_at)],
        ["Reputation lookups", when(w.intel_built_at)],
        ["Upstream submissions", when(w.submissions_built_at)],
      ].flatMap(([k, v]) => [h("dt", { text: k }), h("dd", { text: v })])),
    ]),
  ]);
}
