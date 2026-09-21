/* pages/method.js - the page that does the portfolio work. Static prose plus
   live coverage numbers, so it never goes stale.

   The prose here is a factual claim about the system and is worth re-reading
   against the deployment whenever either changes. See the upgrade note. */

import { api, h, panel, shortDate } from "../core.js";

export const TITLE = "Method";

const P = (t) => h("p", { text: t });

export async function render() {
  const meta = await api("/api/v1/meta");
  const cov = meta.coverage || {};
  const w = meta.worker || {};

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("h2", { text: "How this works, and what it does not claim." }),
      P("A single Cowrie SSH honeypot runs on a public VPS with a custom persona: "
        + "hostname, banner, filesystem, hardware output, and a credential set seeded "
        + "from what attackers actually try. A stock Cowrie install is fingerprinted "
        + "and skipped by a lot of commodity tooling, so the persona is what keeps the "
        + "sensor worth interacting with."),
      P("Logs ship to a Raspberry Pi over Tailscale every two minutes. The Pi parses them "
        + "into SQLite, enriches source addresses with geo and ASN data, and a worker "
        + "rebuilds the derived tables this site reads. No page here queries the raw event "
        + "table, which is why a million-row dataset renders instantly on a single-board "
        + "computer."),
    ]),

    h("div", { class: "grid g2" }, [
      panel("Pipeline", null, [
        P("Sensor: Cowrie on a dedicated VPS, inbound limited to SSH, log rotation on a timer."),
        P("Transport: pull model over Tailscale against a forced-command key, so the sensor "
          + "holds no credentials for the Pi. The honeypot process on the sensor cannot reach "
          + "the tailnet at all, and the dashboard refuses the sensor's address."),
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
          + "variations of one theme read as one theme instead of a hundred rows. A theme "
          + "is a shared shape, not evidence of a shared operator."),
        P("Abuse scoring: networks are ranked on volume share, single-address "
          + "concentration, per-address intensity, and whether traffic reached a shell."),
        P("Spike breakdown: detection uses a rolling median with median absolute "
          + "deviation, because a multi-day surge inflates its own standard deviation "
          + "enough to hide itself."),
      ]),
    ]),

    panel("Limitations", "Stated plainly, because a dashboard that hides them is marketing.", [
      P("Login success counts are not a compromise metric. The credential file accepts what "
        + "attackers offer by design, so a successful login means the sensor let them in, "
        + "not that a real system was breached."),
      P("Geolocation of an attacking address identifies infrastructure, not an operator. "
        + "Most of what appears here is rented, compromised, or proxied."),
      P("This is one sensor on one address. It measures what finds it, which is untargeted "
        + "internet-wide scanning plus whatever the persona attracts. It is not a survey of "
        + "threats to any particular industry or sector."),
      P("Flagged malware means at least one VirusTotal engine called the sample "
        + "malicious or suspicious, or URLhaus lists it. That is a signal worth acting "
        + "on and worth submitting, not a confirmation, and a single engine can be wrong."),
      P("Reputation verdicts come from free-tier APIs with per-day caps, so a recently "
        + "captured sample may sit at unknown for a cycle before it is looked up."),
      P("The persona changed during the period covered here. Figures either side of the "
        + "marked boundary on the activity chart describe different offered hosts and "
        + "should not be trended against each other."),
    ]),

    panel("Data currency", null, [
      h("p", { class: "mono sub2", text:
        `coverage ${cov.first_day || "?"} to ${cov.last_day || "?"} \u00b7 `
        + `worker last run ${shortDate(w.last_run) || "never"} \u00b7 `
        + `facts ${shortDate(w.facts_built_at)} \u00b7 intel ${shortDate(w.intel_built_at)} \u00b7 `
        + `submissions ${shortDate(w.submissions_built_at)}` }),
    ], { scoped: false }),
  ]);
}
