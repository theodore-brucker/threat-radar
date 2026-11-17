/* pages/trend_entity.js - one incident, supplier or organization from the
 * incident trends section, with its sources and an export for an AI model. */

import {
  api, h, num, panel, table, routeLink, backLink, breadcrumbs, currentPath, exportControl,
  pageState, errorState, shortDate,
} from "../core.js";
import { statusTag, incidentTable } from "./trends.js";

export let TITLE = "Incident";
export let DOC_TITLE = "";

const META = {
  incident: { label: "Incident" },
  vendor: { label: "Supplier" },
  organization: { label: "Organization" },
};

function facts(rows) {
  const keep = rows.filter(([, v]) => v !== null && v !== undefined && v !== "");
  return h("dl", { class: "facts" }, keep.flatMap(([k, v]) => [
    h("dt", { text: k }),
    h("dd", {}, [typeof v === "object" ? v : String(v)]),
  ]));
}

function outLink(href, label) {
  return href ? h("a", { href, target: "_blank", rel: "noreferrer noopener", text: label }) : label;
}

function sourceText(source) {
  return source === "seed" ? "Seed file (DysruptionHub registry)" : source;
}

function incidentBody(d) {
  const factRows = [
    ["Started", shortDate(d.started)],
    ["Kind", d.kind === "national" ? "National outage" : d.kind === "vendor" ? "Supplier outage" : "Organization"],
    ["Organization", d.org_slug ? routeLink(`/organization/${d.org_slug}`, d.org_name, "plain") : null],
    ["Sector", d.sector], ["State", d.state], ["Scope", d.scope],
    ["Cause status", statusTag(d.cause_status)],
    ["Days to first stated cause", d.delay ? num(d.delay.days) : null],
    ["Source", outLink(d.source_url, sourceText(d.source))],
    ["Confidence", d.confidence],
  ];
  const panels = [
    panel("Statements", "What sources said about the cause, oldest first.",
      [table([{ label: "Stated" }, { label: "Cause status" }, { label: "Text" }, { label: "Source" }],
        d.statements || [],
        (s) => [s.stated_at ? shortDate(s.stated_at) : "Undated", statusTag(s.cause_status),
          s.text || "-", outLink(s.url, sourceText(s.source))],
        "No statement about a cause has been recorded.")]),
  ];
  if ((d.vendors || []).length) {
    panels.push(panel("Suppliers", null, [table(
      [{ label: "Supplier" }, { label: "Product" }, { label: "Customers", num: true }, { label: "Note" }],
      d.vendors,
      (v) => [routeLink(`/vendor/${v.slug}`, v.name, "plain"), v.product || "-",
        v.customers === null ? "-" : num(v.customers), v.note || "-"])]));
  }
  if ((d.cves || []).length) {
    panels.push(panel("Known exploited vulnerabilities", "From the CISA KEV catalog.", [table(
      [{ label: "CVE" }, { label: "Vendor" }, { label: "Product" }, { label: "Added" }],
      d.cves,
      (c) => [h("span", { class: "mono", text: c.cve_id }), c.vendor || "-", c.product || "-",
        shortDate(c.kev_added)])]));
  }
  if ((d.claims || []).length) {
    panels.push(panel("Leak-site claims", "Source: Ransomware.live. Group and link only.", [table(
      [{ label: "Group" }, { label: "Discovered" }, { label: "Post" }],
      d.claims,
      (c) => [c.actor, shortDate(c.discovered), outLink(c.post_url, "Open on Ransomware.live")])]));
  }
  return [d.title, factRows, panels];
}

function listBody(d, label) {
  const factRows = [["Product", d.product], ["Sector", d.sector], ["State", d.state],
    ["Incidents", num((d.incidents || []).length)]];
  return [d.name, factRows,
    [panel("Incidents", `Every incident recorded for this ${label.toLowerCase()}.`,
      [incidentTable(d.incidents || [])])]];
}

export async function render() {
  const parts = currentPath().split("/").filter(Boolean);
  const etype = parts[0] || "";
  let raw = parts[1] || "";
  try { raw = decodeURIComponent(raw); } catch (err) { /* keep it as it came */ }
  const meta = META[etype];
  TITLE = meta ? meta.label : "Page not found";
  DOC_TITLE = TITLE;
  let d;
  try {
    d = await api(`/api/v1/trends/${etype}/${encodeURIComponent(raw)}`);
  } catch (err) {
    if (err && (err.status === 404 || err.status === 400)) {
      return pageState({
        iconName: "search-x",
        title: `No ${meta.label.toLowerCase()} is recorded under this address.`,
        text: err.detail ? `The server said: ${err.detail}.` : "Check the value in the address bar.",
        actions: [routeLink("/trends", "Back to incident trends", "action")],
      });
    }
    return errorState(err);
  }
  const [title, factRows, panels] = etype === "incident" ? incidentBody(d) : listBody(d, meta.label);
  DOC_TITLE = `${title} (${meta.label})`;
  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      breadcrumbs() || backLink("/trends", "Incident trends"),
      h("div", { class: "enthead" }, [
        h("h1", { text: title }),
        h("span", { class: "scope", text: meta.label }),
        exportControl(etype, raw, "/api/v1/trends/export"),
      ]),
    ]),
    panel("What we know", null, [facts(factRows)]),
    ...panels,
  ]);
}
