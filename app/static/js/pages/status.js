/* pages/status.js - when each part of the pipeline last ran, in Eastern time.

   The page lists times and nothing else. It does not grade them, so the
   reader compares each row against the "Checked at" time. */

import { api, h, panel, table } from "../core.js";

export const TITLE = "Pipeline status";

export async function render() {
  const d = await api("/api/v1/health", { fresh: true });
  const items = d.items || [];
  const tz = d.timezone || "Eastern time";

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("h2", { text: "When each part of the pipeline last ran" }),
      h("p", { text: `All times are ${tz}. Checked at ${d.checked_at_local || "an unknown time"}.` }),
    ]),
    panel(null, null, [
      table(
        [
          { label: "Part of the pipeline" },
          { label: "Last time", sort: (r) => r.at || "" },
          { label: "What the time records" },
        ],
        items,
        (r) => [r.label, r.at_local || "No record", r.detail],
        "No pipeline records yet.",
      ),
    ]),
    d.storage
      ? panel("Storage", "Written by the hourly prune.", [h("p", { text: d.storage })])
      : null,
  ]);
}
