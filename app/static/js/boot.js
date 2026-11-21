/* boot.js - the entry point.
 *
 * A module, so the content security policy can exclude 'unsafe-inline'. The
 * only inline script in the page is the pre-paint theme resolver, which the
 * server allows by hash.
 */

import { wireShell, render, url } from "./core.js";
import { mountOmnibar } from "./omnibar.js";
import { mountHovercards } from "./hovercard.js";
import { mountTheme } from "./theme.js";
import { mountKeys } from "./keys.js";

wireShell();
mountTheme();
mountOmnibar();
mountHovercards();
mountKeys();
render();

/* The rail footer states when the newest event arrived, in Eastern time. The
   status page has the same for every other stage. */
fetch(url("/api/v1/health"))
  .then((r) => r.json())
  .then((b) => {
    const d = b.data || b;
    const newest = (d.items || []).find((i) => i.key === "events");
    document.getElementById("last-event").textContent =
      `Newest event: ${(newest && newest.at_local) || "none recorded"}`;
  })
  .catch(() => {
    const el = document.getElementById("last-event");
    if (el) el.textContent = "Pipeline status unavailable";
  });
