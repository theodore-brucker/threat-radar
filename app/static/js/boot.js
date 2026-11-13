/* boot.js - the entry point.
 *
 * v3 carried this as an inline <script> in index.html, which meant the page
 * could not be served with a script-src that excludes 'unsafe-inline'. It is
 * a module now so the CSP can be strict. The only inline script left is the
 * pre-paint theme resolver, which the server pins by hash.
 */

import { wireShell, render, url, h, icon } from "./core.js";
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

/* Sensor health. A dot in the rail is not enough when every figure on the
   page is stale, so a degraded sensor also raises a bar across the top. */
fetch(url("/api/v1/health"))
  .then((r) => r.json())
  .then((b) => {
    const d = b.data || b;
    const dot = document.getElementById("health-dot");
    const txt = document.getElementById("health-text");
    dot.className = `dot ${d.status === "fault" ? "fault" : d.status === "warn" ? "stale" : "live"}`;
    txt.textContent = d.status === "fault" ? "Sensor fault"
      : d.status === "warn" ? "Data is behind" : "Sensor reporting";
    document.getElementById("coverage").textContent =
      d.last_event_day ? `Data through ${d.last_event_day}` : "";

    const bar = document.getElementById("stalebar");
    if (d.status === "ok") { bar.hidden = true; return; }
    bar.className = `stalebar ${d.status}`;
    bar.replaceChildren(h("span", {
      text: d.message || "The sensor is not reporting normally, so recent figures may be incomplete.",
    }));
    bar.hidden = false;
  })
  .catch(() => {
    const txt = document.getElementById("health-text");
    if (txt) txt.textContent = "Sensor status unavailable";
  });
