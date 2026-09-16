/* boot.js - the entry point.
 *
 * v3 carried this as an inline <script> in index.html, which meant the page
 * could not be served with a script-src that excludes 'unsafe-inline'. It is
 * a module now so the CSP can be strict. The only inline script left is the
 * pre-paint theme resolver, which the server pins by hash.
 */

import { wireShell, render, url, h } from "./core.js";
import { mountChat } from "./chat.js";
import { mountOmnibar } from "./omnibar.js";
import { mountHovercards } from "./hovercard.js";
import { mountTheme } from "./theme.js";
import { mountKeys } from "./keys.js";

wireShell();
mountTheme();
mountChat();
mountOmnibar();
mountHovercards();
mountKeys();
render();

/* Sensor health. A dot in the rail is not enough when every figure on the
   page is stale, so a degraded sensor also raises a bar under the marking. */
fetch(url("/api/v1/health"))
  .then((r) => r.json())
  .then((b) => {
    const d = b.data || b;
    const dot = document.getElementById("health-dot");
    const txt = document.getElementById("health-text");
    dot.className = `dot ${d.status === "fault" ? "fault" : d.status === "warn" ? "stale" : "live"}`;
    txt.textContent = d.status === "fault" ? "sensor fault"
      : d.status === "warn" ? "data behind" : "sensor healthy";
    document.getElementById("coverage").textContent =
      d.last_event_day ? `through ${d.last_event_day}` : "";

    const bar = document.getElementById("stalebar");
    if (d.status === "ok") { bar.hidden = true; return; }
    bar.className = `stalebar ${d.status}`;
    bar.replaceChildren(h("span", { text: d.message || "Sensor health is degraded." }));
    bar.hidden = false;
  })
  .catch(() => {
    const txt = document.getElementById("health-text");
    if (txt) txt.textContent = "health unknown";
  });
