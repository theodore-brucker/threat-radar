/* keys.js - the keyboard layer.
 *
 * The bindings a practitioner reaches for without being told: "/" for search,
 * "?" for the sheet, digits for sections, and single letters for the controls
 * that are otherwise a mouse trip to the top right. Nothing fires while a
 * text field has focus, and nothing fires with a modifier held, so browser
 * and screen reader shortcuts are untouched.
 */

import { h, navigate, setMode, setDays, setDensity, state, clearCache, render } from "./core.js";
import { cycleTheme } from "./theme.js";

const SECTIONS = ["/", "/sources", "/credentials", "/payloads", "/sessions", "/tunnels", "/method"];

const HELP = [
  ["/", "focus the search box"],
  ["? ", "this list"],
  ["1 - 7", "jump to a section"],
  ["e / a", "executive or analyst view"],
  ["w", "cycle the time window"],
  ["d", "compact or roomy rows"],
  ["t", "cycle the colour theme"],
  ["j / k", "move down or up a table, once it has focus"],
  ["Enter", "open the focused row"],
  ["Esc", "close whatever is open"],
];

let sheet = null;

function helpSheet() {
  if (sheet) return sheet;
  const dl = h("dl", {}, HELP.flatMap(([k, v]) => [
    h("dt", {}, [h("kbd", { text: k.trim() })]),
    h("dd", { text: v }),
  ]));
  sheet = h("dialog", { class: "sheet", "aria-label": "keyboard shortcuts" }, [
    h("h2", { text: "Keyboard" }),
    dl,
    h("button", { type: "button", text: "Close", onclick: () => sheet.close() }),
  ]);
  document.body.appendChild(sheet);
  return sheet;
}

function typing() {
  const el = document.activeElement;
  if (!el) return false;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
}

const WINDOWS = [1, 7, 14, 30, 90, 3650];

function cycleWindow() {
  const i = WINDOWS.indexOf(state.days);
  const next = WINDOWS[(i + 1) % WINDOWS.length];
  setDays(next);
  const sel = document.getElementById("window-select");
  if (sel) sel.value = String(next);
  clearCache();
  render();
}

export function mountKeys() {
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (sheet && sheet.open) sheet.close();
      return;
    }
    if (typing() || e.ctrlKey || e.metaKey || e.altKey) return;

    if (e.key === "?") { e.preventDefault(); helpSheet().showModal(); return; }

    const n = Number(e.key);
    if (n >= 1 && n <= SECTIONS.length) { e.preventDefault(); navigate(SECTIONS[n - 1]); return; }

    switch (e.key) {
      case "e": setMode("exec"); syncMode(); render(); break;
      case "a": setMode("analyst"); syncMode(); render(); break;
      case "w": cycleWindow(); break;
      case "d": setDensity(state.density === "compact" ? "comfortable" : "compact"); break;
      case "t": cycleTheme(); break;
      default: break;
    }
  });
}

function syncMode() {
  document.querySelectorAll(".modeswitch button").forEach((x) =>
    x.setAttribute("aria-pressed", String(x.dataset.mode === state.mode)));
}
