/* theme.js - light, dark, or follow the system.
 *
 * The dark palette is a second measured ramp rather than an inversion: see
 * the contrast table at the top of tokens.css. The initial resolution happens
 * in a tiny inline script in the document head so a dark-mode reader never
 * sees a white flash; this module only handles switching after load.
 */

import { icon } from "./icons.js";

const ORDER = ["auto", "light", "dark"];
const NAMES = { auto: "follow the system", light: "light", dark: "dark" };
const ICON = { auto: "sun-moon", light: "sun", dark: "moon" };
const KEY = "tr.theme";

function stored() {
  try { return localStorage.getItem(KEY) || "auto"; } catch (e) { return "auto"; }
}

function systemDark() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function applyTheme(pref) {
  const dark = pref === "dark" || (pref === "auto" && systemDark());
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  const btn = document.getElementById("theme-toggle");
  if (btn) {
    const next = ORDER[(ORDER.indexOf(pref) + 1) % ORDER.length];
    const label = `Colour theme: ${NAMES[pref]}${pref === "auto" ? ` (${dark ? "dark" : "light"} now)` : ""}. `
      + `Switch to ${NAMES[next]} (t)`;
    btn.replaceChildren(icon(ICON[pref] || "sun-moon"));
    btn.setAttribute("aria-label", label);
    btn.setAttribute("title", label);
  }
}

export function cycleTheme() {
  const next = ORDER[(ORDER.indexOf(stored()) + 1) % ORDER.length];
  try { localStorage.setItem(KEY, next); } catch (e) { /* storage blocked */ }
  applyTheme(next);
}

export function mountTheme() {
  applyTheme(stored());
  const btn = document.getElementById("theme-toggle");
  if (btn) btn.addEventListener("click", cycleTheme);
  if (window.matchMedia) {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => { if (stored() === "auto") applyTheme("auto"); };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }
}
