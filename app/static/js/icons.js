/* icons.js - the icon set, as data.

 * Path data from Lucide (lucide-static 1.72.0), ISC licensed; some glyphs
 * descend from Feather, MIT licensed. Both notices are in
 * static/vendor/lucide-LICENSE.txt and THIRD_PARTY.md. Icons are drawn with
 * createElementNS so nothing here is markup, and they inherit currentColor so
 * they follow the text they sit beside in both themes.
 *
 * To add one: copy the child elements of icons/<name>.svg from lucide-static
 * into the table below. Keep the set small; an icon earns its place by
 * replacing a word the reader would otherwise have to parse.
 */

const ICONS = {
  "search": [["path", {"d": "m21 21-4.34-4.34"}], ["circle", {"cx": "11", "cy": "11", "r": "8"}]],
  "search-x": [["path", {"d": "m13.5 8.5-5 5"}], ["path", {"d": "m8.5 8.5 5 5"}], ["circle", {"cx": "11", "cy": "11", "r": "8"}], ["path", {"d": "m21 21-4.3-4.3"}]],
  "sun": [["circle", {"cx": "12", "cy": "12", "r": "4"}], ["path", {"d": "M12 2v2"}], ["path", {"d": "M12 20v2"}], ["path", {"d": "m4.93 4.93 1.41 1.41"}], ["path", {"d": "m17.66 17.66 1.41 1.41"}], ["path", {"d": "M2 12h2"}], ["path", {"d": "M20 12h2"}], ["path", {"d": "m6.34 17.66-1.41 1.41"}], ["path", {"d": "m19.07 4.93-1.41 1.41"}]],
  "moon": [["path", {"d": "M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401"}]],
  "sun-moon": [["path", {"d": "M12 2v2"}], ["path", {"d": "M14.837 16.385a6 6 0 1 1-7.223-7.222c.624-.147.97.66.715 1.248a4 4 0 0 0 5.26 5.259c.589-.255 1.396.09 1.248.715"}], ["path", {"d": "M16 12a4 4 0 0 0-4-4"}], ["path", {"d": "m19 5-1.256 1.256"}], ["path", {"d": "M20 12h2"}]],
  "rows-3": [["rect", {"width": "18", "height": "18", "x": "3", "y": "3", "rx": "2"}], ["path", {"d": "M21 9H3"}], ["path", {"d": "M21 15H3"}]],
  "rows-4": [["rect", {"width": "18", "height": "18", "x": "3", "y": "3", "rx": "2"}], ["path", {"d": "M21 7.5H3"}], ["path", {"d": "M21 12H3"}], ["path", {"d": "M21 16.5H3"}]],
  "copy": [["rect", {"width": "14", "height": "14", "x": "8", "y": "8", "rx": "2", "ry": "2"}], ["path", {"d": "M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"}]],
  "check": [["path", {"d": "M20 6 9 17l-5-5"}]],
  "file-down": [["path", {"d": "M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z"}], ["path", {"d": "M14 2v5a1 1 0 0 0 1 1h5"}], ["path", {"d": "M12 18v-6"}], ["path", {"d": "m9 15 3 3 3-3"}]],
  "external-link": [["path", {"d": "M15 3h6v6"}], ["path", {"d": "M10 14 21 3"}], ["path", {"d": "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"}]],
  "arrow-left": [["path", {"d": "m12 19-7-7 7-7"}], ["path", {"d": "M19 12H5"}]],
  "keyboard": [["path", {"d": "M10 8h.01"}], ["path", {"d": "M12 12h.01"}], ["path", {"d": "M14 8h.01"}], ["path", {"d": "M16 12h.01"}], ["path", {"d": "M18 8h.01"}], ["path", {"d": "M6 8h.01"}], ["path", {"d": "M7 16h10"}], ["path", {"d": "M8 12h.01"}], ["rect", {"width": "20", "height": "16", "x": "2", "y": "4", "rx": "2"}]],
  "triangle-alert": [["path", {"d": "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"}], ["path", {"d": "M12 9v4"}], ["path", {"d": "M12 17h.01"}]],
  "octagon-alert": [["path", {"d": "M12 16h.01"}], ["path", {"d": "M12 8v4"}], ["path", {"d": "M15.312 2a2 2 0 0 1 1.414.586l4.688 4.688A2 2 0 0 1 22 8.688v6.624a2 2 0 0 1-.586 1.414l-4.688 4.688a2 2 0 0 1-1.414.586H8.688a2 2 0 0 1-1.414-.586l-4.688-4.688A2 2 0 0 1 2 15.312V8.688a2 2 0 0 1 .586-1.414l4.688-4.688A2 2 0 0 1 8.688 2z"}]],
  "chevron-up": [["path", {"d": "m18 15-6-6-6 6"}]],
  "chevron-down": [["path", {"d": "m6 9 6 6 6-6"}]],
  "chevrons-up-down": [["path", {"d": "m7 15 5 5 5-5"}], ["path", {"d": "m7 9 5-5 5 5"}]],
  "trending-up": [["path", {"d": "M16 7h6v6"}], ["path", {"d": "m22 7-8.5 8.5-5-5L2 17"}]],
  "trending-down": [["path", {"d": "M16 17h6v-6"}], ["path", {"d": "m22 17-8.5-8.5-5 5L2 7"}]],
  "minus": [["path", {"d": "M5 12h14"}]],
  "refresh-cw": [["path", {"d": "M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"}], ["path", {"d": "M21 3v5h-5"}], ["path", {"d": "M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"}], ["path", {"d": "M8 16H3v5"}]],
  "compass": [["circle", {"cx": "12", "cy": "12", "r": "10"}], ["path", {"d": "m16.24 7.76-1.804 5.411a2 2 0 0 1-1.265 1.265L7.76 16.24l1.804-5.411a2 2 0 0 1 1.265-1.265z"}]],
};

const NS = "http://www.w3.org/2000/svg";

/* An inline SVG icon. Decorative by default (aria-hidden); pass a label when
   the icon is the only thing carrying the meaning. */
export function icon(name, { size = 16, label } = {}) {
  const el = document.createElementNS(NS, "svg");
  const attrs = {
    viewBox: "0 0 24 24", width: size, height: size, fill: "none",
    stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round",
    "stroke-linejoin": "round", class: `icon icon-${name}`, focusable: "false",
  };
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (label) { el.setAttribute("role", "img"); el.setAttribute("aria-label", label); }
  else el.setAttribute("aria-hidden", "true");
  for (const [tag, a] of ICONS[name] || []) {
    const child = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(a)) child.setAttribute(k, v);
    el.appendChild(child);
  }
  return el;
}
