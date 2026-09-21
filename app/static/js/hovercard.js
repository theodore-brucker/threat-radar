/* hovercard.js - preview an entity before committing to the click.

   After each render the page collects every entity link it drew and asks for
   all their summaries in one request, so hovering costs nothing. Cards are
   cached for the life of the page and keyed the same way the API returns
   them, so a second page that reuses an address does not refetch it.

   Every card value came from an attacker at some point and goes in through
   textContent. */

import { h, num, url } from "./core.js";

const cache = new Map();     // "type:value" -> card | null (null = no card)
const DELAY = 220;           // long enough that passing over a table is quiet

let layer = null;
let timer = null;
let current = null;

function ensureLayer() {
  if (layer) return layer;
  layer = h("div", { class: "hovercard", hidden: "hidden" });
  document.body.appendChild(layer);
  return layer;
}

function hide() {
  clearTimeout(timer);
  current = null;
  if (layer) { layer.hidden = true; layer.replaceChildren(); }
}

function place(anchor) {
  const r = anchor.getBoundingClientRect();
  const el = ensureLayer();
  el.hidden = false;
  // Measure after making it visible, then flip if it would run off screen.
  const w = el.offsetWidth;
  const hgt = el.offsetHeight;
  let left = r.left + window.scrollX;
  let top = r.bottom + window.scrollY + 6;
  if (left + w > window.scrollX + document.documentElement.clientWidth - 12) {
    left = window.scrollX + document.documentElement.clientWidth - w - 12;
  }
  if (r.bottom + hgt + 20 > document.documentElement.clientHeight) {
    top = r.top + window.scrollY - hgt - 6;   // flip above
  }
  el.style.left = `${Math.max(8, left)}px`;
  el.style.top = `${Math.max(8, top)}px`;
}

function paint(card, anchor) {
  const el = ensureLayer();
  el.replaceChildren(
    h("div", { class: `hc-head ${card.tone || ""}` }, [
      h("div", { class: "hc-title mono", text: card.title }),
      card.sub ? h("div", { class: "hc-sub", text: card.sub }) : null,
    ]),
    h("dl", { class: "hc-facts" }, (card.facts || []).flatMap(([k, v]) => [
      h("dt", { text: k }),
      h("dd", { class: "mono", text: typeof v === "number" ? num(v) : String(v) }),
    ])),
  );
  place(anchor);
}

/* Fetch the cards for every entity on the page, in batches. One request for
   a large page can pass the 16 KB body limit nginx enforces, and a refused
   request used to leave every card on the page empty. Anything the API does
   not return is cached as null so it is never asked for again. */
const CARD_BATCH = 100;

async function warmBatch(batch) {
  const items = batch.map((k) => {
    const i = k.indexOf(":");
    return { type: k.slice(0, i), value: k.slice(i + 1) };
  });
  try {
    const res = await fetch(url("/api/v1/cards"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ items }),
    });
    if (!res.ok) throw new Error(res.status);
    const body = await res.json();
    const got = ((body.data || body).cards) || {};
    for (const k of batch) cache.set(k, got[k] || null);
  } catch (err) {
    // No cards is a degraded page, not a broken one: links still work.
    for (const k of batch) cache.set(k, null);
  }
}

async function warm(keys) {
  const missing = keys.filter((k) => !cache.has(k));
  if (!missing.length) return;
  for (let i = 0; i < missing.length; i += CARD_BATCH) {
    await warmBatch(missing.slice(i, i + CARD_BATCH));
  }
  // A card may have arrived while its link was already being hovered.
  if (current && cache.get(current.key)) paint(cache.get(current.key), current.el);
}

/* Called after every render. */
export function warmView(root) {
  const scope = root || document.getElementById("view");
  if (!scope) return;
  const keys = [...new Set([...scope.querySelectorAll("a[data-ent]")]
    .map((a) => a.dataset.ent))];
  if (keys.length) warm(keys);
}

export function mountHovercards() {
  document.addEventListener("mouseover", (e) => {
    const a = e.target.closest && e.target.closest("a[data-ent]");
    if (!a) return;
    const key = a.dataset.ent;
    clearTimeout(timer);
    timer = setTimeout(() => {
      const card = cache.get(key);
      current = { key, el: a };
      if (card) paint(card, a);
      else if (!cache.has(key)) warm([key]);   // a link drawn after the warm pass
    }, DELAY);
  });

  document.addEventListener("mouseout", (e) => {
    const a = e.target.closest && e.target.closest("a[data-ent]");
    if (a) hide();
  });

  // Anything that moves the page out from under the card dismisses it.
  window.addEventListener("scroll", hide, { passive: true });
  window.addEventListener("popstate", hide);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });
}
