/* omnibar.js - one box, any indicator.
 *
 * Paste an address, a hash, a credential, an AS number or a date and land on
 * its entity page. Exact shapes resolve on the client with no round trip;
 * anything ambiguous goes to /api/v1/lookup for candidates.
 *
 * Every suggestion label came from an attacker at some point, so the whole
 * dropdown is built through h() and textContent.
 */

import { h, navigate, entityHref, mid, url } from "./core.js";

const SHA256 = /^[0-9a-f]{64}$/i;
const HASSH = /^[0-9a-f]{32}$/i;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]{3,45}$/i;
const ASN = /^as\s?\d{1,10}$/i;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const URLISH = /^(https?:\/\/|[a-z0-9.-]+\.[a-z]{2,}\/)/i;
const CREDPAIR = /^([^\s:]+):([^\s:]*)$/;

/* A shape the client can resolve alone. Returns an app route, or null. */
export function resolveExact(raw) {
  const q = (raw || "").trim();
  if (!q) return null;
  if (SHA256.test(q)) return `/sample/${q.toLowerCase()}`;
  if (DAY.test(q)) return `/day/${q}`;
  if (ASN.test(q)) return `/asn/AS${q.replace(/\D/g, "")}`;
  if (IPV4.test(q)) {
    // reject 999.1.1.1 rather than routing to a page that cannot exist
    if (q.split(".").every((o) => Number(o) <= 255)) return `/ip/${q}`;
    return null;
  }
  if (HASSH.test(q)) return `/hassh/${q.toLowerCase()}`;
  if (q.includes(":") && IPV6.test(q) && !CREDPAIR.test(q)) return `/ip/${q}`;
  if (URLISH.test(q)) return entityHref("url", q);
  const cred = CREDPAIR.exec(q);
  if (cred) return entityHref("credential", { username: cred[1], password: cred[2] });
  return null;
}

function kindLabel(t) {
  return {
    ip: "Address", asn: "Network", credential: "Credential", url: "URL",
    session: "Session", sample: "Sample", hassh: "Fingerprint", day: "Day",
  }[t] || t;
}

export function mountOmnibar() {
  const input = document.getElementById("omnibar");
  const drop = document.getElementById("omnibar-results");
  if (!input || !drop) return;

  let items = [];       // [{path, label, sub, kind}]
  let cursor = -1;
  let seq = 0;          // guards against a slow response overwriting a fast one

  const close = () => {
    drop.replaceChildren();
    drop.hidden = true;
    input.setAttribute("aria-expanded", "false");
    items = [];
    cursor = -1;
  };

  const go = (path) => {
    close();
    input.value = "";
    input.blur();
    navigate(path);
  };

  /* One delegated listener, wired once. Per-item handlers died with the
     element whenever the list repainted, which is what made clicks miss. */
  drop.addEventListener("mousedown", (e) => {
    const li = e.target.closest("li[data-i]");
    if (!li) return;
    e.preventDefault();               // keep the input from blurring first
    const it = items[Number(li.dataset.i)];
    if (it) go(it.path);
  });

  /* No match is an answer too: say so, and say what the box understands,
     rather than leaving the reader wondering whether the search ran. */
  const paint = (q, failed = false) => {
    if (!items.length) {
      const shown = q.trim().length > 40 ? mid(q.trim(), 24, 12) : q.trim();
      drop.replaceChildren(h("li", { class: "omni-none", role: "option", "aria-disabled": "true" }, failed
        ? [h("b", { text: "Search is not answering right now." }),
           "A complete address, hash or date still opens its page when you press Enter."]
        : [h("b", { text: `No match for ${shown}` }),
           "Try a full address, a 64-character sha256, user:pass, an AS number such as "
             + "AS14061, or a date such as 2026-11-01."]));
      drop.hidden = false;
      input.setAttribute("aria-expanded", "true");
      return;
    }
    drop.replaceChildren(...items.map((it, i) =>
      h("li", {
        class: i === cursor ? "omni-item sel" : "omni-item", "data-i": String(i),
        role: "option", "aria-selected": String(i === cursor),
      }, [
        h("span", { class: "omni-kind", text: kindLabel(it.kind) }),
        h("span", { class: "omni-label mono", text: it.label }),
        it.sub ? h("span", { class: "omni-sub", text: it.sub }) : null,
      ])));
    drop.hidden = false;
    input.setAttribute("aria-expanded", "true");
  };

  const highlight = () => {
    [...drop.children].forEach((li, i) => {
      li.classList.toggle("sel", i === cursor);
      li.setAttribute("aria-selected", String(i === cursor));
    });
  };

  const suggest = async (q) => {
    const mine = ++seq;
    const exact = resolveExact(q);
    const next = [];
    let failed = false;
    if (exact) {
      next.push({ path: exact, kind: exact.split("/")[1], label: q.trim(), sub: "Open its page" });
    }
    if (q.trim().length >= 2) {
      try {
        const res = await fetch(url(`/api/v1/lookup?q=${encodeURIComponent(q.trim())}`),
          { headers: { Accept: "application/json" } });
        if (res.ok && mine === seq) {
          const body = await res.json();
          for (const r of ((body.data || body).results || [])) {
            const path = entityHref(r.type, r.value);
            if (!path || next.some((n) => n.path === path)) continue;
            next.push({
              path, kind: r.type,
              label: r.label.length > 70 ? mid(r.label, 44, 20) : r.label,
              sub: r.sub,
            });
          }
        } else if (!res.ok) {
          failed = true;
        }
      } catch (err) { failed = true; }
    }
    if (mine !== seq) return;
    items = next.slice(0, 12);
    cursor = items.length ? 0 : -1;
    // A single character is still being typed; only report "no match" once
    // there is enough to have searched for.
    if (!items.length && q.trim().length < 2) { close(); return; }
    paint(q, failed);
  };

  let timer = null;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    const q = input.value;
    if (!q.trim()) { close(); return; }
    timer = setTimeout(() => suggest(q), 140);
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { close(); input.blur(); return; }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (!items.length) return;
      e.preventDefault();
      cursor = (cursor + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
      highlight();
      const sel = drop.children[cursor];
      if (sel && sel.scrollIntoView) sel.scrollIntoView({ block: "nearest" });
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      if (cursor >= 0 && items[cursor]) { go(items[cursor].path); return; }
      const exact = resolveExact(input.value);
      if (exact) go(exact);
    }
  });

  input.addEventListener("blur", () => setTimeout(close, 120));

  // "/" focuses the box, the way every analyst tool does it, but not while
  // the user is already typing somewhere else.
  document.addEventListener("keydown", (e) => {
    const el = document.activeElement || {};
    const tag = el.tagName;
    if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA" && !el.isContentEditable) {
      e.preventDefault();
      input.focus();
      input.select();
    }
  });
}
