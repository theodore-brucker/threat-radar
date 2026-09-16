/* chat.js - slide-over panel, opened from the topbar.
 *
 * v3 launched this from a filled pill fixed to the bottom right of every
 * page. It was the loudest element on screen and the least important thing
 * on it. The launcher is a quiet topbar button now, and "c" opens it.
 */

import { h, url } from "./core.js";

let setOpen = () => {};

export function toggleChat(open) { setOpen(open); }

export function mountChat() {
  const log = h("div", { class: "log" });
  const input = h("input", {
    type: "text", placeholder: "Ask about the sensor data\u2026", "aria-label": "question",
  });
  const send = h("button", { class: "primary", type: "submit", text: "Ask" });
  const form = h("form", {}, [input, send]);
  const stateEl = h("span", { class: "sub2", text: "checking\u2026" });
  const panel = h("aside", {
    class: "chat", "data-open": "false", "aria-hidden": "true", "aria-label": "ask the sensor",
  }, [
    h("header", {}, [
      h("b", { text: "Ask the sensor" }),
      stateEl,
      h("button", { style: "margin-left:auto", text: "Close", onclick: () => setOpen(false) }),
    ]),
    log, form,
  ]);

  setOpen = (open) => {
    panel.dataset.open = String(!!open);
    panel.setAttribute("aria-hidden", String(!open));
    if (open) input.focus();
    else if (panel.contains(document.activeElement)) launcher.focus();
  };

  const launcher = document.getElementById("chat-toggle");
  if (launcher) launcher.addEventListener("click", () => setOpen(panel.dataset.open !== "true"));

  function add(cls, text) {
    log.appendChild(h("div", { class: `msg ${cls}`, text }));
    log.scrollTop = log.scrollHeight;
  }

  fetch(url("/api/v1/chat/status"))
    .then((r) => r.json())
    .then((b) => {
      const d = b.data || b;
      stateEl.textContent = d.enabled ? (d.model || "ready") : "no API key configured";
      if (!d.enabled) {
        input.disabled = true;
        send.disabled = true;
        if (launcher) launcher.disabled = true;
      }
    })
    .catch(() => { stateEl.textContent = "unavailable"; });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;
    add("you", q);
    input.value = "";
    send.disabled = true;
    const context = `The user is viewing the ${location.pathname} page of the Threat Radar dashboard.`;
    try {
      const res = await fetch(url("/api/v1/chat"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: `${context}\n\n${q}` }),
      });
      const body = await res.json();
      const answer = body.answer || body.text || (body.data && body.data.answer);
      if (!res.ok || !answer) add("err", body.error || `error ${res.status}`);
      else add("bot", answer);
    } catch (err) {
      add("err", String(err.message || err));
    } finally {
      send.disabled = false;
    }
  });

  document.body.append(panel);
}
