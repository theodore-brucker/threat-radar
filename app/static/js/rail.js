/* rail.js v4 - the funnel, two ways.
 *
 * Every class emitted here now has a rule in components.css. In v3 the
 * analyst rail emitted .rail, .segs, .seg, .drops and .rail-note, none of
 * which were styled, so it rendered as run-on text; and funnelExec emitted
 * .fstep inside a .funnel that the payloads work had since redefined as a
 * four column grid, which crushed every bar to a stub.
 *
 * Executive mode: proportional bars plus the odds restated in words. "1 in
 * 2,000 connections ends with malware" is the sentence someone repeats in a
 * meeting. Analyst mode: log scaled widths so the tail stays visible, and the
 * whole rail doubles as a stage filter.
 */

import { h, num, state, funnel, takeaway, STAGE_COLORS } from "./core.js";

const EXEC_LABELS = {
  connected: ["Knocked on the door", "Any machine that opened a connection"],
  authenticated: ["Guessed a valid login", "Got past the password prompt"],
  shell: ["Ran commands", "Reached a working shell and typed something"],
  transferred: ["Moved a file", "Uploaded or downloaded something"],
};

export function funnelExec(rail, odds) {
  const stages = (rail.stages || []).filter((s) => s.unit === "sessions");

  const steps = stages.map((s, i) => {
    const label = EXEC_LABELS[s.key] || [s.label, ""];
    return {
      label: label[0],
      sub: label[1],
      value: s.count,
      color: STAGE_COLORS[Math.min(i, 4)],
      baseLabel: "all connections",
    };
  });

  const samples = (rail.stages || []).filter((s) => s.unit === "samples");
  const sampleLine = samples.length
    ? h("p", { class: "sub2", style: "margin-top:14px",
        text: `${num(samples[0].count)} unique malware samples kept from those transfers`
          + (samples[1] ? `, ${num(samples[1].count)} shared back to VirusTotal.` : ".") })
    : null;

  const oddsEl = h("div", { class: "odds" }, [
    odds.login ? h("div", {}, [
      h("b", { text: `1 in ${num(odds.login)}` }),
      h("span", { text: "connections guesses a working login" }),
    ]) : null,
    odds.shell ? h("div", {}, [
      h("b", { text: `1 in ${num(odds.shell)}` }),
      h("span", { text: "reaches a shell and runs commands" }),
    ]) : null,
    odds.malware ? h("div", { class: "alarm" }, [
      h("b", { text: `1 in ${num(odds.malware)}` }),
      h("span", { text: "ends with a file moved onto the machine" }),
    ]) : null,
  ]);

  return h("div", {}, [
    funnel(steps),
    sampleLine,
    oddsEl,
    takeaway([
      "Almost everything reaching an internet-facing machine is automated and stops at the password prompt. ",
      "The risk is the ",
      { alarm: `${num(odds.transferred_sessions || 0)} connections` },
      " that got far enough to put a file on disk.",
    ]),
  ]);
}

const listeners = new Set();

export function onStageChange(fn) { listeners.add(fn); }

function emit() { listeners.forEach((fn) => fn(state.minStage)); }

function widths(counts) {
  const logs = counts.map((c) => Math.log10(Math.max(c, 1)) + 1);
  const total = logs.reduce((a, b) => a + b, 0) || 1;
  return logs.map((l) => (l / total) * 100);
}

export function railFull(data, { interactive = true } = {}) {
  const stages = data.stages || [];
  const w = widths(stages.map((s) => s.count));

  const segs = h("div", { class: "rail-segs" }, stages.map((s, i) => {
    const stage = Math.min(i, 4);
    const btn = h("button", {
      class: "seg",
      type: "button",
      style: `flex:0 1 ${w[i].toFixed(2)}%;--stage:var(${STAGE_COLORS[stage]})`,
      "aria-pressed": String(interactive && state.minStage === stage),
      title: interactive
        ? `Filter the map and tables to sources that reached ${s.label.toLowerCase()}`
        : s.label,
    }, [
      h("span", { class: "n", text: num(s.count) }),
      h("span", { class: "k", text: `${i} \u00b7 ${s.label}` }),
      h("span", { class: "u", text: s.unit }),
    ]);
    if (interactive && i <= 4) {
      btn.addEventListener("click", () => {
        state.minStage = state.minStage === i ? 0 : i;
        emit();
        segs.querySelectorAll(".seg").forEach((b, j) =>
          b.setAttribute("aria-pressed", String(state.minStage === j)));
      });
    }
    return btn;
  }));

  const drops = h("div", { class: "rail-drops" }, stages.map((s, i) =>
    h("div", { style: `flex:0 1 ${w[i].toFixed(2)}%`,
      title: s.retained_pct === null || s.retained_pct === undefined
        ? "" : `${s.retained_pct}% of the previous stage carried forward` }, [
      s.retained_pct === null || s.retained_pct === undefined
        ? (i === 0 ? "baseline" : "unit changes here")
        : `${s.retained_pct}% carried forward`,
    ])));

  return h("div", {}, [
    h("div", { class: "rail" }, [segs, drops]),
    h("p", { class: "rail-note", text:
      "Widths are log scaled so the tail stays visible. The last two stages count unique samples, not sessions." }),
  ]);
}

/* The compact filter strip used on pages other than the overview. */
export function railStrip(data, { onChange } = {}) {
  const stages = (data.stages || []).slice(0, 5);
  const strip = h("div", { class: "railstrip", role: "group", "aria-label": "filter by escalation stage" });
  // Stage 0 is every source, so it is the unfiltered state rather than a
  // filter. Marking it pressed by default told the reader a filter was on
  // when none was.
  const buttons = stages.map((s, i) => {
    const b = h("button", {
      type: "button",
      style: `--stage:var(${STAGE_COLORS[i]})`,
      "aria-pressed": String(state.minStage !== 0 && state.minStage === i),
      title: i === 0
        ? "Show every source, which is the default"
        : `Show only sources that reached stage ${i}`,
    }, [
      h("b", { text: num(s.count) }),
      h("span", { text: s.label.toLowerCase() }),
    ]);
    b.addEventListener("click", () => {
      state.minStage = state.minStage === i ? 0 : i;
      sync();
      emit();
      if (onChange) onChange(state.minStage);
    });
    return b;
  });
  const clear = h("button", {
    type: "button", class: "clear", text: "clear filter",
    onclick: () => {
      state.minStage = 0;
      sync();
      emit();
      if (onChange) onChange(0);
    },
  });

  function sync() {
    buttons.forEach((b, j) =>
      b.setAttribute("aria-pressed", String(state.minStage !== 0 && state.minStage === j)));
    clear.hidden = state.minStage === 0;
  }

  strip.append(...buttons, clear);
  sync();
  return strip;
}
