/* pages/credentials.js - credential campaigns, then the raw pairs.
 *
 * In the example pairs column each pair is its own chip with its count in a
 * separate element, so a row of examples cannot run together into one
 * unreadable string such as "0:0 969firedancer:firedancer 25". */

import { api, h, num, pct, panel, table, stats, tag, entity, dayLink, emptyState } from "../core.js";

export const TITLE = "Credentials";

function pairChips(examples) {
  if (!examples || !examples.length) return h("span", { class: "sub2", text: "-" });
  return h("span", { class: "pairs" }, examples.slice(0, 4).map((e) =>
    h("span", { class: "pair" }, [
      entity("credential", { username: e.username, password: e.password },
        `${e.username || "(blank)"}:${e.password || "(blank)"}`),
      h("span", { class: "pair-n", text: num(e.attempts) }),
    ])));
}

export async function render() {
  const d = await api("/api/v1/credentials");
  const camps = (d.campaigns && d.campaigns.campaigns) || [];
  const totalAttempts = camps.reduce((a, c) => a + (c.attempts || 0), 0);

  return h("div", {}, [
    h("div", { class: "pagehead" }, [
      h("p", { text:
        "Every username and password offered at the login prompt, grouped by theme. "
        + "The sensor accepts a fixed list of passwords, so a successful login here "
        + "means the sensor let someone in. No real system was breached." }),
    ]),

    stats([
      { label: "Campaigns", value: num(camps.length) },
      { label: "Tagged attempts", value: num(totalAttempts) },
      { label: "Clustered pairs", value: num(camps.reduce((a, c) => a + (c.pairs || 0), 0)) },
      { label: "Successes", value: num(camps.reduce((a, c) => a + (c.successes || 0), 0)), tone: "accent" },
    ]),

    panel("Campaigns",
      "Pairs are grouped by rule, so a hundred variations on one theme appear as one "
      + "row. A pair can belong to more than one campaign.",
      [table(
        [{ label: "Campaign" }, { label: "Attempts", num: true }, { label: "Share", num: true },
         { label: "Pairs", num: true }, { label: "Source addresses", num: true },
         { label: "Example pairs" }, { label: "Last seen" }],
        camps,
        (r) => [
          [h("b", { text: r.label }), h("div", { class: "sub2 mono", text: r.tag })],
          num(r.attempts),
          pct(r.share_pct, 2),
          num(r.pairs),
          num(r.src_ips),
          pairChips(r.examples),
          dayLink(r.last_seen),
        ],
        "No credential campaigns in this window.")]),

    panel("Most attempted pairs", "Lifetime counts, unclustered.",
      [table(
        [{ label: "Username" }, { label: "Password" }, { label: "Attempts", num: true },
         { label: "Successes", num: true }, { label: "Source addresses", num: true }],
        d.top_pairs || [],
        (r) => [
          entity("credential", { username: r.username, password: r.password },
            r.username || "(blank)"),
          entity("credential", { username: r.username, password: r.password },
            r.password || "(blank)"),
          num(r.attempts), num(r.successes), num(r.distinct_ips),
        ],
        emptyState("No login attempts recorded yet.", {
          hint: "This table counts every attempt the sensor has seen, so it fills as soon as anyone tries a password.",
        }))]),

    (d.tiers || []).length
      ? panel("Credential tiers",
          "Whether the guess matched this host's persona, an adjacent one, or a generic list.",
          [table(
            [{ label: "Tier" }, { label: "Attempts", num: true }, { label: "Addresses", num: true },
             { label: "Succeeded", num: true }],
            d.tiers,
            (r) => [r.cred_tier, num(r.attempts), num(r.ips), num(r.succeeded)],
            "No tiered attempts in this window.")])
      : null,
  ]);
}
