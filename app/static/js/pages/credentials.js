/* pages/credentials.js v4 - campaigns rather than raw pairs.
 *
 * The example pairs column is the fix that matters here. v3 rendered each
 * example as one link reading `user:pass 969`, so a row came out as
 * "0:0 969firedancer:firedancer 25admin:admin 22" and a reader could not see
 * where one pair ended and the next began. The count is its own element now,
 * and every pair is a separate chip. */

import { api, h, num, pct, panel, table, stats, tag, entity, dayLink } from "../core.js";

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
        "Every username and password offered at the login prompt, clustered by theme. "
        + "The sensor accepts a seeded set by design, so a success here means it let "
        + "someone in rather than that anything was breached." }),
    ]),

    stats([
      { label: "campaigns", value: num(camps.length) },
      { label: "tagged attempts", value: num(totalAttempts) },
      { label: "clustered pairs", value: num(camps.reduce((a, c) => a + (c.pairs || 0), 0)) },
      { label: "successes", value: num(camps.reduce((a, c) => a + (c.successes || 0), 0)), tone: "accent" },
    ]),

    panel("Campaigns",
      "Pairs are clustered by rule, so a hundred variations of one theme read as one "
      + "campaign. A pair can belong to more than one.",
      [table(
        [{ label: "campaign" }, { label: "attempts", num: true }, { label: "share", num: true },
         { label: "pairs", num: true }, { label: "source ips", num: true },
         { label: "example pairs" }, { label: "last seen" }],
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
        [{ label: "username" }, { label: "password" }, { label: "attempts", num: true },
         { label: "successes", num: true }, { label: "source ips", num: true }],
        d.top_pairs || [],
        (r) => [
          entity("credential", { username: r.username, password: r.password },
            r.username || "(blank)"),
          entity("credential", { username: r.username, password: r.password },
            r.password || "(blank)"),
          num(r.attempts), num(r.successes), num(r.distinct_ips),
        ],
        "No login attempts recorded.")], { scoped: false }),

    (d.tiers || []).length
      ? panel("Credential tiers",
          "Whether the guess matched this host's persona, an adjacent one, or a generic list.",
          [table(
            [{ label: "tier" }, { label: "attempts", num: true }, { label: "ips", num: true },
             { label: "succeeded", num: true }],
            d.tiers,
            (r) => [r.cred_tier, num(r.attempts), num(r.ips), num(r.succeeded)],
            "No tiered attempts in this window.")])
      : null,
  ]);
}
