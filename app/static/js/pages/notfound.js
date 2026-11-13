/* pages/notfound.js - a path the site does not have.
 *
 * The server answers these with status 404 and the same shell, so a crawler
 * or a link checker sees the truth while a reader still gets the site around
 * the message. The page says what was asked for, why it might be missing, and
 * offers the three ways forward a reader takes.
 */

import { h, currentPath, routeLink, icon, pageState } from "../core.js";

export const TITLE = "Page not found";

export async function render() {
  const path = currentPath();
  const search = document.getElementById("omnibar");
  return pageState({
    iconName: "compass",
    title: "There is no page at this address.",
    text: `Nothing on Threat Radar lives at ${path}. If you followed a link to an `
      + "address, hash or session, search for the value itself: entity pages are "
      + "built from data, and the link may have used an older address format.",
    actions: [
      routeLink("/", "Go to the overview", "action"),
      routeLink("/sessions", "Browse sessions", "action"),
      search
        ? h("button", {
            type: "button",
            onclick: () => { search.focus(); search.select(); },
          }, [icon("search"), "Search for a value"])
        : null,
    ].filter(Boolean),
  });
}
