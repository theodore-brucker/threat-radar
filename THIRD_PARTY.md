# Third-party material

The project code is MIT licensed, see LICENSE. The files listed here are not
covered by that licence and carry their own terms. They are bundled rather than
loaded from a CDN, because the dashboard has no third-party network calls by
design.

## Fonts

`app/static/fonts/IBMPlexSans-Latin-Var.woff2`

IBM Plex Sans, variable weight, Latin subset. Copyright IBM Corp., with
Reserved Font Name "Plex". Licensed under the SIL Open Font License, Version
1.1. The licence text ships alongside the font as `IBMPlexSans-LICENSE.txt`.

`app/static/fonts/IBMPlexMono-Latin-400.woff2`, `app/static/fonts/IBMPlexMono-Latin-500.woff2`

IBM Plex Mono, Latin subset. Copyright IBM Corp., with Reserved Font Name
"Plex". Licensed under the SIL Open Font License, Version 1.1. The licence
text ships alongside the fonts as `IBMPlexMono-LICENSE.txt`, which the OFL
requires when the font files are redistributed.

The WOFF2 files are the Fontsource builds (`@fontsource-variable/ibm-plex-sans`
and `@fontsource/ibm-plex-mono`, version 5.3.0), fetched by
`bin/fetch_fonts.sh`. The licence texts come from the Google Fonts repository.

## Icons

`app/static/js/icons.js`

Path data for a small set of icons taken from Lucide (`lucide-static` 1.72.0),
copyright Lucide Icons and Contributors, licensed under the ISC License. A few
of those glyphs (search, check, the chevrons, external-link, arrow-left,
minus) descend from Feather, copyright Cole Bemis, under the MIT License. Both
notices ship in full as `app/static/vendor/lucide-LICENSE.txt`.

The Threat Radar mark (`app/static/favicon.svg` and the PNGs beside it) is
original to this project and covered by the project licence.

## Map outline

`app/static/vendor/world.json`

A simplified world coastline outline, stored as plain coordinate rings so the
escalation map needs no mapping library and no tile service. The file carries
no attribution metadata of its own. Record the upstream dataset and its terms
here before relying on this notice: TODO, upstream source and licence.

## Cowrie

The sensor runs Cowrie, which is not vendored here. `sensor/patches/` holds
small local modifications to Cowrie source as patch files. Cowrie is
distributed under a BSD 3-clause licence by its own authors, and the patches
are intended to be applied to a checkout obtained from upstream.
