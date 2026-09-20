# Third-party material

The project code is MIT licensed, see LICENSE. The files listed here are not
covered by that licence and carry their own terms. They are bundled rather than
loaded from a CDN, because the dashboard has no third-party network calls by
design.

## Fonts

`app/static/fonts/IBMPlexMono-Regular.ttf`, `app/static/fonts/IBMPlexMono-Medium.ttf`

IBM Plex Mono, copyright IBM Corp., with Reserved Font Name "Plex". Licensed
under the SIL Open Font License, Version 1.1. The licence text ships alongside
the fonts as `IBMPlexMono-LICENSE.txt`, which the OFL requires when the font
files are redistributed.

`app/static/fonts/PublicSans[wght].ttf`

Public Sans, a modified version of Libre Franklin produced by the General
Services Administration. Licensed under the SIL Open Font License, Version 1.1.
The licence text ships alongside the font as `PublicSans-LICENSE.md`.

Both files are fetched by `bin/fetch_fonts.sh` from the Google Fonts
repository, which is also where the licence texts come from.

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
