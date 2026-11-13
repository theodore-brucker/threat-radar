#!/usr/bin/env bash
# Self-host the two typefaces the stylesheet asks for, so the dashboard makes
# no third-party network calls. Skip it and the CSS falls back to the system
# stack. The Open Font License requires its text to travel with the font
# files, so the licences are fetched alongside them.
#
# The fonts are the Latin subsets published by Fontsource as WOFF2: about
# 75 KB for all three files, against roughly 400 KB for the full TTFs. Text
# outside Latin (attacker strings sometimes carry it) falls back to the
# system stack, which is the right result for content we never chose.
set -euo pipefail
DEST="${1:-/opt/threat-radar/app/static/fonts}"
mkdir -p "$DEST"
npm="https://cdn.jsdelivr.net/npm"
ofl="https://raw.githubusercontent.com/google/fonts/main/ofl"
fetch() {
  echo "fetching $1"
  curl -fsSL --max-time 60 -o "$DEST/$1" "$2" || echo "  failed, falling back to system fonts"
}
fetch "IBMPlexSans-Latin-Var.woff2" \
  "$npm/@fontsource-variable/ibm-plex-sans@5.3.0/files/ibm-plex-sans-latin-wght-normal.woff2"
fetch "IBMPlexMono-Latin-400.woff2" \
  "$npm/@fontsource/ibm-plex-mono@5.3.0/files/ibm-plex-mono-latin-400-normal.woff2"
fetch "IBMPlexMono-Latin-500.woff2" \
  "$npm/@fontsource/ibm-plex-mono@5.3.0/files/ibm-plex-mono-latin-500-normal.woff2"
fetch "IBMPlexSans-LICENSE.txt" "$ofl/ibmplexsans/OFL.txt"
fetch "IBMPlexMono-LICENSE.txt" "$ofl/ibmplexmono/OFL.txt"
ls -la "$DEST"
