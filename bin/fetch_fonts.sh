#!/usr/bin/env bash
# Self-host the two typefaces the stylesheet asks for, so the dashboard makes
# no third-party network calls. Skip it and the CSS falls back to the system
# stack. The Open Font License requires its text to travel with the font
# files, so the licences are fetched alongside them.
set -euo pipefail
DEST="${1:-/opt/threat-radar/app/static/fonts}"
mkdir -p "$DEST"
base="https://raw.githubusercontent.com/google/fonts/main"
fetch() {
  echo "fetching $1"
  curl -fsSL --max-time 60 -o "$DEST/$1" "$2" || echo "  failed, falling back to system fonts"
}
fetch "PublicSans[wght].ttf"      "$base/ofl/publicsans/PublicSans%5Bwght%5D.ttf"
fetch "IBMPlexMono-Regular.ttf"   "$base/ofl/ibmplexmono/IBMPlexMono-Regular.ttf"
fetch "IBMPlexMono-Medium.ttf"    "$base/ofl/ibmplexmono/IBMPlexMono-Medium.ttf"
fetch "PublicSans-LICENSE.md"     "$base/ofl/publicsans/OFL.txt"
fetch "IBMPlexMono-LICENSE.txt"   "$base/ofl/ibmplexmono/OFL.txt"
ls -la "$DEST"
