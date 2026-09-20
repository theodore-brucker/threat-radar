#!/usr/bin/env bash
# verify.sh - post-deploy check for every route the site depends on.
#
#   sudo /opt/threat-radar/deploy/verify.sh
#   /opt/threat-radar/deploy/verify.sh http://127.0.0.1:8080
#
# Talks to uvicorn directly by default, so nginx basic auth is out of the way.
# Detail endpoints are driven by ids pulled from the list endpoints in the same
# run, so a passing result means the drill-down paths work against real data
# rather than against hand-written fixtures.
#
# Exit status is 0 only when every check passed.
set -uo pipefail

BASEURL="${1:-http://127.0.0.1:8080}"
PREFIX="${TR_URL_PREFIX:-}"
ROOT="${BASEURL%/}${PREFIX}"

PASS=0
FAIL=0
SLOW=0
SLOW_LIMIT="${TR_SLOW_MS:-2500}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

c_ok=$'\033[32m'; c_bad=$'\033[31m'; c_warn=$'\033[33m'; c_off=$'\033[0m'
[ -t 1 ] || { c_ok=""; c_bad=""; c_warn=""; c_off=""; }

note() { printf '\n== %s\n' "$1"; }

# get <label> <path> [expect_substring]
get() {
  local label="$1" path="$2" want="${3:-}"
  local body="$TMP/body" code ms
  # -g turns off curl's URL globbing. Without it a path containing [ or ]
  # (the variable font filename is PublicSans[wght].ttf) is read as a range
  # specification and curl fails before it opens a connection.
  read -r code ms < <(curl -g -sS -o "$body" -w '%{http_code} %{time_total}\n' \
    -H 'Accept: application/json' "$ROOT$path" 2>/dev/null || echo "000 0")
  local msi
  msi=$(awk -v t="$ms" 'BEGIN{printf "%d", t*1000}')

  if [ "$code" != "200" ]; then
    if [ "$code" = "000" ]; then
      # No HTTP status at all means curl never got a reply: a transport or
      # URL problem rather than something the app returned.
      local why
      why=$(curl -g -sS -o /dev/null "$ROOT$path" 2>&1 | head -1)
      printf '%s FAIL%s %-46s no response (%s)\n' "$c_bad" "$c_off" "$label" "${why:-unreachable}"
    else
      printf '%s FAIL%s %-46s http %s\n' "$c_bad" "$c_off" "$label" "$code"
    fi
    FAIL=$((FAIL+1)); return 1
  fi
  if [ -n "$want" ] && ! grep -q -- "$want" "$body"; then
    printf '%s FAIL%s %-46s missing %s\n' "$c_bad" "$c_off" "$label" "$want"
    FAIL=$((FAIL+1)); return 1
  fi
  if [ "$msi" -gt "$SLOW_LIMIT" ]; then
    printf '%s SLOW%s %-46s %sms\n' "$c_warn" "$c_off" "$label" "$msi"
    SLOW=$((SLOW+1))
  else
    printf '%s ok  %s %-46s %sms\n' "$c_ok" "$c_off" "$label" "$msi"
  fi
  PASS=$((PASS+1))
  cp "$body" "$TMP/last.json"
  return 0
}

# jget <file> <python expr over `d`> : prints the value or nothing
jget() {
  python3 -c '
import json,sys
try:
    body=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
d=body.get("data", body)
try:
    v=eval(sys.argv[2], {"d": d})
except Exception:
    sys.exit(0)
if v is not None:
    print(v)
' "$1" "$2"
}

envelope_check() {
  local label="$1" file="$2"
  local ok
  ok=$(python3 -c '
import json,sys
try:
    b=json.load(open(sys.argv[1]))
except Exception:
    print("unparseable"); sys.exit()
print("yes" if b.get("ok") is True and "data" in b else "no")
' "$file")
  if [ "$ok" = "yes" ]; then
    printf '%s ok  %s %-46s envelope\n' "$c_ok" "$c_off" "$label"
    PASS=$((PASS+1))
  else
    printf '%s FAIL%s %-46s envelope: %s\n' "$c_bad" "$c_off" "$label" "$ok"
    FAIL=$((FAIL+1))
  fi
}

printf 'Threat Radar verify\n'
printf 'target   %s\n' "$ROOT"
printf 'slow at  %sms\n' "$SLOW_LIMIT"

# --------------------------------------------------------------------------
note "envelope and core reads"

get "meta"                      "/api/v1/meta"          '"ok"' && envelope_check "meta" "$TMP/last.json"
get "health"                    "/api/v1/health"
get "rail"                      "/api/v1/rail"
get "funnel"                    "/api/v1/funnel"
get "contributions"             "/api/v1/contributions"  '"contributed_samples"'
get "spikes"                    "/api/v1/spikes"

# --------------------------------------------------------------------------
note "list views, at two windows"

for D in 1 30; do
  get "overview (days=$D)"      "/api/v1/overview?days=$D"
  get "sources (days=$D)"       "/api/v1/sources?days=$D&limit=25"
  get "credentials (days=$D)"   "/api/v1/credentials?days=$D"
  get "payloads (days=$D)"      "/api/v1/payloads?days=$D"
  get "sessions (days=$D)"      "/api/v1/sessions?days=$D"
  get "tunnels (days=$D)"       "/api/v1/tunnels?days=$D"
done

get "sources, stage filter"     "/api/v1/sources?days=30&min_stage=2&limit=25"
get "overview, stage filter"    "/api/v1/overview?days=30&min_stage=2"
get "all time window"           "/api/v1/overview?days=3650"

# --------------------------------------------------------------------------
note "ids for the detail checks"

get "sources for ids"           "/api/v1/sources?days=3650&limit=25" >/dev/null
IP=$(jget "$TMP/last.json" 'd["sources"][0]["src_ip"]')
ASN=$(jget "$TMP/last.json" 'd["sources"][0]["asn"]')

get "sessions for ids"          "/api/v1/sessions?days=3650" >/dev/null
SESSION=$(jget "$TMP/last.json" 'd["sessions"][0]["session"]')
SHA=$(jget "$TMP/last.json" 'd["sessions"][0]["shasums"][0]')

get "credentials for ids"       "/api/v1/credentials?days=3650" >/dev/null
CUSER=$(jget "$TMP/last.json" 'd["top_pairs"][0]["username"]')
CPASS=$(jget "$TMP/last.json" 'd["top_pairs"][0]["password"]')

get "meta for coverage"         "/api/v1/meta" >/dev/null
DAY=$(jget "$TMP/last.json" 'd["coverage"]["last_day"]')

get "fingerprints for ids"      "/api/v1/sources?days=3650&limit=5" >/dev/null
HASSH=$(jget "$TMP/last.json" 'd["fingerprints"]["fingerprints"][0]["hassh"]')

CRED=""
if [ -n "${CUSER:-}" ]; then
  CRED=$(python3 -c '
import base64, sys
raw = (sys.argv[1] + "\x00" + (sys.argv[2] if len(sys.argv) > 2 else "")).encode()
print(base64.urlsafe_b64encode(raw).decode().rstrip("="))
' "$CUSER" "${CPASS:-}")
fi

printf '   ip=%s asn=%s session=%s sha=%s day=%s hassh=%s\n' \
  "${IP:-none}" "${ASN:-none}" "${SESSION:-none}" "${SHA:-none}" "${DAY:-none}" "${HASSH:-none}"

# --------------------------------------------------------------------------
note "entity drill-down"

[ -n "${IP:-}" ]      && get "entity ip"        "/api/v1/entity/ip/$IP"
[ -n "${ASN:-}" ]     && get "entity asn"       "/api/v1/entity/asn/$ASN"
[ -n "${DAY:-}" ]     && get "entity day"       "/api/v1/entity/day/$DAY"
[ -n "${HASSH:-}" ]   && get "entity hassh"     "/api/v1/entity/hassh/$HASSH"
[ -n "${CRED:-}" ]    && get "entity credential" "/api/v1/entity/credential/$CRED"
[ -n "${SESSION:-}" ] && get "session detail"   "/api/v1/sessions/$SESSION"
[ -n "${SHA:-}" ]     && get "sample detail"    "/api/v1/samples/$SHA"
[ -n "${IP:-}" ]      && get "source detail"    "/api/v1/sources/$IP"

# A bad id must come back as a clean 404 rather than a 500.
BADCODE=$(curl -g -sS -o /dev/null -w '%{http_code}' "$ROOT/api/v1/samples/notahash" || echo 000)
if [ "$BADCODE" = "404" ] || [ "$BADCODE" = "400" ] || [ "$BADCODE" = "422" ]; then
  printf '%s ok  %s %-46s rejects a bad hash (%s)\n' "$c_ok" "$c_off" "bad sample id" "$BADCODE"
  PASS=$((PASS+1))
else
  printf '%s FAIL%s %-46s expected 4xx, got %s\n' "$c_bad" "$c_off" "bad sample id" "$BADCODE"
  FAIL=$((FAIL+1))
fi

# --------------------------------------------------------------------------
note "omnibar and hover cards"

get "lookup"                    "/api/v1/lookup?q=root"
if [ -n "${IP:-}" ]; then
  CODE=$(curl -g -sS -o "$TMP/cards.json" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d "{\"items\":[{\"type\":\"ip\",\"value\":\"$IP\"}]}" \
    "$ROOT/api/v1/cards" || echo 000)
  if [ "$CODE" = "200" ] && grep -q '"cards"' "$TMP/cards.json"; then
    printf '%s ok  %s %-46s POST\n' "$c_ok" "$c_off" "cards"
    PASS=$((PASS+1))
  else
    printf '%s FAIL%s %-46s http %s\n' "$c_bad" "$c_off" "cards" "$CODE"
    FAIL=$((FAIL+1))
  fi
fi

# --------------------------------------------------------------------------
note "page shell and assets"

for P in "/" "/sources" "/credentials" "/payloads" "/sessions" "/tunnels" "/method"; do
  get "page $P" "$P" "boot.js"
done
[ -n "${IP:-}" ]      && get "page /ip/{addr}"      "/ip/$IP" "boot.js"
[ -n "${SESSION:-}" ] && get "page /session/{id}"   "/session/$SESSION" "boot.js"
[ -n "${SHA:-}" ]     && get "page /sample/{sha}"   "/sample/$SHA" "boot.js"

for A in \
  "/static/css/tokens.css" "/static/css/app.css" "/static/css/components.css" \
  "/static/css/print.css" "/static/js/boot.js" "/static/js/core.js" \
  "/static/js/rail.js" "/static/js/theme.js" "/static/js/keys.js" \
  "/static/js/pages/overview.js" "/static/js/pages/entity.js" \
  "/static/vendor/world.json" "/static/fonts/PublicSans[wght].ttf"
do
  get "asset $A" "$A"
done

# --------------------------------------------------------------------------
note "headers and prefix"

curl -g -sSI "$ROOT/" -o "$TMP/head.txt" >/dev/null 2>&1
check_header() {
  if grep -qi "^$1:" "$TMP/head.txt"; then
    printf '%s ok  %s %-46s present\n' "$c_ok" "$c_off" "$1"
    PASS=$((PASS+1))
  else
    printf '%s FAIL%s %-46s missing\n' "$c_bad" "$c_off" "$1"
    FAIL=$((FAIL+1))
  fi
}
check_header "content-security-policy"
check_header "x-content-type-options"
check_header "referrer-policy"

curl -g -sS "$ROOT/" -o "$TMP/shell.html"
if grep -q "__TR_BASE__" "$TMP/shell.html"; then
  printf '%s FAIL%s %-46s placeholder was not substituted\n' "$c_bad" "$c_off" "shell prefix"
  FAIL=$((FAIL+1))
else
  printf '%s ok  %s %-46s substituted (prefix="%s")\n' "$c_ok" "$c_off" "shell prefix" "$PREFIX"
  PASS=$((PASS+1))
fi

if grep -q "src=\"${PREFIX}/static/js/boot.js\"" "$TMP/shell.html"; then
  printf '%s ok  %s %-46s boot script path\n' "$c_ok" "$c_off" "shell prefix"
  PASS=$((PASS+1))
else
  printf '%s FAIL%s %-46s boot script path is wrong for this prefix\n' "$c_bad" "$c_off" "shell prefix"
  FAIL=$((FAIL+1))
fi

# The inline theme script must be covered by the policy, or dark mode dies on
# first paint and the console fills with CSP violations.
HASH=$(python3 -c '
import base64, hashlib, re, sys
html = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>", html, re.S)
if not m:
    sys.exit(0)
print("sha256-" + base64.b64encode(hashlib.sha256(m.group(1).encode()).digest()).decode())
' "$TMP/shell.html")
if [ -z "$HASH" ]; then
  printf '%s ok  %s %-46s no inline script in the shell\n' "$c_ok" "$c_off" "csp inline hash"
  PASS=$((PASS+1))
elif grep -qi "$HASH" "$TMP/head.txt"; then
  printf '%s ok  %s %-46s %s\n' "$c_ok" "$c_off" "csp inline hash" "$HASH"
  PASS=$((PASS+1))
else
  printf '%s FAIL%s %-46s policy does not cover the inline script\n' "$c_bad" "$c_off" "csp inline hash"
  FAIL=$((FAIL+1))
fi

# --------------------------------------------------------------------------
note "result"
printf 'passed %s   failed %s   slow %s\n' "$PASS" "$FAIL" "$SLOW"
if [ "$FAIL" -gt 0 ]; then
  printf '%sverification failed%s\n' "$c_bad" "$c_off"
  exit 1
fi
printf '%sall checks passed%s\n' "$c_ok" "$c_off"
exit 0
