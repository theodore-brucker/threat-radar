#!/bin/bash
# Sensor-side forced command. Read-only. The client cannot pass a path; the
# only accepted argument is a 64-char hex sha256, matched against a fixed
# directory. Default (no argument) is unchanged: a tar of the live log plus
# the newest rotated log.
set -u

LOGDIR=/opt/cowrie/var/log/cowrie
DLDIR=/opt/cowrie/var/lib/cowrie/downloads
MAXBYTES=$((32*1024*1024))

REQ="${SSH_ORIGINAL_COMMAND:-logs}"
set -- $REQ
MODE="${1:-logs}"
ARG="${2:-}"

case "$MODE" in
  logs|"")
    # Cowrie writes cowrie.json continuously. Tarring it in place returns
    # exit 1 ("file changed as we read it") and the client discards the
    # whole cycle, which was losing roughly one pull in three. Snapshot
    # first, then tar the copy.
    cd "$LOGDIR" || exit 1
    TMP=$(mktemp -d /tmp/pull-logs.XXXXXX) || exit 1
    trap 'rm -rf "$TMP"' EXIT
    cp cowrie.json "$TMP/cowrie.json" || exit 1
    NEWEST_ROTATED=$(ls -1t cowrie.json.20* 2>/dev/null | head -1)
    [ -n "${NEWEST_ROTATED:-}" ] && cp "$NEWEST_ROTATED" "$TMP/$NEWEST_ROTATED"
    tar -cf - -C "$TMP" .
    ;;
  samples-list)
    cd "$DLDIR" || exit 1
    for f in *; do
      [ -f "$f" ] || continue
      case "$f" in
        *[!0-9a-f]*|"") continue ;;
      esac
      [ ${#f} -eq 64 ] || continue
      sz=$(stat -c %s "$f")
      [ "$sz" -gt 0 ] && [ "$sz" -le "$MAXBYTES" ] && echo "$sz $f"
    done
    exit 0
    ;;
  samples-get)
    case "$ARG" in
      *[!0-9a-f]*|"") exit 2 ;;
    esac
    [ ${#ARG} -eq 64 ] || exit 2
    F="$DLDIR/$ARG"
    [ -f "$F" ] || exit 3
    sz=$(stat -c %s "$F")
    [ "$sz" -gt 0 ] && [ "$sz" -le "$MAXBYTES" ] || exit 4
    exec cat "$F"
    ;;
  *)
    exit 64
    ;;
esac
