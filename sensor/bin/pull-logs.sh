#!/bin/bash
# Sensor-side forced command for the collector's pull key. Read-only.
#
# Every request is one line in SSH_ORIGINAL_COMMAND, the only input the client
# controls. Nothing here takes a path: log names must match the rotation
# pattern, sample names must be 64 hex characters, and every number must be
# plain decimal.
#
#   manifest                    one "name size" line per log file present
#   chunk NAME OFFSET LENGTH    LENGTH bytes of NAME starting at OFFSET
#   samples-list                one "size sha256" line per capture
#   samples-get SHA256          the capture with that name
#
# The manifest and chunk requests replaced a tar of the whole live log and
# the whole newest rotated log. The tar re-sent the whole
# live log and the whole newest rotated log on every pull, which at a
# two-minute interval came to roughly 35 to 40 GB a day for a few megabytes of
# new events, and it only ever offered the newest rotated file, so a collector
# that missed a full day lost it. The collector now asks for what it lacks.
set -euo pipefail
# Globbing stays off: the request is split into words below and none of them
# may expand against the filesystem.
set -f

LOGDIR="${PULL_LOGDIR:-/opt/cowrie/var/log/cowrie}"
DLDIR="${PULL_DLDIR:-/opt/cowrie/var/lib/cowrie/downloads}"
MAX_CHUNK=$((64 * 1024 * 1024))
MAX_SAMPLE=$((32 * 1024 * 1024))
NAME_RE='^cowrie\.json(\.[0-9]{4}-[0-9]{2}-[0-9]{2})?$'
NUM_RE='^[0-9]{1,12}$'
SHA_RE='^[0-9a-f]{64}$'

refuse() { echo "refused: $1" >&2; exit 2; }

read -r -a argv <<< "${SSH_ORIGINAL_COMMAND:-}"
cmd="${argv[0]:-}"

case "$cmd" in
  manifest)
    [ "${#argv[@]}" -eq 1 ] || refuse "manifest takes no arguments"
    find "$LOGDIR" -maxdepth 1 -type f -regextype posix-extended \
      -regex '.*/cowrie\.json(\.[0-9]{4}-[0-9]{2}-[0-9]{2})?' -printf '%f %s\n' | sort
    ;;

  chunk)
    [ "${#argv[@]}" -eq 4 ] || refuse "chunk takes a name, an offset and a length"
    name="${argv[1]}" offset="${argv[2]}" length="${argv[3]}"
    [[ $name =~ $NAME_RE ]] || refuse "not a log name"
    [[ $offset =~ $NUM_RE && $length =~ $NUM_RE ]] || refuse "not a number"
    [ "$length" -le "$MAX_CHUNK" ] || length=$MAX_CHUNK
    file="$LOGDIR/$name"
    [ -f "$file" ] || refuse "no such log"
    size=$(stat -c %s -- "$file")
    [ "$offset" -le "$size" ] || refuse "offset past the end"
    # dd rather than tail piped to head: a pipe closed early by head would
    # kill tail with SIGPIPE and turn a complete answer into a failed exit.
    # The live log keeps growing while this reads, which is fine, because
    # count_bytes stops at the requested length whatever arrives meanwhile.
    dd if="$file" bs=65536 iflag=skip_bytes,count_bytes \
       skip="$offset" count="$length" status=none
    ;;

  samples-list)
    [ "${#argv[@]}" -eq 1 ] || refuse "samples-list takes no arguments"
    find "$DLDIR" -maxdepth 1 -type f -regextype posix-extended \
      -regex '.*/[0-9a-f]{64}' -size +0c -size -$((MAX_SAMPLE + 1))c -printf '%s %f\n'
    ;;

  samples-get)
    [ "${#argv[@]}" -eq 2 ] || refuse "samples-get takes one sha256"
    sha="${argv[1]}"
    [[ $sha =~ $SHA_RE ]] || refuse "not a sha256"
    file="$DLDIR/$sha"
    [ -f "$file" ] || exit 3
    size=$(stat -c %s -- "$file")
    [ "$size" -gt 0 ] && [ "$size" -le "$MAX_SAMPLE" ] || exit 4
    exec cat -- "$file"
    ;;

  *)
    refuse "unknown request"
    ;;
esac
