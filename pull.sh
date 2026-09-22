#!/usr/bin/env bash
# Pull new Cowrie log bytes from the sensor over the tailnet.
#
# The sensor lists its log files with their sizes, and this asks only for the
# bytes it does not already have, appending them to the spool copy of each
# file. The ingester tracks its own byte offset per spool file and holds back a
# partial last line, so a chunk that ends mid-line is picked up correctly on
# the next pass.
#
# The previous protocol pulled a tar of the whole live log and the whole newest
# rotated log every two minutes, roughly 35 to 40 GB a day over the tailnet and
# about twice that written to the SD card, and it could only ever recover one
# rotated day. Every rotated file the sensor still keeps is now offered, so an
# outage of up to a week loses nothing.
#
# Everything the sensor returns is treated as hostile, because the sensor is
# the host this project exists to have attacked: names must match the rotation
# pattern, sizes and chunk lengths are checked, and nothing is unpacked.
set -euo pipefail

BASE="${TR_BASE:-/opt/threat-radar}"
SPOOL="$BASE/spool"

# The service account does not own the repository, so the lock lives in the
# unit's RuntimeDirectory. The fallback for a run by hand is the spool, which
# the service account owns, rather than /tmp, where another local account
# could create the file first.
exec 9>"${RUNTIME_DIRECTORY:-$SPOOL}/pull.lock"
flock -n 9 || exit 0          # a previous run is still going; skip this tick

# Sensor address lives outside the repo so it is never committed. The unit
# supplies it through EnvironmentFile; this is for a run by hand.
CONF="${TR_PULL_ENV:-/etc/threat-radar/pull.env}"
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"

KEY="$BASE/.ssh_pull"
KNOWN="$BASE/.ssh_known_hosts"
# Rotated files older than this are not requested. It matches the spool
# retention in the prune unit, so a file prune has deleted is never fetched
# again while the sensor still lists it.
RETAIN_DAYS="${TR_SPOOL_RETAIN_DAYS:-8}"
MAX_CHUNK=$((64 * 1024 * 1024))
MAX_FILES=64
NAME_RE='^cowrie\.json(\.[0-9]{4}-[0-9]{2}-[0-9]{2})?$'
NUM_RE='^[0-9]{1,12}$'

sensor() {
  if [ -n "${TR_PULL_TRANSPORT:-}" ]; then
    # Test hook: run the request through a local command instead of ssh.
    SSH_ORIGINAL_COMMAND="$*" "$TR_PULL_TRANSPORT"
    return
  fi
  : "${SENSOR_TS_IP:?SENSOR_TS_IP not set in $CONF}"
  ssh -n -T -i "$KEY" -p 2200 \
      -o IdentitiesOnly=yes -o BatchMode=yes \
      -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=2 \
      cowrie@"$SENSOR_TS_IP" "$*"
}

cd "$SPOOL"
rm -f -- .chunk.* pull.tmp

manifest=$(sensor manifest) || { echo "pull: manifest request failed" >&2; exit 1; }
oldest=$(date -u -d "-$((RETAIN_DAYS - 1)) days" +%F)
fetched=0 files=0 failed=0

# The manifest is read on descriptor 3, not standard input. Each chunk request
# runs ssh inside this loop, and ssh reads its standard input, so a manifest
# on stdin was swallowed by the first request and every pull stopped after
# fetching one file. ssh also gets -n above, so either guard alone would do.
while read -r name size <&3; do
  [ -n "${name:-}" ] || continue
  files=$((files + 1))
  if [ "$files" -gt "$MAX_FILES" ]; then
    echo "pull: manifest lists more than $MAX_FILES files, ignoring the rest" >&2
    break
  fi
  if ! [[ $name =~ $NAME_RE && $size =~ $NUM_RE ]]; then
    echo "pull: ignoring malformed manifest line" >&2
    continue
  fi
  if [ "$name" != cowrie.json ] && [[ ${name#cowrie.json.} < $oldest ]]; then
    continue
  fi

  have=0
  [ -f "$name" ] && have=$(stat -c %s -- "$name")
  if [ "$have" -gt "$size" ]; then
    # The sensor's copy is shorter than ours, which is what the live log looks
    # like just after rotation. Its old contents now live under a dated name
    # that this loop fetches separately, so start this one again.
    rm -f -- "$name"
    have=0
  fi

  while [ "$have" -lt "$size" ]; do
    want=$((size - have))
    [ "$want" -le "$MAX_CHUNK" ] || want=$MAX_CHUNK
    tmp=".chunk.$$"
    # One byte more than asked for is read on purpose. An answer longer than
    # the request is a protocol violation, and reading exactly the requested
    # length would make whether it gets noticed depend on process scheduling.
    if ! sensor chunk "$name" "$have" "$want" | head -c "$((want + 1))" > "$tmp"; then
      rm -f -- "$tmp"
      echo "pull: chunk request failed for $name at $have" >&2
      failed=1
      break
    fi
    got=$(stat -c %s -- "$tmp")
    if [ "$got" -gt "$want" ]; then
      rm -f -- "$tmp"
      echo "pull: sensor sent more than requested for $name, discarded" >&2
      failed=1
      break
    fi
    if [ "$got" -eq 0 ]; then
      rm -f -- "$tmp"
      echo "pull: empty chunk for $name at $have" >&2
      failed=1
      break
    fi
    cat -- "$tmp" >> "$name"
    rm -f -- "$tmp"
    have=$((have + got))
    fetched=$((fetched + got))
  done
done 3<<< "$manifest"

echo "pull: $fetched byte(s) from $files file(s) listed"
# The heartbeat the health view reads. Written only when every request in the
# cycle succeeded, so a pull that keeps failing lets it go stale and shows up.
[ "$failed" -eq 0 ] && : > .pulled
exit 0
