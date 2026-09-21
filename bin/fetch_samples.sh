#!/usr/bin/env bash
# Pull Cowrie captures from the sensor over the collector's forced-command key.
#
# Runs as the insights worker's ExecStartPre. The sensor address comes from
# the unit's environment, the same pull.env the log pull reads. An earlier
# version sourced a combined env file directly, and when that file was split
# by consumer this script lost the address and failed on every run without
# anything noticing, because the unit tolerates its failure on purpose.
#
# The sensor is the host this project exists to have attacked, so nothing it
# returns is trusted: every listed name must be a sha256 before it touches a
# path, every download is capped, and a file is kept only if its content
# hashes to its name.
set -euo pipefail

: "${SENSOR_TS_IP:?SENSOR_TS_IP not set; the unit should read /etc/threat-radar/pull.env}"

DEST="${TR_SAMPLE_DIR:-/opt/threat-radar/data/samples}"
BASE="${TR_BASE:-/opt/threat-radar}"
KEY="$BASE/.ssh_pull"
KNOWN="$BASE/.ssh_known_hosts"
MAX_SAMPLE=$((32 * 1024 * 1024))
MAX_LISTED=10000
SHA_RE='^[0-9a-f]{64}$'
NUM_RE='^[0-9]{1,12}$'

sensor() {
  if [ -n "${TR_PULL_TRANSPORT:-}" ]; then
    SSH_ORIGINAL_COMMAND="$*" "$TR_PULL_TRANSPORT"
    return
  fi
  timeout 120 ssh -n -T -i "$KEY" -p 2200 \
      -o IdentitiesOnly=yes -o BatchMode=yes \
      -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=2 \
      cowrie@"$SENSOR_TS_IP" "$*"
}

mkdir -p "$DEST"
cd "$DEST"
rm -f -- .*.part

listing=$(sensor samples-list) || { echo "fetch_samples: listing request failed" >&2; exit 1; }
new=0 have=0 bad=0 listed=0

# The listing is read on descriptor 3 so that no request made inside the loop
# can consume it; ssh reads standard input unless told otherwise.
while read -r size sha <&3; do
  [ -n "${sha:-}" ] || continue
  listed=$((listed + 1))
  [ "$listed" -le "$MAX_LISTED" ] || break
  if ! [[ $sha =~ $SHA_RE && $size =~ $NUM_RE ]] || [ "$size" -gt "$MAX_SAMPLE" ]; then
    bad=$((bad + 1))
    echo "fetch_samples: ignoring malformed listing line" >&2
    continue
  fi
  if [ -s "$sha" ]; then have=$((have + 1)); continue; fi

  tmp=".$sha.part"
  if ! sensor samples-get "$sha" | head -c "$MAX_SAMPLE" > "$tmp"; then
    rm -f -- "$tmp"; bad=$((bad + 1)); continue
  fi
  # The filename is the content hash, so prove it.
  got=$(sha256sum -- "$tmp" | cut -d' ' -f1)
  if [ "$got" != "$sha" ]; then
    rm -f -- "$tmp"; bad=$((bad + 1))
    echo "fetch_samples: hash mismatch for ${sha:0:16}, discarded" >&2
    continue
  fi
  mv -- "$tmp" "$sha"
  chmod 640 -- "$sha"
  new=$((new + 1))
done 3<<< "$listing"

total=$(find . -maxdepth 1 -type f ! -name '.*' | wc -l)
echo "fetch_samples: ${new} new, ${have} already local, ${bad} failed, ${total} total"
if [ "$new" -eq 0 ] && [ "$have" -eq 0 ]; then
  echo "fetch_samples: sensor returned no samples" >&2
  exit 1
fi
