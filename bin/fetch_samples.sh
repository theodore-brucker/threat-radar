#!/usr/bin/env bash
# Pull Cowrie captures from the sensor over the existing forced-command key.
# No inference: if config is missing this fails loudly rather than skipping.
set -euo pipefail
CONF=/etc/threat-radar.env
[ -r "$CONF" ] && . "$CONF"
: "${SENSOR_TS_IP:?SENSOR_TS_IP not set in /etc/threat-radar.env}"

DEST="${TR_SAMPLE_DIR:-/opt/threat-radar/data/samples}"
KEY=/opt/threat-radar/.ssh_pull
KH=/opt/threat-radar/.ssh_known_hosts
SSH_OPTS=(-n -T -i "$KEY" -p 2200 -o UserKnownHostsFile="$KH"
          -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15)

cd / || exit 1
mkdir -p "$DEST"
new=0; have=0; bad=0

while read -r size sha; do
  [ -n "${sha:-}" ] || continue
  if [ -s "${DEST}/${sha}" ]; then have=$((have+1)); continue; fi
  tmp="${DEST}/.${sha}.part"
  if ! ssh "${SSH_OPTS[@]}" cowrie@"$SENSOR_TS_IP" "samples-get ${sha}" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; bad=$((bad+1)); continue
  fi
  # Trust nothing: the filename is the content hash, so prove it.
  got=$(sha256sum "$tmp" | cut -d' ' -f1)
  if [ "$got" != "$sha" ]; then
    rm -f "$tmp"; bad=$((bad+1))
    echo "fetch_samples: hash mismatch for ${sha:0:16}, discarded" >&2
    continue
  fi
  mv "$tmp" "${DEST}/${sha}"
  chmod 640 "${DEST}/${sha}"
  new=$((new+1))
done < <(ssh "${SSH_OPTS[@]}" cowrie@"$SENSOR_TS_IP" samples-list 2>/dev/null)

chown -R radar:radar "$DEST" 2>/dev/null || true
echo "fetch_samples: ${new} new, ${have} already local, ${bad} failed, $(find "$DEST" -type f ! -name '.*' | wc -l) total"
[ "$new" -eq 0 ] && [ "$have" -eq 0 ] && { echo "fetch_samples: sensor returned no samples" >&2; exit 1; }
exit 0
