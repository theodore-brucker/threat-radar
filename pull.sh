#!/usr/bin/env bash
# Pull Cowrie logs from the sensor over the tailnet.
# Pulls the live log AND the most recent rotated file, so daily rotation
# never leaves a gap. The ingester de-duplicates by line hash, so
# overlapping pulls are safe and idempotent.
set -u
exec 9>/opt/threat-radar/.pull.lock
flock -n 9 || exit 0          # a previous run is still going; skip this tick

# Sensor address lives outside the repo so it is never committed.
CONF=/etc/threat-radar.env
[ -r "$CONF" ] && . "$CONF"
: "${SENSOR_TS_IP:?SENSOR_TS_IP not set in /etc/threat-radar.env}"

KEY=/opt/threat-radar/.ssh_pull
KH=/opt/threat-radar/.ssh_known_hosts
SPOOL=/opt/threat-radar/spool

ssh -T -i "$KEY" -p 2200 \
    -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new \
    -o BatchMode=yes -o ConnectTimeout=10 \
    cowrie@"$SENSOR_TS_IP" > "${SPOOL}/pull.tmp" || exit 1

# The sensor-side wrapper emits a tar of the current + newest rotated log.
if tar -tf "${SPOOL}/pull.tmp" >/dev/null 2>&1; then
    tar -xf "${SPOOL}/pull.tmp" -C "$SPOOL" && rm -f "${SPOOL}/pull.tmp"
else
    mv "${SPOOL}/pull.tmp" "${SPOOL}/cowrie.json"
fi
