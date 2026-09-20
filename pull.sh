#!/usr/bin/env bash
# Pull Cowrie logs from the sensor over the tailnet.
# Pulls the live log AND the most recent rotated file, so daily rotation
# never leaves a gap. The ingester de-duplicates by line hash, so
# overlapping pulls are safe and idempotent.
set -u
# The service account does not own the repository, so the lock lives in the
# unit's RuntimeDirectory. The fallback is for a run by hand outside systemd.
exec 9>"${RUNTIME_DIRECTORY:-/tmp}/pull.lock"
flock -n 9 || exit 0          # a previous run is still going; skip this tick

# Sensor address lives outside the repo so it is never committed. The unit
# supplies it through EnvironmentFile; this is for a run by hand.
CONF="${TR_PULL_ENV:-/etc/threat-radar/pull.env}"
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"
: "${SENSOR_TS_IP:?SENSOR_TS_IP not set in $CONF}"

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
