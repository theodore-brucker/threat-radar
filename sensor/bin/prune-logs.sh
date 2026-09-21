#!/bin/bash
# Sensor-side retention. Two caps so the VPS disk never fills:
#   AGE  - delete rotated logs older than SENSOR_RETAIN_DAYS
#   SIZE - if the log directory still exceeds SENSOR_MAX_MB, delete the
#          oldest rotated logs until it fits
# The live cowrie.json is never deleted.
set -u
LOGDIR=/opt/cowrie/var/log/cowrie
RETAIN_DAYS="${SENSOR_RETAIN_DAYS:-7}"
MAX_MB="${SENSOR_MAX_MB:-2048}"

cd "$LOGDIR" || exit 1
find . -maxdepth 1 -name 'cowrie.json.20*' -mtime "+${RETAIN_DAYS}" -print -delete

while :; do
  SIZE_MB=$(du -sm "$LOGDIR" | cut -f1)
  [ "$SIZE_MB" -le "$MAX_MB" ] && break
  OLDEST=$(find . -maxdepth 1 -name 'cowrie.json.20*' -printf '%T@ %f\n' 2>/dev/null \
           | sort -n | head -1 | cut -d' ' -f2)
  [ -z "${OLDEST:-}" ] && break
  echo "size cap ${SIZE_MB}MB > ${MAX_MB}MB, removing $OLDEST"
  rm -f "$OLDEST"
done
