#!/usr/bin/env bash
# One-time move to the ownership model described in deploy/README.md.
#   sudo /opt/threat-radar/deploy/install-ownership.sh [--dry-run]
#
# Before: the whole tree, including .git and the deploy scripts, belonged to
# the service account, and root's git safe.directory trusted it. Anything able
# to execute as that account could therefore edit a hook, the git config or
# this script, and root would run the result on the next deploy.
#
# After: root owns the code, the service account owns data/, spool/ and the
# pull key, and nothing the services can write is ever executed by root.
set -euo pipefail

REPO=/opt/threat-radar
SERVICE_USER=radar
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -d "$REPO/.git" ] || { echo "no git repo at $REPO"; exit 1; }

run() {
  if [ "$DRY" -eq 1 ]; then
    printf 'would run: %s\n' "$*"
  else
    "$@"
  fi
}

echo "==> code tree to root"
run chown -R root:root "$REPO"

echo "==> writable paths back to $SERVICE_USER"
run chown -R "$SERVICE_USER":"$SERVICE_USER" "$REPO/data" "$REPO/spool"
run chmod 750 "$REPO/data" "$REPO/spool"
for f in .ssh_pull .ssh_pull.pub .ssh_known_hosts; do
  [ -e "$REPO/$f" ] && run chown "$SERVICE_USER":"$SERVICE_USER" "$REPO/$f"
done
[ -e "$REPO/.ssh_pull" ] && run chmod 600 "$REPO/.ssh_pull"
for f in "$REPO"/data/radar.db*; do [ -e "$f" ] && run chmod 640 "$f"; done

echo "==> lock files that moved to the unit RuntimeDirectory"
for f in "$REPO/.pull.lock" "$REPO/.insights.lock"; do
  [ -e "$f" ] && run rm -f "$f"
done

echo "==> root no longer needs to trust a tree it does not own"
if git config --global --get-all safe.directory 2>/dev/null | grep -qx "$REPO"; then
  run git config --global --unset-all safe.directory "$REPO"
fi

echo "==> result"
stat -c '%U:%G %a %n' "$REPO" "$REPO/.git" "$REPO/deploy/update.sh" "$REPO/venv" \
  "$REPO/data" "$REPO/spool" 2>/dev/null
echo "==> done"
