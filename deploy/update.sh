#!/usr/bin/env bash
# Pull the latest source from GitHub and restart the affected services.
#   sudo /opt/threat-radar/deploy/update.sh [branch]
#
# Runs git as root (root has a real HOME and can write the radar-owned tree),
# then hands ownership back to the radar service account. Only tracked source
# is replaced: the database, spool, venv, SSH keys and /etc/threat-radar.env
# are gitignored or live outside the repo, so an update never touches
# captured data or secrets.
set -euo pipefail

REPO=/opt/threat-radar
BRANCH="${1:-main}"
DEPLOY_KEY=/root/.ssh/radar_deploy

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -d "$REPO/.git" ] || { echo "no git repo at $REPO"; exit 1; }

export GIT_SSH_COMMAND="ssh -i $DEPLOY_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
cd "$REPO"

OLD=$(git rev-parse --short HEAD)
echo "==> fetching origin/$BRANCH (at $OLD)"
git fetch --quiet origin "$BRANCH"
git reset --hard --quiet "origin/$BRANCH"
NEW=$(git rev-parse --short HEAD)

if [ "$OLD" = "$NEW" ]; then
  echo "==> already up to date at $NEW"
else
  echo "==> updated $OLD -> $NEW"
  git --no-pager log --oneline "$OLD..$NEW" | sed 's/^/    /' || true
fi

echo "==> syncing dependencies"
sudo -u radar "$REPO/venv/bin/pip" install --quiet --no-cache-dir -r "$REPO/requirements.txt"

echo "==> permissions"
chown -R radar:radar "$REPO"
chmod +x "$REPO"/pull.sh "$REPO"/deploy/*.sh "$REPO"/sensor/*.sh 2>/dev/null || true

echo "==> restarting services"
systemctl restart radar-web radar-ingest radar-enrich
sleep 3
for s in radar-web radar-ingest radar-enrich; do
  printf '    %-14s %s\n' "$s" "$(systemctl is-active "$s")"
done

echo "==> health check"
if curl -fsS http://127.0.0.1:8080/api/v1/meta >/dev/null 2>&1; then
  echo "    API responding"
else
  echo "    WARNING: API not responding - check: journalctl -u radar-web -n 30"
  exit 1
fi
echo "==> done"
