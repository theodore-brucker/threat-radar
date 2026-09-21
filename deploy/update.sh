#!/usr/bin/env bash
# Pull the latest source from GitHub and restart the affected services.
#   sudo /opt/threat-radar/deploy/update.sh [branch] [--config]
#
# Ownership: the code tree belongs to root and the service account owns only
# what it has to write, which is data/, spool/ and the pull key. The previous
# version handed the whole tree including .git to the service account, so
# anything running as radar could edit the code that root then executed, and
# root ran git inside a repository that account could rewrite.
#
# --config also installs the unit files and the nginx config from deploy/.
# That is off by default so a routine code deploy never changes the shape of
# the deployment without being asked for it.
set -euo pipefail

REPO=/opt/threat-radar
SERVICE_USER=radar
DEPLOY_KEY=/root/.ssh/radar_deploy
BRANCH=main
WITH_CONFIG=0
SERVICES=(radar-web radar-ingest radar-enrich)

for arg in "$@"; do
  case "$arg" in
    --config) WITH_CONFIG=1 ;;
    -*)       echo "unknown option: $arg" >&2; exit 2 ;;
    *)        BRANCH="$arg" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -d "$REPO/.git" ] || { echo "no git repo at $REPO"; exit 1; }

owner=$(stat -c '%U' "$REPO/.git")
if [ "$owner" != "root" ]; then
  echo "WARNING: $REPO/.git is owned by $owner, not root."
  echo "         Run deploy/install-ownership.sh once to fix the tree."
fi

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
# requirements.txt pins every transitive dependency with its hashes, so a
# package that changed on the index, or one the lock does not list, fails the
# install instead of landing silently on the collector.
"$REPO/venv/bin/pip" install --quiet --no-cache-dir --require-hashes -r "$REPO/requirements.txt"

echo "==> ownership"
chown -R root:root "$REPO"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$REPO/data" "$REPO/spool"
chmod 750 "$REPO/data" "$REPO/spool"
for f in .ssh_pull .ssh_pull.pub .ssh_known_hosts; do
  [ -e "$REPO/$f" ] && chown "$SERVICE_USER":"$SERVICE_USER" "$REPO/$f"
done
[ -e "$REPO/.ssh_pull" ] && chmod 600 "$REPO/.ssh_pull"
for f in "$REPO"/data/radar.db*; do [ -e "$f" ] && chmod 640 "$f"; done

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

changed_units=0
changed_nginx=0

report_or_install() {
  # $1 source in the repo, $2 destination, $3 mode
  local src="$1" dst="$2" mode="$3"
  if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
    return 1
  fi
  if [ "$WITH_CONFIG" -eq 1 ]; then
    install -m "$mode" -o root -g root "$src" "$dst"
    echo "    installed $dst"
  else
    echo "    differs: $dst"
  fi
  return 0
}

echo "==> configuration"
for src in "$REPO"/deploy/systemd/*.service "$REPO"/deploy/systemd/*.timer; do
  if report_or_install "$src" "/etc/systemd/system/$(basename "$src")" 644; then
    changed_units=1
  fi
done

mapfile -t leftover < <(find /etc/systemd/system -maxdepth 2 -path '*/radar-*.service.d/*.conf' 2>/dev/null || true)
if [ "${#leftover[@]}" -gt 0 ]; then
  echo "    drop-ins present, these override the versioned units:"
  printf '      %s\n' "${leftover[@]}"
fi

if report_or_install "$REPO/deploy/nginx/radar.conf" /etc/nginx/sites-available/radar 644; then
  changed_nginx=1
fi

if [ "$WITH_CONFIG" -eq 0 ] && { [ "$changed_units" -eq 1 ] || [ "$changed_nginx" -eq 1 ]; }; then
  echo "    run with --config to install the differences above"
fi

if [ "$WITH_CONFIG" -eq 1 ] && [ "$changed_units" -eq 1 ]; then
  systemctl daemon-reload
  echo "    systemd reloaded"
fi

if [ "$WITH_CONFIG" -eq 1 ] && [ "$changed_nginx" -eq 1 ]; then
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
    echo "    nginx reloaded"
  else
    echo "    nginx config test FAILED, not reloading:"
    nginx -t 2>&1 | sed 's/^/      /'
    exit 1
  fi
fi

echo "==> restarting services"
systemctl restart "${SERVICES[@]}"
sleep 3
for s in "${SERVICES[@]}"; do
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
