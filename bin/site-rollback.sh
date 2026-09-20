#!/usr/bin/env bash
# Undo the site v3 install. Usage:
#   sudo site-rollback.sh /opt/threat-radar/.backups/site-pre-<stamp>.tar.gz
# Derived tables are left in place. Pass --drop-tables to remove the ones v3
# added (source_stage, client_fp_daily, payload_submissions).
set -euo pipefail
APP="${TR_APP:-/opt/threat-radar}"
PY="$APP/venv/bin/python"
BACKUP="${1:-}"
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
[[ -f "$BACKUP" ]] || { echo "usage: $0 <backup.tar.gz> [--drop-tables]"; exit 2; }

tar -xzf "$BACKUP" -C "$APP"
echo "restored from $BACKUP"

# the old pages were moved, not deleted
for f in index.html persona.html insights.html; do
  [[ -f "$APP/app/static/_archive/$f" && ! -f "$APP/app/static/$f" ]] \
    && mv "$APP/app/static/_archive/$f" "$APP/app/static/$f"
done

rm -f /etc/systemd/system/radar-intel.service.d/10-samples.conf
systemctl daemon-reload

for f in /etc/nginx/sites-enabled/*.bak-radar-* /etc/nginx/conf.d/*.bak-radar-*; do
  [[ -f "$f" ]] || continue
  target="${f%.bak-radar-*}"
  cp -f "$f" "$target" && echo "nginx restored: $target"
done
nginx -t && systemctl reload nginx || true

if [[ "${2:-}" == "--drop-tables" ]]; then
  sudo -u "${TR_USER:-radar}" "$PY" - <<'PYEOF'
import os, sqlite3
db = os.environ.get("TR_DB", "/opt/threat-radar/data/radar.db")
con = sqlite3.connect(db, timeout=120)
for t in ("source_stage", "client_fp_daily", "payload_submissions"):
    con.execute(f"DROP TABLE IF EXISTS {t}")
con.commit(); con.close()
print("dropped v3 tables")
PYEOF
fi

systemctl restart radar-web
echo "done. Note: the persona views dropped by the migration are not restored;"
echo "re-run tr-upgrade/pi/radar_views.sql if you want them back."
