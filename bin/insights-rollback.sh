#!/usr/bin/env bash
# Undo the insights pack. Usage: sudo insights-rollback.sh /opt/threat-radar/.backups/insights-pre-<stamp>.tar.gz
# The derived tables are left in place; they are additive and pruned with the
# rest of the database. Pass --drop-tables to remove them too.
set -euo pipefail

APP="${TR_APP:-/opt/threat-radar}"
PY="$APP/venv/bin/python"
BACKUP="${1:-}"
DROP=0
[[ "${2:-}" == "--drop-tables" ]] && DROP=1

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
[[ -f "$BACKUP" ]] || { echo "usage: $0 <backup.tar.gz> [--drop-tables]"; exit 2; }

systemctl disable --now radar-intel.timer 2>/dev/null || true
rm -f /etc/systemd/system/radar-intel.service /etc/systemd/system/radar-intel.timer
systemctl daemon-reload

tar -xzf "$BACKUP" -C "$APP"
echo "restored files from $BACKUP"

# If main.py in the backup predates the patch, this is already undone. If not,
# strip the block by hand.
"$PY" - <<'PYEOF'
import os, re
path = os.path.join(os.environ.get("TR_APP", "/opt/threat-radar"), "app", "main.py")
src = open(path).read()
if "radar-insights" in src:
    src = re.sub(r"\n# --- radar-insights.*?# --- end radar-insights ---\n",
                 "\n", src, flags=re.S)
    open(path, "w").write(src)
    print("removed the insights block from main.py")
else:
    print("main.py has no insights block")
PYEOF

if [[ "$DROP" -eq 1 ]]; then
  sudo -u "${TR_USER:-radar}" "$PY" - <<'PYEOF'
import os, sqlite3
db = os.environ.get("TR_DB", "/opt/threat-radar/data/radar.db")
con = sqlite3.connect(db, timeout=120)
for t in ("asn_ip_daily","eventid_daily","session_facts","tunnel_targets",
          "payloads","payload_sightings","payload_intel","cred_pairs",
          "cred_pair_tags","cred_tag_ips","spike_annotations","insights_state"):
    con.execute(f"DROP TABLE IF EXISTS {t}")
con.execute("DROP INDEX IF EXISTS idx_raw_eventid_ts")
con.commit(); con.execute("VACUUM"); con.close()
print("dropped insights tables from", db)
PYEOF
fi

systemctl restart radar-web
echo "done"
