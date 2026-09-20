#!/usr/bin/env bash
# One-time move of /opt/cowrie to root ownership.
#   sudo /opt/cowrie/bin/install-ownership.sh [--dry-run]
#
# The account Cowrie runs as owned everything: the code, the patched upstream
# source, cowrie.cfg, the userdb, the validator that gates start-up, the
# forced-command wrapper, and its own authorized_keys. That account is the
# process attackers are invited to break. Owning the wrapper means deciding
# what the collector receives; owning authorized_keys means removing the
# forced command; owning the validator means removing the check that keeps a
# bad userdb from taking authentication down.
#
# After this, the account can write var/ and nothing else.
set -euo pipefail

COWRIE_HOME=/opt/cowrie
COWRIE_USER=cowrie
KEYDIR=/etc/ssh/authorized_keys
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -d "$COWRIE_HOME/var" ] || { echo "no cowrie install at $COWRIE_HOME"; exit 1; }

run() {
  if [ "$DRY" -eq 1 ]; then printf 'would run: %s\n' "$*"; else "$@"; fi
}

echo "==> install tree to root"
run chown -R root:root "$COWRIE_HOME"
# The account still has to traverse and read its own install.
run chmod 750 "$COWRIE_HOME"
run chgrp "$COWRIE_USER" "$COWRIE_HOME"

echo "==> runtime state stays with $COWRIE_USER"
run chown -R "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_HOME/var"
run chmod 750 "$COWRIE_HOME/var"

echo "==> configuration readable, not writable"
for f in "$COWRIE_HOME/cowrie.cfg" "$COWRIE_HOME/etc/cowrie.cfg" "$COWRIE_HOME/etc/userdb.txt"; do
  if [ -e "$f" ]; then
    run chown root:"$COWRIE_USER" "$f"
    run chmod 640 "$f"
  fi
done
run chmod 755 "$COWRIE_HOME/etc"

echo "==> forced-command key out of the account's home"
run install -d -m 755 -o root -g root "$KEYDIR"
if [ -f "$COWRIE_HOME/.ssh/authorized_keys" ] && [ ! -f "$KEYDIR/$COWRIE_USER" ]; then
  run install -m 644 -o root -g root "$COWRIE_HOME/.ssh/authorized_keys" "$KEYDIR/$COWRIE_USER"
  echo "    copied to $KEYDIR/$COWRIE_USER, review the options on that line"
else
  echo "    $KEYDIR/$COWRIE_USER already present or no source file, left alone"
fi

echo "==> result"
stat -c '%U:%G %a %n' "$COWRIE_HOME" "$COWRIE_HOME/bin/pull-logs.sh" "$COWRIE_HOME/etc" \
  "$COWRIE_HOME/etc/userdb.txt" "$COWRIE_HOME/cowrie.cfg" "$COWRIE_HOME/var" \
  "$COWRIE_HOME/var/lib/cowrie/downloads" "$KEYDIR/$COWRIE_USER" 2>/dev/null
echo "==> done"
