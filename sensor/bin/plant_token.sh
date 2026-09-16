#!/usr/bin/env bash
# plant_token.sh - install canarytoken content at a path the spec declares.
#
#   plant_token.sh /etc/example/token.conf /tmp/token.txt
#
# Token content never lives in the repo, so this is how it gets onto the
# sensor: copy the file into honeyfs at the virtual path, set ownership and
# mode, then re-apply the spec so fs.pickle carries a matching entry.
#
# Why both steps matter: honeyfs supplies bytes, fs.pickle supplies the entry
# a session resolves against. Content with no entry is unreachable, which is
# the state the AWS token sat in for three weeks. An entry with no content is
# worse, because it advertises a planted file that reads back empty, so
# persona_fs skips those rather than stubbing them.
set -euo pipefail

COWRIE=${COWRIE:-/opt/cowrie}
HONEYFS="$COWRIE/honeyfs"
SPEC="$COWRIE/persona/fs_spec.json"
TOOL="$COWRIE/bin/persona_fs.py"

VIRT=${1:?usage: plant_token.sh <virtual-path> <source-file>}
SRC=${2:?usage: plant_token.sh <virtual-path> <source-file>}

[ -f "$SRC" ] || { echo "no such source file: $SRC" >&2; exit 1; }

# The path must be declared in the spec, or apply will not create an entry for
# it and the plant is inert. Fail here rather than after copying.
python3 - "$SPEC" "$VIRT" <<'PY' || exit 1
import json, sys
spec, virt = json.load(open(sys.argv[1])), sys.argv[2]
paths = [f["path"] if isinstance(f, dict) else f for f in spec.get("files", [])]
if virt not in paths:
    sys.stderr.write(
        f"{virt} is not declared in fs_spec.json.\n"
        f"Add it to files[] with \"token\": true first, or the content will\n"
        f"sit in honeyfs with no entry in the tree and never be readable.\n")
    sys.exit(1)
PY

DEST="$HONEYFS/${VIRT#/}"
mkdir -p "$(dirname "$DEST")"
install -m 0600 "$SRC" "$DEST"
chown -R cowrie:cowrie "$(dirname "$DEST")"
echo "planted $(wc -c < "$DEST") bytes at $VIRT"

python3 "$TOOL" apply
python3 "$TOOL" check

cat <<EOF

Planted. Two things worth doing now:

  1. Read it back the way an attacker would, over the honeypot rather than
     from the shell:
       ssh -p 2222 <a-userdb-account>@127.0.0.1
       cat $VIRT
  2. Confirm the token fires. Reading it should produce an alert from
     whoever issues it. A token that does not alert is decoration.
EOF
