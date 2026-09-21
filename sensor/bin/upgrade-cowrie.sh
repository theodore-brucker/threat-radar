#!/usr/bin/env bash
# Move a Cowrie checkout to another upstream tag and re-apply the local patches.
#   sudo /opt/cowrie/bin/upgrade-cowrie.sh TAG PATCH_DIR [--dry-run]
#
# /opt/cowrie is a git checkout of upstream with two local patches applied to
# its source. The persona lives in untracked directories and in files upstream
# does not change between patch releases, so a checkout carries it across;
# this script refuses to continue if that stops being true. It does not restart
# Cowrie, because the restart is the step that needs watching.
#
# Rolling back is the same script with the previous tag, or the tarball it
# writes before changing anything.
set -euo pipefail

COWRIE_HOME="${COWRIE_HOME:-/opt/cowrie}"
TAG="${1:?usage: upgrade-cowrie.sh TAG PATCH_DIR [--dry-run]}"
PATCHES="${2:?usage: upgrade-cowrie.sh TAG PATCH_DIR [--dry-run]}"
DRY=0
[ "${3:-}" = "--dry-run" ] && DRY=1
PATCHED=(src/cowrie/commands/lspci.py src/cowrie/ssh/factory.py)

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
cd "$COWRIE_HOME"
[ -d .git ] || { echo "$COWRIE_HOME is not a git checkout"; exit 1; }
shopt -s nullglob
patch_files=("$PATCHES"/*.patch)
[ "${#patch_files[@]}" -gt 0 ] || { echo "no patches in $PATCHES"; exit 1; }

echo "==> preflight"
current=$(git describe --tags --always)
echo "    at $current, moving to $TAG"
git fetch --tags --quiet origin
git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null || { echo "no such tag: $TAG"; exit 1; }

# The only tracked files allowed to differ from upstream are the patched ones.
mapfile -t modified < <(git status --porcelain --untracked-files=no | awk '{print $2}')
unexpected=()
for f in "${modified[@]}"; do
  [ "$f" = "${PATCHED[0]}" ] || [ "$f" = "${PATCHED[1]}" ] || unexpected+=("$f")
done
if [ "${#unexpected[@]}" -gt 0 ]; then
  echo "    tracked files changed outside the patch set, refusing:"
  printf '      %s\n' "${unexpected[@]}"
  exit 1
fi

# The persona lives in untracked files. A checkout refuses to overwrite an
# untracked file that the target adds, which is safe but would stop this
# script halfway, so the collision is looked for first.
mapfile -t added < <(git diff --name-only --diff-filter=A HEAD "$TAG")
collide=()
for f in "${added[@]}"; do
  [ -e "$f" ] && collide+=("$f")
done
if [ "${#collide[@]}" -gt 0 ]; then
  echo "    $TAG adds files that exist here untracked, refusing:"
  printf '      %s\n' "${collide[@]}"
  exit 1
fi

# Prove the patches apply to the target before touching anything.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git worktree add --quiet --detach "$scratch/tree" "$TAG"
( cd "$scratch/tree" && git apply --check "${patch_files[@]}" ) \
  || { git worktree remove --force "$scratch/tree"; echo "    patches do not apply to $TAG"; exit 1; }
git worktree remove --force "$scratch/tree"
echo "    patches apply cleanly to $TAG"

if [ "$DRY" -eq 1 ]; then
  echo "==> dry run, nothing changed"
  exit 0
fi

echo "==> backup"
backup="/root/cowrie-${current}-$(date -u +%Y%m%dT%H%M%SZ).tgz"
tar czf "$backup" --exclude=./var -C "$COWRIE_HOME" .
echo "    $backup"

echo "==> upgrade"
git checkout --quiet -- "${PATCHED[@]}"
find src \( -name '*.orig.*' -o -name '*.bak.*' -o -name '*.rej' \) -delete
git checkout --quiet "$TAG"
git apply "${patch_files[@]}"
"$COWRIE_HOME/cowrie-env/bin/pip" install --quiet -e "$COWRIE_HOME"
"$COWRIE_HOME/cowrie-env/bin/pip" check
# Twisted keeps a plugin cache beside the plugins. The service cannot write it
# under ProtectSystem=strict and the tree belongs to root, so it is rebuilt
# here, as root, with Cowrie's own interpreter.
"$COWRIE_HOME/cowrie-env/bin/python" "$COWRIE_HOME/bin/regen-dropin.cache"

echo "==> result"
echo "    $(git describe --tags --dirty)"
"$COWRIE_HOME/cowrie-env/bin/pip" freeze | grep -i -E '^(cryptography|pyopenssl|twisted)==' | sed 's/^/    /'
git status --porcelain --untracked-files=no | sed 's/^/    /'
echo "==> done; restart cowrie and watch the login events"
