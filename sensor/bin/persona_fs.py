#!/usr/bin/env python3
"""persona_fs.py - apply a declarative filesystem spec to Cowrie's fs.pickle.

Why this exists
---------------
A canarytoken planted in a home directory was unreachable
for weeks. The contents were in honeyfs, but the *path* was never added to
fs.pickle, and Cowrie needs both: fs.pickle is the metadata tree that ls and
cat resolve against, honeyfs only supplies bytes once a path resolves. A file
present in one and absent from the other does not exist as far as a session
is concerned, and nothing reported the mismatch.

Hand-editing the pickle is how that happened, and how /home came to hold
duplicate entries. This replaces that with a spec you can read and re-apply.

Why not createfs
----------------
bin/createfs walks a real directory. Pointed at honeyfs it yields a tree with
nothing in /usr/bin, /etc or /var, which any session detects immediately.
Pointed at the sensor's own root it embeds this host's real layout, including
/opt/cowrie, into the filesystem attackers browse. Neither is acceptable, so
the shipped tree stays as the base and the persona is applied on top.

Usage
-----
  persona_fs.py check   [--fs PICKLE] [--honeyfs DIR] [--spec JSON]
  persona_fs.py apply   [--fs PICKLE] [--honeyfs DIR] [--spec JSON] [--dry-run]
  persona_fs.py show PATH [--fs PICKLE]

check exits non-zero when the tree and honeyfs disagree, so it can gate a
service start the way validate_userdb.py already does.
"""

import argparse
import datetime as dt
import json
import os
import pickle
import shutil
import stat
import sys
import time

# Cowrie's fs.py node layout. Verified at runtime rather than trusted: using
# the wrong constants makes getfile() dereference a None target and every
# session dies at "Error getting shell".
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, \
    A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(7)
NODE_WIDTH = 10

DEFAULT_FS = "/opt/cowrie/var/lib/cowrie/fs.pickle"
DEFAULT_HONEYFS = "/opt/cowrie/honeyfs"
DEFAULT_SPEC = "/opt/cowrie/persona/fs_spec.json"


def ctime_of(opts):
    """An ISO date from the spec becomes a POSIX timestamp. Anything the spec
    creates otherwise carries the time of the apply, which dates a persona to
    the afternoon it was staged."""
    raw = (opts or {}).get("ctime")
    if not raw:
        return None
    try:
        return dt.datetime.strptime(str(raw), "%Y-%m-%d").replace(
            tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        die(f"ctime {raw!r} is not YYYY-MM-DD")


def die(msg, code=2):
    sys.stderr.write(f"persona_fs: {msg}\n")
    sys.exit(code)


# ---------------------------------------------------------------------------
# loading and structural verification
# ---------------------------------------------------------------------------

def load(path):
    with open(path, "rb") as fh:
        tree = pickle.load(fh)
    verify_shape(tree, path)
    return tree


def verify_shape(tree, path):
    """Confirm the node layout matches what this tool assumes.

    A silent mismatch here is the failure that kills every session, so it is
    checked once up front instead of being discovered in production.
    """
    if not isinstance(tree, list) or len(tree) != NODE_WIDTH:
        die(f"{path}: root is not a {NODE_WIDTH}-field node; this Cowrie "
            f"version uses a different layout and this tool would corrupt it")
    if tree[A_TYPE] != T_DIR:
        die(f"{path}: root node is type {tree[A_TYPE]}, expected T_DIR={T_DIR}")
    if not isinstance(tree[A_CONTENTS], list):
        die(f"{path}: root contents is not a list")
    # Spot-check a few children to be sure the width is consistent.
    for child in tree[A_CONTENTS][:20]:
        if not isinstance(child, list) or len(child) != NODE_WIDTH:
            die(f"{path}: child node has width {len(child)}, expected {NODE_WIDTH}")


def save(tree, path, backup=True):
    if backup and os.path.exists(path):
        stamp = time.strftime("%Y%m%dT%H%M%S")
        shutil.copy2(path, f"{path}.bak.{stamp}")
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as fh:
        pickle.dump(tree, fh)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# tree navigation
# ---------------------------------------------------------------------------

def split(path):
    return [p for p in path.strip("/").split("/") if p not in ("", ".")]


def find(tree, path):
    """Resolve a path to its node, or None. Does not follow symlinks."""
    node = tree
    for part in split(path):
        if node[A_TYPE] != T_DIR:
            return None
        nxt = None
        for child in node[A_CONTENTS]:
            if child[A_NAME] == part:
                nxt = child
                break
        if nxt is None:
            return None
        node = nxt
    return node


def mkdir(tree, path, uid=0, gid=0, mode=0o40755, ctime=None, own=False):
    """Create a directory and any missing parents. Returns the node.

    own=True also corrects an existing directory's uid/gid/mode. Only the
    final component is re-owned; parents keep whatever they had, because a
    spec declaring /home/ubuntu should not silently re-own /home.
    """
    node = tree
    ctime = time.time() if ctime is None else ctime
    parts = split(path)
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        found = None
        for child in node[A_CONTENTS]:
            if child[A_NAME] == part:
                found = child
                break
        if found is None:
            found = [part, T_DIR, uid, gid, 4096, mode, ctime, [], None, None]
            node[A_CONTENTS].append(found)
        elif found[A_TYPE] != T_DIR:
            die(f"{path}: {part} exists and is not a directory")
        elif last and own:
            found[A_UID], found[A_GID], found[A_MODE] = uid, gid, mode
        node = found
    return node


def putlink(tree, path, target, uid=0, gid=0, mode=0o120777, ctime=None):
    """Create or repair a symlink. A link with a null target makes getfile()
    dereference None and kills the session, so repairing in place matters."""
    parts = split(path)
    if not parts:
        die("cannot write the root node as a link")
    parent = mkdir(tree, "/".join(parts[:-1])) if len(parts) > 1 else tree
    ctime = time.time() if ctime is None else ctime
    for child in parent[A_CONTENTS]:
        if child[A_NAME] == parts[-1]:
            child[A_TYPE] = T_LINK
            child[A_TARGET] = target
            child[A_MODE] = mode
            return child
    node = [parts[-1], T_LINK, uid, gid, len(target), mode, ctime, None,
            target, None]
    parent[A_CONTENTS].append(node)
    return node


def putfile(tree, path, size, uid=0, gid=0, mode=0o100644, ctime=None):
    """Create or update a file node. Parent directories are created."""
    parts = split(path)
    if not parts:
        die("cannot write the root node as a file")
    parent = mkdir(tree, "/".join(parts[:-1])) if len(parts) > 1 else tree
    ctime = time.time() if ctime is None else ctime
    for child in parent[A_CONTENTS]:
        if child[A_NAME] == parts[-1]:
            if child[A_TYPE] != T_FILE:
                die(f"{path}: exists and is not a regular file")
            child[A_SIZE] = size
            child[A_UID], child[A_GID], child[A_MODE] = uid, gid, mode
            return child
    node = [parts[-1], T_FILE, uid, gid, size, mode, ctime, None, None, None]
    parent[A_CONTENTS].append(node)
    return node


def remove(tree, path):
    """Delete a path. Returns True if something was removed."""
    parts = split(path)
    if not parts:
        die("refusing to remove the root node")
    parent = find(tree, "/".join(parts[:-1])) if len(parts) > 1 else tree
    if parent is None or parent[A_TYPE] != T_DIR:
        return False
    before = len(parent[A_CONTENTS])
    parent[A_CONTENTS][:] = [c for c in parent[A_CONTENTS] if c[A_NAME] != parts[-1]]
    return len(parent[A_CONTENTS]) != before


def dedupe(tree, path):
    """Collapse duplicate names inside one directory, keeping the first.

    /home held two ubuntu entries, one with corrupt permissions whose
    timestamp advanced on every restart. Duplicates are invisible to a normal
    ls and break getfile() in ways that are hard to trace back.
    """
    node = find(tree, path)
    if node is None or node[A_TYPE] != T_DIR:
        return []
    seen, kept, dropped = set(), [], []
    for child in node[A_CONTENTS]:
        if child[A_NAME] in seen:
            dropped.append(child[A_NAME])
            continue
        seen.add(child[A_NAME])
        kept.append(child)
    node[A_CONTENTS][:] = kept
    return dropped


def walk(node, prefix=""):
    """Yield (path, node) for the whole tree."""
    here = prefix or "/"
    yield here, node
    if node[A_TYPE] == T_DIR:
        for child in node[A_CONTENTS]:
            child_path = f"{prefix}/{child[A_NAME]}" if prefix else f"/{child[A_NAME]}"
            yield from walk(child, child_path)


# ---------------------------------------------------------------------------
# spec application
# ---------------------------------------------------------------------------

def apply_spec(tree, spec, honeyfs):
    """Apply a spec. Idempotent: running it twice changes nothing."""
    actions = []

    for path in spec.get("remove", []):
        if remove(tree, path):
            actions.append(("removed", path))

    for path in spec.get("dedupe", []):
        for name in dedupe(tree, path):
            actions.append(("deduped", f"{path}/{name}"))

    for d in spec.get("dirs", []):
        path = d["path"] if isinstance(d, dict) else d
        opts = d if isinstance(d, dict) else {}
        node = find(tree, path)
        existed = node is not None
        uid, gid = opts.get("uid", 0), opts.get("gid", 0)
        mode = opts.get("mode", 0o40755)
        rewned = existed and (node[A_UID] != uid or node[A_GID] != gid
                              or node[A_MODE] != mode)
        ct = ctime_of(opts)
        mkdir(tree, path, uid=uid, gid=gid, mode=mode, ctime=ct, own=True)
        if ct is not None:
            find(tree, path)[A_CTIME] = ct
        if not existed:
            actions.append(("mkdir", path))
        elif rewned:
            actions.append(("chown", path))

    # Repair symlinks before files, so a file declared under a repaired link
    # resolves during the check that follows.
    for l in spec.get("links", []):
        node = find(tree, l["path"])
        was_null = node is not None and node[A_TYPE] == T_LINK and not node[A_TARGET]
        existed = node is not None
        putlink(tree, l["path"], l["target"])
        if was_null:
            actions.append(("relink", f"{l['path']} -> {l['target']} (was null)"))
        elif not existed:
            actions.append(("link", f"{l['path']} -> {l['target']}"))

    for f in spec.get("files", []):
        path = f["path"] if isinstance(f, dict) else f
        opts = f if isinstance(f, dict) else {}
        real = os.path.join(honeyfs, path.lstrip("/"))
        # A token path with no content on this host gets no tree entry at all.
        # An entry sized 0 with nothing behind it is worse than absence: it
        # advertises a planted file that reads back empty.
        if opts.get("token") and not os.path.isfile(real):
            actions.append(("skip", f"{path} (token declared, no content here)"))
            continue
        # Size comes from the honeyfs file when it exists, so ls and cat agree.
        size = os.path.getsize(real) if os.path.isfile(real) else opts.get("size", 0)
        node = find(tree, path)
        if node is not None and node[A_TYPE] == T_LINK:
            die(f"{path}: declared as a file but exists as a symlink to "
                f"{node[A_TARGET]!r}. Put the contents at the link target "
                f"instead, or declare it under links[].")
        existed = node is not None
        changed = existed and node[A_SIZE] != size
        ct = ctime_of(opts)
        written = putfile(tree, path, size,
                          uid=opts.get("uid", 0), gid=opts.get("gid", 0),
                          mode=opts.get("mode", 0o100644), ctime=ct)
        if ct is not None:
            written[A_CTIME] = ct
        if not existed:
            actions.append(("create", path))
        elif changed:
            actions.append(("resize", f"{path} -> {size}"))

    return actions


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def check(tree, spec, honeyfs):
    """Every way these two can disagree, reported rather than discovered."""
    problems = []

    notes = []

    # 1. Spec paths must resolve. This is the canarytoken failure.
    for f in spec.get("files", []):
        path = f["path"] if isinstance(f, dict) else f
        opts = f if isinstance(f, dict) else {}
        real = os.path.join(honeyfs, path.lstrip("/"))
        if opts.get("token"):
            # Token contents never live in the repo, so absence on a given
            # host is expected there and a live problem on the sensor. Report
            # it as a note so a fresh checkout does not look broken, but say
            # plainly that the plant is not live.
            if not os.path.isfile(real):
                notes.append((path, "token path declared but no content on this "
                                    "host, so nothing is planted here"))
                continue
        node = find(tree, path)
        if node is None:
            problems.append((path, "declared in the spec but absent from fs.pickle; "
                                   "a session cannot see it"))
        elif node[A_TYPE] != T_FILE:
            problems.append((path, f"exists but is type {node[A_TYPE]}, not a file"))
    for d in spec.get("dirs", []):
        path = d["path"] if isinstance(d, dict) else d
        node = find(tree, path)
        if node is None:
            problems.append((path, "directory declared in the spec but absent"))
        elif node[A_TYPE] != T_DIR:
            problems.append((path, "exists but is not a directory"))

    # 2. Paths the spec removed must stay gone.
    for path in spec.get("remove", []):
        if find(tree, path) is not None:
            problems.append((path, "spec removes this but it is still present"))

    # 2b. Declared symlinks must point somewhere.
    for l in spec.get("links", []):
        node = find(tree, l["path"])
        if node is None:
            problems.append((l["path"], "declared as a link but absent"))
        elif node[A_TYPE] != T_LINK:
            problems.append((l["path"], "declared as a link but is not one"))
        elif node[A_TARGET] != l["target"]:
            problems.append((l["path"], f"points at {node[A_TARGET]!r}, "
                                        f"spec says {l['target']!r}"))

    # 3. Anything with contents in honeyfs must be reachable, or those bytes
    #    are never served. This is the general form of the canary bug.
    if os.path.isdir(honeyfs):
        for root, _dirs, files in os.walk(honeyfs):
            for name in files:
                real = os.path.join(root, name)
                virt = "/" + os.path.relpath(real, honeyfs).replace(os.sep, "/")
                node = find(tree, virt)
                if node is None:
                    problems.append((virt, "honeyfs has contents for this path but "
                                           "fs.pickle has no entry, so it is unreachable"))
                elif node[A_TYPE] == T_LINK:
                    # /etc/os-release is a symlink on real Ubuntu. Contents put
                    # at the link path are never read: the shell follows the
                    # link and serves whatever is at the target instead.
                    problems.append((virt, f"honeyfs holds contents here but the tree "
                                           f"has a symlink to {node[A_TARGET]!r}; a read "
                                           f"follows the link, so these bytes are never "
                                           f"served. Move them to the target path."))
                elif node[A_TYPE] == T_FILE:
                    actual = os.path.getsize(real)
                    if node[A_SIZE] != actual:
                        problems.append((virt, f"size in fs.pickle is {node[A_SIZE]} "
                                               f"but honeyfs holds {actual} bytes"))

    # 4. Structural faults that kill sessions rather than merely misleading.
    for path, node in walk(tree):
        if len(node) != NODE_WIDTH:
            problems.append((path, f"node width {len(node)}, expected {NODE_WIDTH}"))
            continue
        if node[A_TYPE] == T_LINK and not node[A_TARGET]:
            problems.append((path, "symlink with a null target; getfile() "
                                   "dereferences this and the session dies"))
        if node[A_TYPE] == T_DIR and not isinstance(node[A_CONTENTS], list):
            problems.append((path, "directory whose contents is not a list"))

    # 5. Duplicate names in one directory.
    for path, node in walk(tree):
        if node[A_TYPE] != T_DIR:
            continue
        names = [c[A_NAME] for c in node[A_CONTENTS]]
        for name in {n for n in names if names.count(n) > 1}:
            problems.append((f"{path}/{name}", "appears more than once in its parent"))

    return problems, notes


# ---------------------------------------------------------------------------

def _report(problems, notes):
    if notes:
        print(f"{len(notes)} note(s):")
        for path, why in notes:
            print(f"  {path}\n    {why}")
    if problems:
        print(f"{len(problems)} problem(s):")
        for path, why in problems[:40]:
            print(f"  {path}\n    {why}")
        if len(problems) > 40:
            print(f"  ... {len(problems) - 40} more")


def cmd_check(args):
    tree = load(args.fs)
    spec = json.load(open(args.spec)) if os.path.exists(args.spec) else {}
    problems, notes = check(tree, spec, args.honeyfs)
    _report(problems, notes)
    if not problems:
        total = sum(1 for _ in walk(tree))
        print(f"ok: {total} nodes, spec and honeyfs agree")
        return 0
    return 1


def cmd_apply(args):
    tree = load(args.fs)
    spec = json.load(open(args.spec))
    actions = apply_spec(tree, spec, args.honeyfs)
    for what, path in actions:
        print(f"  {what:8} {path}")
    problems, notes = check(tree, spec, args.honeyfs)
    if notes:
        print()
        _report([], notes)
    if problems:
        print(f"\nREFUSING TO WRITE: {len(problems)} problem(s) after applying:")
        for path, why in problems[:20]:
            print(f"  {path}\n    {why}")
        return 2
    if args.dry_run:
        print(f"\ndry run: {len(actions)} change(s) not written")
        return 0
    save(tree, args.fs)
    print(f"\nwrote {args.fs} ({len(actions)} change(s)), backup alongside it")
    return 0


def cmd_show(args):
    tree = load(args.fs)
    node = find(tree, args.path)
    if node is None:
        print(f"{args.path}: not in the tree")
        return 1
    kind = {T_DIR: "dir", T_FILE: "file", T_LINK: "link"}.get(node[A_TYPE], node[A_TYPE])
    print(f"{args.path}: {kind} uid={node[A_UID]} gid={node[A_GID]} "
          f"size={node[A_SIZE]} mode={stat.filemode(node[A_MODE])}")
    if node[A_TYPE] == T_LINK:
        print(f"  target: {node[A_TARGET]!r}")
    if node[A_TYPE] == T_DIR:
        for child in sorted(node[A_CONTENTS], key=lambda c: c[A_NAME]):
            ck = {T_DIR: "d", T_FILE: "-", T_LINK: "l"}.get(child[A_TYPE], "?")
            print(f"  {ck} {child[A_NAME]}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fs", default=DEFAULT_FS)
    ap.add_argument("--honeyfs", default=DEFAULT_HONEYFS)
    ap.add_argument("--spec", default=DEFAULT_SPEC)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--dry-run", action="store_true")
    p_show = sub.add_parser("show")
    p_show.add_argument("path")
    args = ap.parse_args()

    if not os.path.exists(args.fs):
        die(f"no filesystem pickle at {args.fs}")
    return {"check": cmd_check, "apply": cmd_apply, "show": cmd_show}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
