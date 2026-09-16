#!/usr/bin/env python3
"""Duplicate the existing /api/chat nginx block for /api/v1/chat.

The chat endpoint moved under /api/v1. Its old location block carries longer
proxy timeouts, so the new path needs the same treatment. This copies the
block rather than rewriting it, so any timeout or buffering tuning already
there carries over. Backs up, tests with nginx -t, and reverts on failure.
"""

import glob
import os
import shutil
import subprocess
import sys
import time

OLD = "location /api/chat"
NEW = "location /api/v1/chat"


def find_block(text, start):
    depth, i = 0, text.index("{", start)
    depth = 1
    j = i + 1
    while j < len(text) and depth:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
        j += 1
    return start, j


def main():
    targets = sys.argv[1:] or (
        glob.glob("/etc/nginx/sites-enabled/*") + glob.glob("/etc/nginx/conf.d/*.conf")
    )
    changed = []
    for path in targets:
        if not os.path.isfile(path):
            continue
        text = open(path, encoding="utf-8").read()
        if NEW in text:
            print(f"{path}: already has {NEW}")
            continue
        if OLD not in text:
            continue
        start = text.index(OLD)
        s, e = find_block(text, start)
        block = text[s:e]
        new_block = block.replace(OLD, NEW, 1)
        backup = f"{path}.bak-radar-{time.strftime('%Y%m%d%H%M%S')}"
        shutil.copy2(path, backup)
        open(path, "w", encoding="utf-8").write(
            text[:s] + new_block + "\n\n    " + text[s:]
        )
        changed.append((path, backup))
        print(f"{path}: added {NEW} (backup {backup})")

    if not changed:
        print("no /api/chat block found; nothing to do")
        return 0

    try:
        test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    except FileNotFoundError:
        print("nginx binary not found; edit applied but not validated")
        return 0
    if test.returncode != 0:
        for path, backup in changed:
            shutil.copy2(backup, path)
        print("nginx -t failed, reverted:\n" + test.stderr)
        return 1
    subprocess.run(["systemctl", "reload", "nginx"], check=False)
    print("nginx reloaded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
