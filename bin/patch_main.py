#!/usr/bin/env python3
"""Wire the insights router into app/main.py without touching anything else.

The block is inserted ahead of the first top-level app.mount(...) call, because
a mount on "/" is matched before any route registered after it. If there is no
mount, the block goes at the end of the file. Running this twice is a no-op.
"""

import os
import re
import shutil
import sys
import time

MARKER = "radar-insights"
BLOCK = '''
# --- radar-insights (v2 analytics pack) ---
try:
    from app.routers.insights import router as _insights_router

    app.include_router(_insights_router)
except Exception as _insights_err:  # never take the base dashboard down with it
    import logging

    logging.getLogger("uvicorn.error").warning(
        "radar-insights router not loaded: %s", _insights_err
    )
# --- end radar-insights ---
'''


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/opt/threat-radar/app/main.py"
    if not os.path.exists(path):
        print(f"main.py not found at {path}")
        return 1

    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()

    if MARKER in src:
        print("already patched, nothing to do")
        return 0

    backup = f"{path}.bak-insights-{time.strftime('%Y%m%d%H%M%S')}"
    shutil.copy2(path, backup)

    lines = src.splitlines(keepends=True)
    insert_at = None
    for i, line in enumerate(lines):
        if re.match(r"^app\.mount\(", line):
            insert_at = i
            break
    if insert_at is None:
        out = src.rstrip("\n") + "\n" + BLOCK
        where = "end of file"
    else:
        out = "".join(lines[:insert_at]) + BLOCK + "\n" + "".join(lines[insert_at:])
        where = f"before the mount on line {insert_at + 1}"

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"patched {path} ({where}); backup at {backup}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
