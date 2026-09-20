#!/usr/bin/env python3
"""Validate a Cowrie userdb.txt before it can take the honeypot offline.

Cowrie reloads this file on every authentication attempt, so one malformed
line stops all authentication and logs nothing at the login stage. This runs
as an ExecStartPre gate on cowrie.service: a FATAL finding means the sensor
refuses to start rather than running with authentication silently dead, which
is the state that went unnoticed for seventeen days in July 2026.

The rules live in cowrie_userdb.py, which mirrors Cowrie's own parser, so this
gate and the generator that writes the file cannot drift apart.

  validate_userdb.py FILE              exit 1 only on FATAL
  validate_userdb.py FILE --strict     exit 1 on FATAL or WARN
  validate_userdb.py IN --fix OUT      write a copy with bad lines removed
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cowrie_userdb as udb  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--fix", metavar="OUT", help="write a cleaned copy here")
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings as failures too")
    args = ap.parse_args()

    with open(args.path, "rb") as fh:
        data = fh.read()

    usable, findings = udb.check_file(data)
    fatal = udb.fatal(findings)
    warn = [f for f in findings if f[1] == udb.WARN]

    print(f"{args.path}: {usable} usable, {len(fatal)} FATAL, {len(warn)} WARN")
    for rows in (fatal, warn):
        for number, severity, text, why in rows[:20]:
            where = f"line {number}" if number else "file"
            print(f"  {severity} {where}: {why}")
            if text:
                print(f"    {text!r}")
        if len(rows) > 20:
            print(f"  ... {len(rows) - 20} more {rows[0][1]}")

    if args.fix:
        lines, why = udb.decode_file(data)
        if lines is None:
            print(f"cannot fix: {why}")
            return 1
        bad = {f[0] for f in findings}
        kept = [line for n, line in enumerate(lines, 1) if n not in bad]
        tmp = args.fix + ".tmp"
        with open(tmp, "w", encoding="ascii") as out:
            out.write("\n".join(kept) + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, args.fix)
        print(f"clean copy written to {args.fix}, {len(kept)} line(s) kept")
        return 0

    if fatal:
        return 1
    if warn and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
