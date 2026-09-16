#!/usr/bin/env python3
"""Validate a Cowrie userdb.txt before it can take the honeypot offline.

The July 31 2026 outage was one line with an empty password field. Cowrie
reloads this file on every authentication attempt, so a single malformed line
stops all authentication and logs nothing at the login stage.

Two severities, and the distinction matters because this runs as an
ExecStartPre gate on cowrie.service:

  FATAL  - Cowrie raises while loading and ALL authentication stops.
           Empty password field (auth.py does passwd[0] == ord("!"), which
           raises IndexError on empty bytes) or fewer than three colon
           separated fields (ValueError on unpack).
  WARN   - the entry is dead but harmless. It loads fine and simply never
           matches. Not a reason to refuse to start the sensor.

  validate_userdb.py FILE              exit 1 only on FATAL
  validate_userdb.py FILE --strict     exit 1 on FATAL or WARN
  validate_userdb.py IN --fix OUT      write a copy with bad lines removed
"""
import argparse
import sys

FATAL, WARN = "FATAL", "WARN"


def check_line(raw: bytes):
    """Return (severity, reason) if the line is a problem, else None."""
    line = raw.rstrip(b"\r\n")
    if not line or line.startswith(b"#"):
        return None
    if line.count(b":") < 2:
        return (FATAL, "fewer than three colon-separated fields, ValueError on load")
    login, _uid, passwd = line.split(b":", 2)
    if not passwd:
        return (FATAL, "empty password field, IndexError aborts the whole userdb")
    if not login:
        return (WARN, "empty login field")
    if passwd.strip() != passwd:
        return (WARN, "password has leading or trailing whitespace, will never match")
    if b"/" in login or b" " in login:
        return (WARN, "login contains a space or slash, usually a corrupted line")
    if login.startswith(b"userdb"):
        return (WARN, "line looks like grep filename output, not a credential")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--fix", metavar="OUT", help="write a cleaned copy here")
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings as failures too")
    args = ap.parse_args()

    good, fatal, warn = [], [], []
    with open(args.path, "rb") as fh:
        for n, raw in enumerate(fh, 1):
            hit = check_line(raw)
            if hit is None:
                good.append(raw)
            elif hit[0] == FATAL:
                fatal.append((n, raw.rstrip()[:70], hit[1]))
            else:
                warn.append((n, raw.rstrip()[:70], hit[1]))

    print(f"{args.path}: {len(good)} usable, {len(fatal)} FATAL, {len(warn)} WARN")
    for label, rows in (("FATAL", fatal), ("WARN", warn)):
        for n, text, why in rows[:20]:
            print(f"  {label} line {n}: {why}\n    {text!r}")
        if len(rows) > 20:
            print(f"  ... {len(rows) - 20} more {label}")

    if args.fix:
        with open(args.fix, "wb") as out:
            out.writelines(good)
        print(f"clean copy written to {args.fix}")
        return 0
    if fatal:
        return 1
    if warn and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
