#!/usr/bin/env python3
"""Validate a Cowrie userdb.txt before it can take the honeypot offline.

The July 31 outage was one line with an empty password field. Cowrie reloads
this file on every authentication attempt, so a single malformed line stops
all authentication and logs nothing at the login stage. Run this from
build_userdb.py before the file is written, and as a pre-flight on the sensor.

  validate_userdb.py /opt/cowrie/etc/userdb.txt          check
  validate_userdb.py in.txt --fix out.txt                check and write a clean copy

Exit status is non-zero when a line would break Cowrie.
"""

import argparse
import sys


def check_line(raw: bytes):
    """Return None if the line is safe, or a reason string if it is not."""
    line = raw.rstrip(b"\r\n")
    if not line or line.startswith(b"#"):
        return None
    if line.count(b":") < 2:
        return "fewer than three colon-separated fields"
    login, _uid, passwd = line.split(b":", 2)
    if not login:
        return "empty login field"
    if not passwd:
        # Cowrie does passwd[0] == ord('!') and raises IndexError on empty
        return "empty password field, this is the fault that broke the sensor"
    if passwd.strip() != passwd:
        return "password has leading or trailing whitespace and will never match"
    if b"/" in login or b" " in login:
        return "login contains a space or slash, usually a corrupted line"
    if login.startswith(b"userdb"):
        return "line looks like grep filename output, not a credential"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--fix", metavar="OUT", help="write a cleaned copy here")
    args = ap.parse_args()

    good, bad = [], []
    with open(args.path, "rb") as fh:
        for n, raw in enumerate(fh, 1):
            why = check_line(raw)
            if why:
                bad.append((n, raw.rstrip()[:70], why))
            else:
                good.append(raw)

    print(f"{args.path}: {len(good)} usable line(s), {len(bad)} rejected")
    for n, text, why in bad[:20]:
        print(f"  line {n}: {why}\n    {text!r}")
    if len(bad) > 20:
        print(f"  ... {len(bad) - 20} more")

    if args.fix:
        with open(args.fix, "wb") as out:
            out.writelines(good)
        print(f"clean copy written to {args.fix}")
        return 0
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
