#!/usr/bin/env python3
"""What Cowrie actually does with userdb.txt, in one place.

Two programs need to agree about this file: the generator that writes it from
observed credentials, and the start-up gate that refuses to launch the sensor
with a broken one. They disagreed, and each missed cases the other caught, so
both now import this module.

The rules below are not a reasonable interpretation of the format. They are
Cowrie 3.0.6 `src/cowrie/core/auth.py`, read line by line, because the failure
mode is specific: `UserDB.load` runs on every authentication attempt, anything
it raises propagates, and the sensor then answers no one while logging nothing
at the login stage. That cost seventeen days in 2026.

What Cowrie does, in order:

  load()
    reads the whole file with encoding="ascii", so one byte above 127
    anywhere in the file raises UnicodeDecodeError and no credential loads
    splits on str.splitlines(), which breaks on \\v \\f \\x1c \\x1d \\x1e as
    well as newlines, so those characters inside a field silently split a
    line in two
    skips lines starting with "#"
    takes field 0 as the login and field 2, stripped, as the password
    catches IndexError, so a line with fewer than three fields is skipped
    rather than fatal

  adduser()
    reads passwd[0], which raises IndexError on an empty password and takes
    the whole load with it
    treats a leading "!" as deny and drops that character

  re_or_bytes()
    turns a field matching /(.+)/(i)? into a compiled regex, so an invalid
    pattern raises re.error and a valid one silently changes the meaning of
    the entry. This applies to the login as well as the password

  match_rule()
    treats a literal "*" as matching anything

Severities exist because this gates service start-up:

  FATAL  Cowrie raises while loading and all authentication stops.
  WARN   the entry loads but does not mean what it looks like, either
         because it never matches or because it matches too much.

`literal_pair_problem` is stricter again and is what the generator uses: it
admits only plain literal credentials, because a file built from strings an
attacker chose should never contain a pattern, a wildcard or a deny rule that
the attacker put there.
"""

import re

FATAL = "FATAL"
WARN = "WARN"

# Characters str.splitlines() treats as line boundaries, minus the ones that
# cannot survive the ascii decode. A field containing any of these splits its
# own line when Cowrie reads the file.
SPLIT_CHARS = "\n\r\v\f\x1c\x1d\x1e"

# The pattern Cowrie uses to decide a field is a regex rather than a literal.
REGEX_FIELD = re.compile(r"/(.+)/(i)?$")

# The line the generator writes to deny an account outright.
DENY_ALL = "!*"


def decode_file(data):
    """Decode a whole userdb the way Cowrie does.

    Returns (lines, None) or (None, reason). A decode failure is fatal for
    every entry in the file, not just the line that carries the bad byte,
    which is why this is checked before anything else.
    """
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        return None, (
            "byte 0x%02x at offset %d is not ascii, and Cowrie reads this file "
            "with encoding=\"ascii\", so no credential in it loads at all"
            % (data[exc.start], exc.start)
        )
    return text.splitlines(), None


def check_line(line):
    """Return (severity, reason) for one decoded line, or None if it is fine.

    `line` is one element of the list Cowrie iterates, so it carries no line
    ending. Comments and blanks return None.
    """
    if line.startswith("#") or not line.strip():
        return None

    fields = line.split(":")
    if len(fields) < 3:
        return (
            WARN,
            "fewer than three colon-separated fields, so Cowrie's IndexError "
            "handler skips this line and the credential does nothing",
        )

    login = fields[0]
    passwd = fields[2].strip()

    if len(fields) > 3:
        return (
            WARN,
            "more than three fields, and Cowrie takes the third one, so the "
            "password is silently truncated at the next colon",
        )

    if not passwd:
        return (
            FATAL,
            "empty password field, which is the 2026-07-31 fault: adduser "
            "reads passwd[0] and the IndexError aborts the entire userdb",
        )

    for field, what in ((login, "login"), (passwd, "password")):
        match = REGEX_FIELD.match(field)
        if not match:
            continue
        try:
            re.compile(match.group(1))
        except re.error as exc:
            return (
                FATAL,
                "%s looks like a /regex/ to Cowrie and does not compile (%s), "
                "so re.error aborts the entire userdb" % (what, exc),
            )
        return (
            WARN,
            "%s is treated as a regular expression, not the literal text it "
            "appears to be" % what,
        )

    if login == "*":
        return (WARN, "login is the wildcard, so this entry matches every account")
    if passwd == "*":
        return (
            WARN,
            "password is the wildcard, so this account accepts anything and a "
            "single probe with a random credential identifies the honeypot",
        )
    if passwd == DENY_ALL:
        return None
    if passwd.startswith("!"):
        return (
            WARN,
            "password starts with '!', which Cowrie reads as a rule denying "
            "the rest of the string rather than as a literal password",
        )
    if not login:
        return (WARN, "empty login field, matches only an empty username")
    if "/" in login or " " in login:
        return (WARN, "login contains a space or slash, usually a corrupted line")
    if login.startswith("userdb"):
        return (WARN, "line looks like grep filename output, not a credential")
    return None


def literal_pair_problem(login, passwd):
    """Return a reason this pair must not be written, or None.

    Stricter than check_line on purpose. Anything here came from a credential
    an attacker chose, so a field that Cowrie would read as a pattern, a
    wildcard or a deny rule is rejected outright rather than warned about: the
    userdb is an allow-list built from hostile input, and the only safe
    content is a literal.
    """
    if not login:
        return "empty login field"
    if login.startswith("#"):
        return "login starts with '#', which makes the whole line a comment"
    if not passwd:
        return "empty password field, the fault that broke the sensor 2026-07-31"
    if passwd.strip() != passwd:
        return "password has leading or trailing whitespace, which Cowrie strips"
    for field, what in ((login, "login"), (passwd, "password")):
        if any(ch in field for ch in SPLIT_CHARS):
            return "%s contains a character that splits the line when read" % what
        if any(ord(ch) > 127 for ch in field):
            return "%s is not ascii, and one such byte breaks the whole file" % what
        if REGEX_FIELD.match(field):
            return "%s would be compiled as a regular expression" % what
        if field == "*":
            return "%s is the wildcard and would match anything" % what
    if ":" in login or ":" in passwd:
        return "colon in a field, would corrupt the three-field format"
    if passwd.startswith("!"):
        return "password starts with '!', which Cowrie reads as a deny rule"
    if "/" in login or " " in login:
        return "login contains a space or slash, usually a corrupted line"
    if login.startswith("userdb"):
        return "line looks like grep filename output, not a credential"
    return None


def format_pair(login, passwd):
    """Render one allow entry in the three-field format."""
    return "%s:x:%s" % (login, passwd)


def format_deny(login):
    """Render one entry denying every password for an account."""
    return "%s:x:%s" % (login, DENY_ALL)


def check_file(data):
    """Check a whole userdb.

    Returns (usable, findings) where findings is a list of
    (line_number, severity, text, reason). A decode failure reports line 0,
    because it is a property of the file rather than of any one line.
    """
    lines, why = decode_file(data)
    if lines is None:
        return 0, [(0, FATAL, "", why)]

    usable, findings = 0, []
    for number, line in enumerate(lines, 1):
        hit = check_line(line)
        if hit is None:
            if line.strip() and not line.startswith("#"):
                usable += 1
            continue
        findings.append((number, hit[0], line[:70], hit[1]))
    return usable, findings


def fatal(findings):
    """The fatal subset of a findings list."""
    return [f for f in findings if f[1] == FATAL]
