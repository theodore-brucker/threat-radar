#!/usr/bin/env python3
"""Report the writing habits docs/WRITING.md asks this repository to avoid.

    python tools/writing_check.py            # checked rules only, exit 1 on a hit
    python tools/writing_check.py --soft     # also list the reader-judged signals

The checked rules are the ones a pattern can catch without false alarms in
this codebase. The soft signals ("rather than", version narration, emphasis
words) are often fine, so they are listed for a person to judge and never
fail the run.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

TEXT = {".md", ".js", ".py", ".css", ".html", ".sh", ".sql", ".conf", ".service",
        ".timer", ".cfg", ".toml", ".yml", ".yaml", ".nft", ".in", ".example", ".bats"}

# Files that quote the patterns on purpose, or are not ours to edit.
SKIP = {
    "docs/WRITING.md",
    "tools/writing_check.py",
    "tests/test_writing.py",
    "THIRD_PARTY.md",
    "app/static/js/icons.js",
}
SKIP_DIRS = ("app/static/vendor/", "app/static/fonts/", "sensor/patches/")

WORDS = [
    "delve", "delves", "delving", "tapestry", "testament", "pivotal", "crucial",
    "seamless", "seamlessly", "robust", "robustly", "harness", "harnessing", "foster",
    "fosters", "fostering", "showcase", "showcases", "showcasing", "intricate",
    "intricacies", "vibrant", "realm", "embark", "elevate", "elevates", "unlock",
    "unlocks", "empower", "empowers", "streamline", "streamlines", "cutting-edge",
    "game-changer", "game-changing", "meticulous", "meticulously", "holistic",
    "quietly", "genuinely", "truly", "deeply", "fundamentally", "essentially",
    "literally", "honestly", "additionally", "moreover", "furthermore", "notably",
    "importantly",
]

CHECKED = [
    ("dash as connector", re.compile("\u2014|\\\\u2014|\\s\u2013\\s|\\s\\\\u2013\\s")),
    # "robust z-score" is the statistics term, not the adjective.
    ("stock vocabulary or weight adverb",
     re.compile(r"\b(" + "|".join(re.escape(w) for w in WORDS) + r")\b(?! z-score)", re.I)),
    ("verb 'leverage' or 'underscore'",
     re.compile(r"\b(leverag(e|es|ed|ing)\s+(the|a|an|our|its|this|these|existing))|"
                r"\bunderscor(e|es|ed|ing)\s+(the|a|an|how|that|its|why)\b", re.I)),
    ("filler transition",
     re.compile(r"\b(it'?s|it is) (worth noting|important to note)|\bin conclusion\b|"
                r"\bin summary\b|\bat the end of the day\b", re.I)),
    ("'not just X' / 'it's not X, it's Y'",
     re.compile(r"\bnot just\b|\bnot only\b|\bit'?s not \w+(\s\w+)?, it'?s\b", re.I)),
    ("copula dodge", re.compile(r"\b(serves|serving|stands|standing) as (a|an|the)\b", re.I)),
    ("arrow in prose", re.compile(r"[→⇒⟶]|\\u2192")),
]

SOFT = [
    ("contrast framing", re.compile(r"\brather than\b|\binstead of\b", re.I)),
    # Action pins ("# v4.2.2") are versions, not narration.
    ("version narration", re.compile(r"(?<![/\w.-])v[1-5](\.\d)?\b(?![/=.])")),
    ("emphasis word", re.compile(r"\b(actually|really|simply|plainly|deliberately|"
                                 r"on purpose|by design|in fact|of course)\b", re.I)),
    ("announcement", re.compile(r"\b(two|three|four|five) (rules|things|changes|jobs|"
                                r"reasons|problems|questions)\b", re.I)),
    ("story framing", re.compile(r"\b(tells the story|narrative|the hard way|first-class)\b", re.I)),
]


def files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
                         check=True).stdout.split()
    for rel in out:
        if rel in SKIP or rel.startswith(SKIP_DIRS):
            continue
        p = ROOT / rel
        if p.suffix in TEXT or p.name in ("pull.sh",):
            yield rel, p


def in_code_block_lines(text):
    """Line numbers inside fenced code blocks in Markdown: diagrams are exempt."""
    inside, skip = False, set()
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            inside = not inside
            skip.add(n)
        elif inside:
            skip.add(n)
    return skip


def scan(rules):
    hits = []
    for rel, path in files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        fenced = in_code_block_lines(text) if path.suffix == ".md" else set()
        for n, line in enumerate(text.splitlines(), 1):
            if n in fenced:
                continue
            for name, rx in rules:
                m = rx.search(line)
                if m:
                    hits.append((rel, n, name, m.group(0), line.strip()))
    return hits


def main(argv):
    hard = scan(CHECKED)
    for rel, n, name, what, line in hard:
        print(f"{rel}:{n}: {name}: {what!r}: {line[:100]}")
    if "--soft" in argv:
        soft = scan(SOFT)
        print(f"\n-- {len(soft)} soft signals for a reader to judge --")
        for rel, n, name, what, line in soft:
            print(f"{rel}:{n}: {name}: {what!r}: {line[:100]}")
    print(f"\n{len(hard)} checked-rule hits", file=sys.stderr)
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
