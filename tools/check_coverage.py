#!/usr/bin/env python3
"""Enforce per-module coverage floors from pyproject.toml.

coverage.py supports one global threshold, which lets a well-covered module
hide a neglected one. This reads coverage.json and fails if any module in the
floors table drops below its floor, or if a new module appears with no floor,
so every file's coverage is a decision somebody made.

    python -m pytest --cov --cov-report=json:coverage.json
    python tools/check_coverage.py coverage.json
"""

import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main(path="coverage.json"):
    floors = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["threat-radar"]["coverage-floors"]
    data = json.loads(pathlib.Path(path).read_text())
    failures = []

    total = data["totals"]["percent_covered"]
    if total < floors["TOTAL"]:
        failures.append(f"TOTAL {total:.1f}% is below its floor of {floors['TOTAL']}%")

    for name, entry in sorted(data["files"].items()):
        summary = entry["summary"]
        if summary["num_statements"] == 0:
            continue
        pct = summary["percent_covered"]
        if name not in floors:
            failures.append(f"{name} has no floor; add one at or below {int(pct // 5 * 5)}")
        elif pct < floors[name]:
            failures.append(f"{name} {pct:.1f}% is below its floor of {floors[name]}%")

    for name in sorted(set(floors) - set(data["files"]) - {"TOTAL"}):
        failures.append(f"{name} has a floor but was not measured; remove the entry if the file is gone")

    if failures:
        print("coverage floors not met:")
        for f in failures:
            print("  " + f)
        return 1
    print(f"coverage floors met, total {total:.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
