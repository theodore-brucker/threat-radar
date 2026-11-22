"""Evaluate arithmetic expressions with the patched Cowrie's evaluator.

tests/test_sensor_patches.py runs this file inside a patched copy of Cowrie,
with a JSON list of expressions on standard input, and reads the JSON list of
results it prints.
"""
from __future__ import annotations

import json
import sys

from cowrie.shell import arithmetic

# Forty variables that each name the next one twice: 2**40 evaluations
# unless the evaluator counts its work.
variables = {"x": "x", "v40": "1"}
variables.update({f"v{n}": f"v{n + 1}+v{n + 1}" for n in range(40)})

results = []
for expression in json.load(sys.stdin):
    try:
        results.append(str(arithmetic.evaluate(expression, variables.get)))
    except arithmetic.ArithmeticError_ as problem:
        results.append(str(problem)[-200:])
sys.stdout.write("\n" + json.dumps(results))
