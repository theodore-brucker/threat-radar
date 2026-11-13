"""The mechanical half of docs/WRITING.md.

tools/writing_check.py holds the patterns; this test fails on any hit so a
new em dash or a stock phrase is caught in review instead of shipping. The
reader-judged rules in that file are listed by `writing_check.py --soft` and
are not enforced here.
"""

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "writing_check", ROOT / "tools" / "writing_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class WritingTests(unittest.TestCase):
    def test_no_checked_writing_habits(self):
        checker = load_checker()
        hits = ["%s:%d: %s (%r)" % (rel, n, name, what)
                for rel, n, name, what, _ in checker.scan(checker.CHECKED)]
        self.assertEqual(hits, [], "see docs/WRITING.md")

    def test_the_checker_catches_what_it_claims_to(self):
        checker = load_checker()
        samples = {
            "dash as connector": "the pull — which runs often",
            "stock vocabulary or weight adverb": "a robust and seamless pipeline",
            "filler transition": "It's worth noting that the pull runs often.",
            "'not just X' / 'it's not X, it's Y'": "It's not a dashboard, it's a tool.",
            "copula dodge": "The rail serves as a filter.",
            "arrow in prose": "pull → ingest",
        }
        rules = dict(checker.CHECKED)
        for name, text in samples.items():
            with self.subTest(rule=name):
                self.assertIsNotNone(rules[name].search(text))
        self.assertIsNone(rules["stock vocabulary or weight adverb"].search("robust z-score"))


if __name__ == "__main__":
    unittest.main()
