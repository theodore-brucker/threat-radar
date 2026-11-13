# Writing

Rules for every sentence in this repository: interface copy, server messages,
export documents, Markdown, commit messages and code comments. They come from
published catalogues of the habits that make text read as machine-written
(sources at the end), narrowed to the ones that showed up here.

None of these words or shapes is wrong once. They are a problem in bulk,
because they replace a specific claim with the sound of one. The fix is
almost always the same: say the concrete thing, once, in the plainest words
that are accurate.

`tests/test_writing.py` checks the first group mechanically. The rest need a
reader.

## Checked by the test suite

1. **Dashes as connectors.** No em dashes or spaced en dashes in prose. Use a
   full stop, a comma, a colon or parentheses. Hyphenated words and number
   ranges (2026-11-01, 0-4) are fine.
2. **Stock AI vocabulary.** delve, tapestry, testament, pivotal, crucial,
   seamless(ly), robust, leverage (as a verb), harness, foster, showcase,
   underscore (as a verb), intricate, vibrant, realm, embark, elevate,
   unlock, empower, streamline, cutting-edge, game-changer, meticulous(ly),
   holistic, landscape (meaning a field). Name the actual property instead:
   "handles a malformed line without stopping" rather than "robust".
3. **Weight adverbs.** quietly, genuinely, truly, deeply, fundamentally,
   essentially, literally, honestly. They add emphasis without adding a
   fact. Delete them, and if the sentence feels weak, the sentence needs a
   better fact.
4. **Filler transitions.** "Additionally", "Moreover", "Furthermore",
   "Notably", "Importantly", "It's worth noting", "It's important to note",
   "In conclusion", "In summary", "At the end of the day". Start with the
   point.
5. **"Not just X, but Y" and "It's not X, it's Y".** The fake reveal. Say
   what the thing is.
6. **The copula dodge.** "serves as", "stands as", "acts as a testament".
   Write "is".
7. **Unicode decoration in prose.** Arrows (→, ⇒) and decorative bullets in
   sentences. Write the word. Diagrams in code blocks are exempt.

## Checked by a reader

8. **Negative framing as the default shape.** "X rather than Y", "X, not Y",
   "instead of Y" used to set up a contrast nobody proposed. Keep the
   contrast when a reader would plausibly expect Y (the sensor pulls rather
   than pushes, which is a real design choice). Cut it when Y is a straw man.
9. **Change-log narration.** "v3 did this, which broke that, so v4 does
   this." Comments and docs describe what the code does now and why. History
   lives in git and in commit messages.
10. **Announcing instead of saying.** "Two rules shaped this:", "Three things
    to know:", "The reason is narrow and worth stating plainly." Delete the
    announcement and start with the first rule.
11. **Quotable one-liners and stakes inflation.** "A dashboard that hides its
    limits is marketing." "The sentence someone repeats in a meeting."
    Aphorisms that sound wise and carry no information, and small decisions
    described as if they matter enormously.
12. **Rule of three.** Lists of exactly three adjectives, benefits or
    clauses, especially back to back. Use the number of items the facts
    have.
13. **Short punchy fragments.** One-line sentences or fragments for drama
    ("No CDN. No build step. Just files."). Write connected sentences.
14. **Trailing significance clauses.** ", ensuring that...", ", reflecting
    ...", ", making it ideal for...". If the consequence matters, give it its
    own sentence with a subject.
15. **Invented labels and personified systems.** "the funnel narrative",
    "the site's story", a system that "tells", "wants" or "refuses". Describe
    what it computes or displays.
16. **Defending against objections nobody raised.** "This is deliberate",
    "on purpose", "by design" attached to ordinary choices. Keep them only
    where a reader would otherwise file a bug.
17. **Bold lead-ins on every bullet.** Bold the term in a definition list if
    it helps scanning; do not bold the first words of every list item by
    reflex.

## Interface copy in particular

- Buttons are verbs that say what happens ("Show the last 30 days", "Copy").
  The confirmation reuses the verb ("Copied").
- Errors say what happened and what to do. They do not apologise, and they
  do not say "something went wrong" without saying what.
- Use the reader's words: "address" before "src_ip", "network operator"
  before "ASN" in the summary view.
- Sentence case everywhere. Headings have no full stop.

## Sources

- Wikipedia, [Signs of AI writing](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing)
  (WikiProject AI Cleanup): the AI-vocabulary list, superficial "-ing"
  analyses, negative parallelism, rule of three, copula avoidance.
- [tropes.fyi directory](https://tropes.fyi/directory): named patterns
  including magic adverbs, preambles, compulsive counting, quotable
  one-liners, invented concept labels and belaboring.
- Pangram Labs, [9 Signs of AI Writing, Backed by Data](https://www.pangram.com/signs-of-ai-writing):
  measured frequency of em dashes, triads and "not just X but Y".
