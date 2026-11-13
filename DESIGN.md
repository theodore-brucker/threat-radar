# Design

This is the design brief and system for the Threat Radar dashboard. It is
written for whoever changes the front end next, human or AI. Read it before
touching anything under `app/static/`, and update it in the same commit when
a rule here changes. `PRODUCT.md` says who the site is for; this file says
how it looks and why.

`tests/test_frontend.py::DesignSystemTests` enforces the cheapest rules
(token-only colours, one radius, no all-caps labels, every icon exists), so a
change that breaks one fails CI rather than drifting in.

## Brief

Threat Radar is the public face of a single SSH honeypot. It has two readers:
someone non-technical following a link from theobrucker.us who wants to know
what happens to an exposed server, and an analyst who wants to pivot from an
address to its sessions to the file it dropped. The overview's Summary mode
serves the first, everything else serves the second.

The site should feel like an instrument rather than a marketing page: calm,
dense where the data is dense, and honest about what the numbers can and
cannot support. It should not look like a SaaS template, a terminal cosplay
(green on black), or a government form.

The one memorable element is the **escalation funnel**: connections narrowing
to logins, shells, and files moved. Every other choice is quiet so that one
can be loud.

## References

Look at these before proposing a new layout, and say which one a change
borrows from.

- `docs/design/*.png`: the current pages, rendered from `tools/demo_data.py`.
  These are the baseline. A redesign should be compared against them side by
  side.
- Instrument panels and field manuals for the typography: labels in plain
  sentence case, numbers set large and tabular, units stated rather than
  implied.
- GreyNoise Visualizer and VirusTotal's file pages for the entity pivot
  pattern: every indicator is a link to its own page, and that page leads
  with identity, then activity, then relations.

To preview with realistic data:

```bash
python tools/demo_data.py /tmp/radar-demo
TR_DB=/tmp/radar-demo/radar.db TR_SAMPLE_DIR=/tmp/radar-demo/samples \
  uvicorn app.main:app --port 8080
```

The demo data is synthetic (RFC 5737 addresses, RFC 5398 AS numbers,
placeholder organisation names), so screenshots of it are safe to publish.

## Tokens

All of these live in `app/static/css/tokens.css`. Component and shell sheets
refer to tokens only; a literal colour or radius there is a bug.

### Colour

| Role | Light | Dark | Use |
| --- | --- | --- | --- |
| canvas | `#F5F7F6` | `#0B1419` | page background, nav, topbar |
| surface | `#FFFFFF` | `#101E27` | data surfaces: tables, map, charts, facts |
| ink | `#0F1A20` | `#E8EEF1` | text |
| mark | `#36454D` | `#B4C2CA` | non-stage data marks: bars, the volume line |
| accent | `#1E4E9C` | `#6BA5E7` | **interactive only**: links, focus, pressed, primary |
| alert / warn / ok | red / amber / green | | status, never decoration |
| stage 0 to 4 | grey, teal, deep teal, amber, red | | escalation stage, nothing else |

Three rules:

1. **One accent.** Blue means "you can act on this". Bars, lines and emphasis
   in prose are ink, not blue. If something is blue and not clickable, it is
   wrong.
2. **Stage colours are data.** They appear only where a value is a stage.
   Stage never relies on colour alone: chips carry a numeral and a word, and
   stages 0 and 1 are outlined while 2 to 4 are filled (the same hollow and
   solid rule the map uses). Summary mode collapses the ramp to two colours.
3. **Measured contrast.** The ramps are checked against WCAG 2.1 and the
   figures are in the header of `tokens.css`. Recompute them when a colour
   changes.

### Type

- **IBM Plex Sans** (variable, Latin subset) for everything we wrote: headings,
  prose, labels, numbers.
- **IBM Plex Mono** only for indicators and anything an attacker supplied:
  addresses, hashes, credentials, commands, URLs, banners. Mono marks "this is
  data from the wire", so it never appears on labels, headings or our own
  numbers.
- Scale: 12 / 13 / 15 / 18 / 24 / 36 px. 12 is the floor. 36 is reserved for
  the one number a page is about.
- Labels are sentence case at 12 px in `--ink-dim`. No all-caps eyebrows, no
  letter-spaced labels.
- Prose is capped at `--measure` (70ch).

### Space, shape, motion

- Spacing scale: 2, 4, 8, 12, 16, 24, 32, 48 px (`--s0` to `--s7`). Sections
  are 48 apart, a heading sits 4 above its description and 16 above its
  content.
- One corner radius, `--radius` (4 px), on everything with corners. Dots are
  circles.
- Motion: one orchestrated moment, the funnel bars growing in sequence the
  first time the overview draws. Everything else is response motion (the
  export menu dropping, Copy turning into Copied). All of it is disabled under
  `prefers-reduced-motion`.

## Layout

```
+---------+--------------------------------------------------+
| mark    | Page title   [ search .............. / ]  window |
|         +--------------------------------------------------+
| Overview|  Heading                                         |
| Sources |  Lede, at most 70ch                              |
| ...     |                                                  |
|         |  Section heading                                 |
|         |  description                                     |
|         |  +--------------------------------------------+  |
|         |  | data surface (table, map, chart)           |  |
|         |  +--------------------------------------------+  |
| status  |  Takeaway sentence                               |
| credit  |                                                  |
+---------+--------------------------------------------------+
```

- Left aligned throughout. Nothing is centred except the stale-data bar.
- **Sections are not cards.** A section is a heading, a description and its
  content on the canvas, separated from the next by space. Only data surfaces
  get a border and the surface colour, so a box always means "data".
- Figures (`stats()`) are a row of numbers on the canvas, not tiles.
- Below 1000 px the nav becomes a horizontal strip; below 900 px the grids
  collapse to one column and the search box hides.

## Components

| Component | Where | Notes |
| --- | --- | --- |
| `funnel()` | overview, malware | The hero. Pass `{ reveal: true }` only for the first draw. |
| `railFull()`, `railStrip()` | analyst overview, sources | Stage filters. Stage 0 is "unfiltered", never shown pressed. |
| `dataTable()` / `table()` | everywhere | Sticky header, sort, row count, copy, j/k. Column labels in sentence case. |
| `stageTag()` | tables, facts | Numeral, fill state and word. |
| `emptyState()` | empty data | Says what would be here and offers to widen the window when that is the cause. Do not offer to widen an all-time table. |
| `errorState()` | failed loads | Plain sentence, a Try again button, and the raw status as a detail line. |
| `pageState()` | 404, unknown entities | Full-page version of the same shape. |
| `icon(name)` | `icons.js` | Lucide path data. Add a glyph to the table rather than drawing one inline. |
| `place(org, country)` | anywhere | Joins with a comma. No dot leaders. |

## Copy

- Write for the reader, in plain words: "Show the last 30 days", not
  "Widen to 30". A button says what happens, and its confirmation reuses the
  verb (Copy, Copied).
- Empty and error states explain what happened and what to do, in the
  interface's voice. They do not apologise and are never vague.
- Headings have no full stop. Sentences do.
- No em dashes, no "A · B · C" meta strings, no arrows appended to links.
- Keep technical terms where an analyst needs them (HASSH, SHA-256), and use
  `term()` to give the Summary reader the plain reading on hover.

## Page states every view must have

1. Loading: nothing for the first 150 ms, then the skeleton (`skeleton()`).
2. Empty: `emptyState()` per section, never a blank gap.
3. Error: `errorState()`; entity pages distinguish 404 (not on record), 400
   (malformed value) and everything else.
4. Not found: the server returns the shell with status 404 for unknown page
   paths, and the router renders `pages/notfound.js`.
5. First run: the overview shows a first-run page when nothing has been
   ingested yet.

## Tab titles and icons

`document.title` is `<page> | Threat Radar`, and entity pages put the value
first (`192.0.2.12 (Address) | Threat Radar`) so a row of tabs is readable.
The favicon (`static/favicon.svg`, with PNG fallbacks) is the radar mark: a
scope ring, a sweep, and one blip in the accent.
