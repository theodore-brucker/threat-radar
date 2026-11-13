# Product

Threat Radar is a public dashboard over one SSH honeypot, run by Theo Brucker
as a personal project and published under theobrucker.us. This file says who
it is for and what it must do; `DESIGN.md` says how it looks.

## Readers

- **The visitor.** Arrives from the portfolio site or a shared link, is not a
  security specialist, and has a minute. They should leave knowing what
  happens to a server exposed to the internet: almost everything is automated,
  almost all of it fails at the password, and the few that get in install
  something straight away. The overview's Summary mode is written for them.
- **The analyst.** A practitioner who wants to pivot: from an address to its
  sessions, to the command it ran, to the file it dropped and what vendors say
  about it. Every indicator is a link, every table sorts and copies, and every
  record exports as a document an AI analyst can read.

## What it must do

- Show how far intruders get, and make that the first thing a visitor sees.
- Let any indicator be searched and opened as its own page.
- State what the data cannot support (see the Method page).
- Never serve sample bytes, never render attacker text as markup, and make no
  third-party requests from the browser.
- Stay readable on a phone and printable on paper.

## What it is not

- Not a threat feed or a block list, and not a claim about any industry or
  sector.
- Not a live SOC console: figures are rebuilt on a timer, not streamed.
