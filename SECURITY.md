# Security

Threat Radar is a honeypot, so part of it is meant to be attacked. This page
separates what is in scope for a report from what is working as designed.

## In scope

Anything in this repository that runs on the collector or supports the
sensor: the ingester, the enrichment and insights workers, the dashboard and
its API, the pull transport on both ends, the deploy and ownership scripts,
the unit files, and the userdb tooling. Examples of what is worth reporting:

- a way to make the dashboard render attacker-controlled content as markup
  or script, or to make any endpoint return sample bytes
- a way for data arriving from the sensor to write outside the spool, run
  code on the collector, or corrupt what the ingester records
- a credential that, once it reaches the userdb, stops Cowrie authenticating
- a way to read a secret, an operator address, or persona detail from the
  public repository or the site
- a path from the service account to root on the collector

## Out of scope

The sensor's emulation itself. Getting a shell, running commands, reading the
fake filesystem, and downloading files on the honeypot are what it is for, and
weaknesses in Cowrie's emulation belong upstream at
https://github.com/cowrie/cowrie. Please do not target the collector or the
dashboard, which are not exposed to the internet, and do not send traffic to
the sensor that could affect anyone else.

## Reporting

Use GitHub's private vulnerability reporting on this repository (the
Security tab, then "Report a vulnerability"). Please include what you found,
how to reproduce it, and what you think the impact is. This is a personal
project maintained on a best-effort basis: there is no bounty, but reports are
read, credited if you want credit, and fixed with a note in the commit that
closes them.

## Properties this project maintains

These are design rules, and a change that breaks one is treated as a
vulnerability regardless of how it got there.

- No endpoint returns sample bytes. Text samples are shown decoded, with
  control characters removed and URLs and IPv4 addresses defanged. Binaries
  are described by metadata and filtered strings.
- The dashboard opens the database read-only, through both a read-only URI
  and a query-only connection.
- Everything the collector receives from the sensor is parsed as hostile
  input. Names, sizes and lengths are validated, and nothing is unpacked.
- The service account owns only what it writes. Root owns the code.
- The honeypot process cannot reach private, link-local or tailnet addresses.
- Operator addresses and persona detail stay out of this repository.
- Dependencies are installed from a lock with hashes.

`ARCHITECTURE.md` describes the trust boundaries these rules protect, and the
risks that remain.
