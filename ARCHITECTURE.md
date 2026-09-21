# Architecture and threat model

## Components

```
  internet
     │  SSH to port 22, redirected to Cowrie on 2222
     ▼
  sensor (VPS)
     Cowrie 3.0.14 with two local patches, running as its own account
     nftables: honeypot account limited to DNS, NTP and web, no internal ranges
     userdb gate: refuses to start Cowrie on a userdb it cannot load
     forced-command wrapper: manifest, byte ranges, samples by sha256
     │
     │  pull every 2 minutes, initiated by the collector over the tailnet
     ▼
  collector (Raspberry Pi)
     pull.sh      appends only the bytes it lacks to the spool
     ingest.py    byte-exact offsets, line-hash deduplication
     enrich.py    GeoLite2 city and ASN
     intel worker per-day rollups, lifetime tables, VirusTotal, URLhaus,
                  MalwareBazaar, capture provenance
     prune.py     age retention for raw events, storage warnings
     FastAPI      read-only API and static SPA on the loopback interface
     nginx        private-network allow list and authentication
```

The collector pulls. The sensor holds no credentials for the collector, and
nothing on the sensor initiates a connection to it.

## Trust boundaries

**Internet to sensor.** Hostile by design. Cowrie emulates a shell, captures
what it is sent, and is expected to be probed for escapes. It runs as an
account that owns only its runtime state under `var/`, with the code, the
configuration, the userdb and the forced-command wrapper owned by root. Its
unit runs with no capabilities, a read-only filesystem apart from that state,
a system call filter, and a memory ceiling.

**Sensor to collector.** The sensor is treated as a host that may already be
compromised. Its output is validated before it touches the collector: log
names must match the rotation pattern, lengths are checked against what was
asked for, nothing is unpacked, and samples are kept only when their content
hashes to their name. The honeypot account cannot reach the tailnet, and the
dashboard refuses the sensor's address as well.

**Inside the collector.** Root owns the code and the service account owns
only the database, the spool and the pull key, so a bug in a process that
parses attacker data cannot become persistent code or a path to root on the
next deploy. Every unit is confined to the paths and network it needs: three
have no network at all, and the dashboard is limited to the loopback
interface nginx reaches it on.

**Collector to internet.** Only the insights worker reaches out, for
reputation lookups and submissions.

**Viewer to dashboard.** The dashboard is reachable from private networks
only, behind basic authentication. The application sets a content security
policy with hashed inline script, and renders every attacker-derived value as
text rather than markup.

## Threats and what addresses them

| Threat | Mitigation |
|--------|------------|
| A credential sprayed into the top of the observed list breaks authentication | the userdb generator admits only literal ASCII pairs, checked against Cowrie's own parser, and the start-up gate refuses a file that would fail to load |
| An attacker in the emulated shell uses Cowrie's downloader to reach internal services or cloud metadata | nftables drops private, link-local and tailnet destinations for the honeypot account, and the unit denies the same ranges again |
| A Cowrie escape rewrites the wrapper to feed the collector crafted data | the wrapper is root-owned, and the collector validates everything it receives regardless |
| Crafted log content attacks the dashboard | values render as text, URL attributes are allow-listed, and the policy forbids inline script |
| Published samples act as distribution | no endpoint returns sample bytes, and text samples are defanged |
| Operator identity or persona detail leaks through the public repository | deployment-specific rules, addresses and persona files live outside it, in a private repository and in `/etc` |
| A compromised package reaches the collector | dependencies install only from a lock with hashes |
| A stage fails quietly and the site keeps showing stale data | each stage leaves a heartbeat the health view checks, and a six-hour window catches connections arriving with no logins |

## Risks that remain

These are known and accepted for now, and listed so that nobody mistakes the
table above for a guarantee.

- The tailnet policy is the default, which allows every node to reach every
  other. The honeypot account cannot use that, but root on a fully
  compromised sensor could reach services on other tailnet nodes, such as SSH
  on the collector. An explicit policy that gives the sensor no outbound
  access would close it.
- The honeypot account may resolve names and fetch over HTTP and HTTPS
  anywhere on the internet, which is how samples are captured, and which also
  leaves room for data to leave through DNS after an escape.
- Dashboard authentication travels over plain HTTP on the local network.
  Access over the tailnet is encrypted by WireGuard.
- Captured samples are kept indefinitely on both hosts.
- The persona changed during the period the data covers, so figures either
  side of that boundary describe different hosts and should not be trended
  against each other.

## Design rules

`SECURITY.md` lists the properties that a change must not break. They are
also what the test suite defends: the retention, userdb, pull protocol,
sample text, health and read-only tests each exist because one of these rules
was broken once, or would have been.
