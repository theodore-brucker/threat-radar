# Threat Radar

A self-hosted SSH honeypot and threat intelligence pipeline. A hardened cloud sensor absorbs real attack traffic, a Raspberry Pi turns it into structured intelligence, and a dashboard tells the story from first connection to confirmed malware.

Over 1.4 million events from 4,600+ distinct source addresses in the current retention window, with captured samples contributed back to VirusTotal.

## How it works

```
Internet ──> Hetzner VPS (Cowrie honeypot, nftables redirect 22 -> 2222)
                 │  logs pulled over Tailscale every 30s
                 ▼
             Raspberry Pi 5
                 ├─ ingest.py      idempotent JSON -> SQLite (WAL)
                 ├─ enrich.py      GeoLite2 city + ASN tagging
                 ├─ intel_worker   fact tables, spike attribution,
                 │                 VirusTotal + URLhaus reputation
                 ├─ prune.py       age and size retention caps
                 └─ FastAPI + nginx dashboard (LAN only)
```

The sensor is disposable and untrusted. It holds no credentials to anything, the pull channel uses a forced-command SSH key that can only stream logs and fetch samples by hash, and all analysis happens on the Pi. Attack traffic never touches the network the dashboard lives on.

## The escalation model

Every source is reduced to the furthest stage it reached:

| Stage | Meaning |
|-------|---------|
| 0 | Connected only |
| 1 | Authenticated |
| 2 | Reached a shell |
| 3 | Transferred a file |
| 4 | Transferred confirmed malware |

That single number colors the map, filters every table, and frames the site's narrative: thousands of sources knock, a fraction get in, and a handful actually drop something worth analyzing.

## The site

Single-page app, vanilla JS, no build step, no CDN. One API surface at `/api/v1` with a uniform response envelope.

- **Overview**: headline numbers, escalation rail, world map, volume chart with sensor outages drawn as labeled gaps rather than averaged into trends
- **Sources**: per-IP escalation, ASN abuse scoring that separates dedicated scanning boxes from noisy residential networks, SSH client fingerprints
- **Credentials**: campaign clustering that collapses 15k raw credential pairs into named campaigns via rule-based tagging
- **Payloads**: capture-to-contribution funnel with VirusTotal and URLhaus standing for every hash, including samples this sensor was first to submit
- **Sessions**: per-session timelines and sample inspection with ELF header parsing, entropy analysis, and packer detection
- **Tunnels**: what attackers wanted the box for, inferred from direct-tcpip forwarding requests
- **Method**: how the pipeline works, for visitors who want the engineering

An optional chat box answers questions about the data through the Anthropic API, grounded in read-only queries against the same database the dashboard reads.

## Design constraints

A few rules shaped most of the code:

- **No sample bytes leave the API.** Text renders as stripped text, binaries return metadata and filtered strings. There is no download path, because the site is meant to be public and a honeypot dashboard should not double as a malware distribution point.
- **Attacker input is data, never markup.** Parameterized SQL on the way in, `textContent` rendering on the way out, no `innerHTML` anywhere.
- **List views never scan raw events.** The intel worker materializes per-day fact tables; endpoints that once timed out against 1.3M rows now read pre-built aggregates. Detail views may touch raw events only through indexed equality lookups.
- **Trends exclude known outages by name.** A 17-day sensor fault taught the hard way that a baseline including broken days reports an attacker collapse that is really a sensor collapse. Outage windows are first-class data.
- **The Pi never fills its disk.** Retention enforces an age cap and a size cap independently, with lifetime source counters surviving the prune.

## Spike detection

Daily volume anomalies use rolling median and median absolute deviation instead of mean and standard deviation, so a multi-day surge does not inflate the threshold meant to catch it. Attribution compares a spike day against its baseline across source IP, ASN, event type, and username, then stores the label so a day is scored once.

## Stack

Python 3 / FastAPI / SQLite (WAL) on the Pi, Cowrie on Ubuntu behind nftables on the sensor, Tailscale for transport, systemd timers for orchestration, GeoLite2 for enrichment, vanilla JS and hand-rolled SVG (including the world map, a 46KB local outline) on the front end.

Deployment is a git pull: the Pi tracks this repo through a read-only deploy key, and `deploy/update.sh` fetches, syncs dependencies, restarts services, and health-checks the API.

See `SETUP.md` for build notes.

## Tests

The suite uses only the standard library `unittest` plus the packages already
in `requirements.txt`. Every test builds a throwaway database from
`schema.sql` and the real migrations, and no test touches the network: the
worker's HTTP helper is replaced with a scripted fake. Run it from the repo
root, locally or on the Pi:

```bash
cd /opt/threat-radar && sudo -u radar venv/bin/python -m unittest discover -s tests -t .
```

Coverage is organised by feature: VirusTotal submission (`test_vt_submit`),
MalwareBazaar submission (`test_bazaar`), VirusTotal snapshots and refresh
cadence (`test_snapshots`), durable capture context (`test_provenance`),
contribution attribution and counts (`test_contributions`), and the API
surface (`test_api`).
