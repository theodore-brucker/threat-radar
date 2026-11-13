# Threat Radar

A self-hosted SSH honeypot and the pipeline behind it. A locked-down cloud VPS runs the honeypot, a Raspberry Pi pulls its logs and analyses them, and a dashboard shows each attacker's progress from first connection to dropped malware.

Captured samples are contributed back to VirusTotal and MalwareBazaar. The dashboard reads thirty days of raw events plus per-day rollups that are kept indefinitely, so trends outlive the raw window.

## How it works

```
Internet ──> Hetzner VPS (Cowrie honeypot, nftables redirect 22 -> 2222)
                 │  logs pulled over Tailscale every 120s
                 ▼
             Raspberry Pi 5
                 ├─ ingest.py      idempotent JSON -> SQLite (WAL)
                 ├─ enrich.py      GeoLite2 city + ASN tagging
                 ├─ intel_worker   fact tables, spike breakdown,
                 │                 VirusTotal + URLhaus reputation
                 ├─ prune.py       age retention, storage warnings
                 └─ FastAPI + nginx dashboard (LAN only)
```

The sensor is disposable and treated as untrusted. It holds no credentials for the Pi, the pull runs in the other direction over a forced-command SSH key that can only stream logs and fetch samples by hash, and all analysis happens on the Pi. Everything the Pi accepts from the sensor is parsed as hostile input.

## The escalation model

Every source is reduced to the furthest stage it reached:

| Stage | Meaning |
|-------|---------|
| 0 | Connected only |
| 1 | Authenticated |
| 2 | Reached a shell |
| 3 | Transferred a file |
| 4 | Transferred flagged malware, meaning at least one VirusTotal engine or a URLhaus listing |

That number colours the map and filters every table. Most sources only ever connect, and each later stage holds far fewer of them than the one before.

## The site

Single-page app, vanilla JS, no build step, no CDN. One API surface at `/api/v1` with a uniform response envelope.

- **Overview**: headline numbers, escalation rail, world map, volume chart with sensor outages drawn as labeled gaps rather than averaged into trends
- **Sources**: per-IP escalation, ASN abuse scoring that separates dedicated scanning boxes from noisy residential networks, SSH client fingerprints
- **Credentials**: rule-based tagging that collapses 15k raw credential pairs into a few dozen themes
- **Payloads**: capture-to-contribution funnel with VirusTotal and URLhaus standing for every hash, including samples this sensor was first to submit
- **Sessions**: per-session timelines and sample inspection with ELF header parsing, entropy analysis, and packer detection
- **Tunnels**: what attackers wanted the box for, inferred from direct-tcpip forwarding requests
- **Method**: how the pipeline works and what the numbers cannot support

Every address, network, day, credential pair, client fingerprint, fetch URL, session and sample has one canonical page, and each of those pages has an export. The export is a single document written for a language model: what the sensor is and how to read its records, the evidence for that one entity, what was left out, and a request for analysis and recommendations that can be switched off. It is served as Markdown or JSON from `/api/v1/export/{type}/{value}`, so an agent can pull it without the page.

## Design constraints

- No sample bytes leave the API. Text samples are shown as stripped text and binaries as metadata and filtered strings. There is no download path, so a public dashboard cannot be used to distribute the malware it collects.
- Attacker input is treated as data and never as markup: parameterised SQL on the way in, `textContent` on the way out, and no `innerHTML` anywhere.
- Attacker input is never treated as instructions either. An export hands recorded text to a language model, so every recorded value sits inside a fence tagged with a nonce made for that document, and text outside the fence tells the model that nothing inside it is an instruction.
- List views never scan raw events. The intel worker builds per-day fact tables, and list endpoints read those. Detail views touch raw events only through indexed equality lookups. Before this, some endpoints timed out against 1.3M rows.
- Trend comparisons skip known outages. During a 17-day sensor fault the login counts fell to zero, and a baseline that included those days showed a drop in attacks that came from a broken sensor. Outage windows are stored in their own table and excluded by name.
- The Pi never fills its disk. Retention enforces an age limit and a size limit separately, and lifetime per-source counters are kept when raw events are pruned.

## Spike detection

Daily volume anomalies use rolling median and median absolute deviation instead of mean and standard deviation, so a multi-day surge does not inflate the threshold meant to catch it. Attribution compares a spike day against its baseline across source IP, ASN, event type, and username, then stores the label so a day is scored once.

## Stack

Python 3 / FastAPI / SQLite (WAL) on the Pi, Cowrie on Ubuntu behind nftables on the sensor, Tailscale for transport, systemd timers for orchestration, GeoLite2 for enrichment, vanilla JS and hand-rolled SVG (including the world map, a 46KB local outline) on the front end.

Deployment is a git pull: the Pi tracks this repo through a read-only deploy key, and `deploy/update.sh` fetches, syncs dependencies, restarts services, and health-checks the API.

See `SETUP.md` for build notes.

## Documentation

- `ARCHITECTURE.md`: the components, the trust boundaries between them, the
  threats each defence answers, and the risks that remain.
- `DATA.md`: what is collected, how long it is kept, what is shared with
  VirusTotal and MalwareBazaar, and what the dashboard shows.
- `SECURITY.md`: what is in scope for a report, how to report it, and the
  properties the project treats as non-negotiable.
- `SETUP.md` and `deploy/README.md`: building and running both hosts.
- `DESIGN.md` and `PRODUCT.md`: who the dashboard is for and the design
  system it follows.
- `docs/WRITING.md`: the writing rules for copy, docs and comments.

## Tests

The tests cover the design rules in `SECURITY.md` and the failures this
deployment has had in production. Every
test builds a throwaway database from `schema.sql` and the real migrations, and
none touches the network. Run it in a separate environment from the
collector's:

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest --cov --cov-report=json:coverage.json
.venv/bin/python tools/check_coverage.py coverage.json
```

What the tests check:

- `test_api_routes` finds every API route from the application, so a new
  route is covered without editing the test. It runs each one against a
  fixture built through the real pipeline with hostile strings in every
  attacker-controlled field, and checks the response envelope, that hostile
  path and query input never causes a 5xx or a leaked error, that no sample
  bytes or live URLs appear anywhere, and that every response carries the
  security headers.
- `test_sql_construction` fails if a value is interpolated into a SQL string
  without having been traced to its source. Bandit's B608 cannot tell a
  traced value from an untraced one, so this test replaces it.
- `test_properties` uses Hypothesis on everything that reads attacker
  strings: anything the userdb generator accepts loads in Cowrie, displayed
  sample text can never run, and ingest's byte offset always lands on a line
  boundary.
- `test_userdb` and `test_build_userdb` check the userdb against Cowrie's own
  parser where it is installed. `test_pull_protocol` and `tests/shell` run the
  pull against a hostile sensor. `test_retention` checks that lifetime tables
  survive the raw window, `test_ingest` covers offsets, `test_health` covers
  stage health, `test_migrations` applies every migration twice,
  `test_readonly` covers read-only connections, `test_frontend` covers HTML
  sinks, the script policy, 404 handling and the design-system rules, and
  `test_writing` checks the rules in `docs/WRITING.md`.

Each module has its own coverage floor in `pyproject.toml`, so a
well-covered module cannot hide a neglected one. The lower floors record where
those modules are today; they are not goals.

CI runs all of this on every push and pull request, plus ruff, bandit,
vulture, shellcheck, the shell tests, pip-audit against every lock, and
gitleaks over the full history. A separate job installs the Cowrie version the
sensor runs and fails if the userdb cross-check skips. `.pre-commit-config.yaml`
runs the fast checks before each commit if you want them there too.

## Licence

MIT, see LICENSE. Bundled fonts and vendor data keep their own terms, listed in
THIRD_PARTY.md.
