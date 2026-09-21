# Deployment

Everything the Pi runs is described here rather than living only on the Pi.
Before this directory existed, the unit files and the nginx config were typed
in by hand during setup and then drifted, which meant the deployed shape of
the system was not reviewable and could not be rebuilt from the repository.

## Ownership

The code tree belongs to root. The service account owns only what it has to
write:

| Path | Owner | Why |
|------|-------|-----|
| `/opt/threat-radar` and everything under it | `root:root` | Nothing that executes as `radar` can edit code that root later runs |
| `data/` | `radar:radar`, mode 750 | The database, the WAL index and captured samples |
| `spool/` | `radar:radar`, mode 750 | Where the pull unpacks logs before ingestion |
| `.ssh_pull`, `.ssh_pull.pub`, `.ssh_known_hosts` | `radar:radar`, key mode 600 | The pull transport runs as the service account |
| `/run/threat-radar` | `radar:radar`, mode 750 | Lock files, created by the units through `RuntimeDirectory` |

The reason for the split is narrow and worth stating plainly. The processes
that parse attacker-controlled data run as `radar`. If that account can also
write the code root executes on the next deploy, then a bug in a parser is a
path to root rather than a bug in a parser. `deploy/install-ownership.sh`
moves an existing install onto this model and `deploy/update.sh` keeps it
there on every deploy.

Root should not have a `safe.directory` entry for the repository. That entry
exists to let root work in a tree someone else owns, which is the situation
this model removes.

## Secrets

Configuration that is specific to a deployment, or secret, lives outside the
repository in `/etc/threat-radar/`, and each unit reads only the file it
needs:

| File | Read by | Holds |
|------|---------|-------|
| `web.env` | `radar-web` | Display and sizing settings, no credentials |
| `pull.env` | `radar-pull` | The sensor's tailnet address |
| `intel.env` | `radar-intel` | VirusTotal and abuse.ch API keys |
| `excluded_sources.txt` | `radar-intel` | Operator addresses kept out of analysis |
| `credential_tags.local.json` | `radar-intel`, `radar-web` | Credential rules that would identify this sensor |

One file holding every key, read by every unit, meant the dashboard process
held the API keys it never uses.

## Units

`deploy/systemd/` holds the installed units. Each one is confined to what it
actually needs: no capabilities, no new privileges, a read-only filesystem
apart from one or two `ReadWritePaths`, a system call filter, and no network
at all for ingest, enrichment and pruning; the dashboard may use the
loopback interface and nothing else. Only the insights worker
reaches the internet, for reputation lookups and submissions.

Drop-ins under `/etc/systemd/system/radar-*.service.d/` override these files.
The settings that used to live in drop-ins are folded into the units here, so
any drop-in still on disk is drift; `update.sh` lists them when it runs.

## nginx

`deploy/nginx/radar.conf` is the dashboard vhost. The application sets its own
security headers, so nginx sets none. Denials specific to a deployment, such
as the sensor's own tailnet address, go in `/etc/nginx/radar-local-deny.conf`,
which the vhost includes before its allow list.

## nginx service hardening

`deploy/systemd/nginx.service.d/10-hardening.conf` confines the nginx service
itself, as opposed to the vhost above. It is installed by hand rather than by
`update.sh`, because that script only manages units it owns and overwriting a
drop-in for a distribution package is not something a routine deploy should do:

```bash
sudo install -D -m 644 deploy/systemd/nginx.service.d/10-hardening.conf \
  /etc/systemd/system/nginx.service.d/10-hardening.conf
sudo systemctl daemon-reload && sudo systemctl restart nginx
```

## Deploying

```bash
sudo /opt/threat-radar/deploy/update.sh              # code only
sudo /opt/threat-radar/deploy/update.sh --config     # code, units and nginx
```

Without `--config` the script reports configuration differences and changes
nothing, so a routine deploy cannot alter the shape of the deployment by
accident. With it, units are installed and systemd is reloaded, and the nginx
config is installed only if `nginx -t` passes.
