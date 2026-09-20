# Sensor configuration

Mirrors `/opt/cowrie` on the sensor VPS. Everything here previously existed in
exactly one copy, on that host, as untracked changes to an upstream Cowrie
checkout.

## Public and private halves

The tooling in this directory is generic. The live persona (hostname, banner,
honeyfs contents, filesystem spec, command output, token placement) is kept in
a separate private repository with the same `sensor/` layout, because a public
copy of a honeypot's persona is a lookup table for anyone who connects to it
and wants to know whether the host is real.

To deploy, overlay the private tree on this one and copy the result onto the
sensor. `persona.example/` shows the shape of every persona file so the tooling
can be read and tested without the real set. The `.gitignore` at the repo root
blocks the persona paths, so an overlaid checkout cannot commit them back here.

## Layout

- `bin/` holds `pull-logs.sh` (forced-command wrapper), `prune-logs.sh` and
  `validate_userdb.py`. The persona tooling, `persona_fs.py` and
  `plant_token.sh`, lives in the private tree with the persona files it acts
  on, and is overlaid into the same `bin/` before deploy.
- `patches/` holds local modifications to upstream Cowrie source, which must be
  reapplied after any `git pull` in `/opt/cowrie`.
  `lspci-txtcmds.patch` makes the `lspci` built-in read the operator file,
  since built-ins otherwise win over txtcmds in `getCommand()`.
  `factory-kex.patch` drops configured kex algorithms Twisted does not
  implement, instead of advertising them and dying at key exchange.
- `systemd/` holds the unit and its drop-in for `cowrie.service`: a hard gate
  on userdb validity, which refuses to start rather than run with
  authentication silently dead.
- `nftables-radar.nft` redirects 22 to 2222 and confines the Cowrie uid to DNS,
  NTP, 80 and 443 outbound.
- `persona.example/` holds a sample `cowrie.cfg` overlay, `fs_spec.json` and
  honeyfs files.

## Persona files and where they go

- `cowrie.cfg` is the overlay read after `etc/cowrie.cfg`. Never append to
  `etc/cowrie.cfg`; it is a full copy of the dist file and a second section
  header raises `DuplicateSectionError`.
- `honeyfs/` supplies file contents only. A path must also exist in
  `var/lib/cowrie/fs.pickle` to be reachable at all.
- `persona/fs_spec.json` is the declarative filesystem layout applied to
  `fs.pickle` by the private `bin/persona_fs.py`, which replaces hand-editing
  the pickle.
- `share/cowrie/txtcmds/` holds operator-supplied command output.
  `txtcmds_path` must be absolute; the shipped default resolves relative to
  WorkingDirectory and misses this tree.

## Never committed, in either repository

- Canary credentials, wherever they are planted.
- `etc/userdb.txt`, regenerated from observed data by `bin/build_userdb.py`.
- `var/lib/cowrie/fs.pickle`, a ~1.2MB binary rebuilt from the spec.
