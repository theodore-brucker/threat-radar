# Sensor configuration

This directory mirrors `/opt/cowrie` on the sensor VPS, so the sensor's
changes to upstream Cowrie are tracked and can be rebuilt from the repository.

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

- `bin/` holds `pull-logs.sh` (forced-command wrapper: the collector asks
  for a manifest of log files and sizes, then for only the byte ranges it
  lacks, and fetches captures by sha256), `prune-logs.sh`,
  `validate_userdb.py` and `cowrie_userdb.py`. The last of those is the one
  place that describes what Cowrie does with `userdb.txt`: the start-up gate
  and the generator on the collector both import it, because they used to
  carry separate copies of those rules and each missed cases the other
  caught. The persona tooling, `persona_fs.py` and
  `plant_token.sh`, lives in the private tree with the persona files it acts
  on, and is copied into the same `bin/` before deploy.
- `patches/` holds local modifications to upstream Cowrie source, which must be
  reapplied after any `git pull` in `/opt/cowrie`.
  `lspci-txtcmds.patch` makes the `lspci` built-in read the operator file,
  since built-ins otherwise win over txtcmds in `getCommand()`.
  `factory-kex.patch` drops configured kex algorithms Twisted does not
  implement, instead of advertising them and dying at key exchange.
  `factory-hostkeys.patch` advertises the RSA host key as `rsa-sha2-512` and
  `rsa-sha2-256`, as OpenSSH 8.8 and later do. Cowrie otherwise offers
  `ssh-rsa`, which no current OpenSSH server lists.
  `shell-host-stats.patch` makes `uptime`, `w` and `free` read the host
  figures that `bin/mirror-host.sh` copies into honeyfs (the service cannot
  read `/proc` itself), prints `free -m` and `free -h` in procps units, and
  makes `last` report wtmp beginning on the first of the month, the way a
  monthly logrotate leaves it.
  `shell-arithmetic.patch` makes the shell evaluate `$((...))`. Cowrie
  3.0.14 runs the text inside as a command and prints `command not found`,
  which is the first thing a careful script checks. The evaluator is a new
  file, `shell/arithmetic.py`, that tokenises the expression itself, wraps at
  64 bits as bash does and bounds its own work.
  `shell-parameters.patch` gives the shell `$$`, `$0`, `set --` and `shift`,
  and makes `set -e` and the other option forms print nothing. `$$` is the
  process id the `ps` command already prints for the login shell, and a
  nested `sh` reports a different one.
  `shell-printf.patch` makes `printf` format its arguments. Cowrie printed
  nothing when a format had any. Field widths and total output are capped.
  `shell-text-tools.patch` makes `grep` honour `-i`, `-v`, `-c` and `-q`,
  which it accepted and ignored, and lets `head` and `tail` take `-5`.
  `auth-implanted-keys.patch` remembers the public keys a session writes to
  an `authorized_keys` file in a home directory and accepts a later login
  that proves it holds the private half. See "Keys an intruder installs"
  below.
- `systemd/` holds the unit and its drop-in for `cowrie.service`. The drop-in
  stops Cowrie from starting with a userdb it cannot load, because Cowrie would
  otherwise start and reject every login without logging an error.
- `bin/mirror-host.sh` copies the host's kernel version, CPU and memory
  and the output of `lscpu`, `nproc`, `lspci`, `df`, `mount` and `getconf`
  into honeyfs and txtcmds. Cowrie's shipped filesystem answers those for
  another machine (a Debian kernel in `/proc/version`, Debian lenny output
  from `df`, `mount` and `dmesg`, a vim error from `top`), so a session that
  asks the same question two ways got two answers. `static` runs as root
  before each start through `systemd/cowrie.service.d/20-mirror-host.conf`,
  and `proc` runs every minute from `systemd/cowrie-proc.timer`.
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

## Upgrading Cowrie and installing patches

`/opt/cowrie` is a git checkout of upstream with the patches in `patches/`
applied. `bin/upgrade-cowrie.sh TAG PATCH_DIR` moves it to another tag. Run
with the tag that is already checked out, it puts every patched file back as
upstream has it and applies the whole set again, which is how a new or
changed patch is installed. It reads the list of patched files from the
patches. It refuses if tracked files differ from upstream anywhere outside
that list, or if the target adds a file that exists here untracked, and it
applies the patches to a scratch copy of the target before touching anything.
It writes a tarball of everything except `var/` first, and rolling back is the
same script with the previous tag or the previous patch directory. It does not
restart Cowrie, so that you can restart it yourself and watch the log.

The patches are independent. Each applies to the untouched release, and they
apply in any order. `tests/test_sensor_patches.py` checks that on every push
against the release pinned in `requirements-cowrie.txt`, and drives the
patched shell to compare its answers with the ones bash gives.

## Trying a command against the emulated shell

`tools/sensor_shell.py` runs commands in the patched shell on any machine
with the pinned Cowrie installed, without touching the sensor:

```
python -m pip install --require-hashes -r requirements-cowrie.txt
python tools/sensor_shell.py 'echo $((2+3))' 'grep -ci root /etc/passwd'
python tools/sensor_shell.py --unpatched 'echo $((2+3))'
```

It answers from the files Cowrie ships. Pass `--honeyfs` and `--txtcmds` to
use a persona's files. Use it to check whether a command a session ran gave
the emulator away, and to test a patch before it goes to the sensor.

## Keys an intruder installs

A common first move after a login is to append a public key to
`~/.ssh/authorized_keys` and come back later with the private half. Each
Cowrie session works on its own copy of the filesystem, so the file is gone
when the session ends and the return visit used to fail at the door.

With `auth-implanted-keys.patch`, a file written to
`/root/.ssh/authorized_keys` or `/home/NAME/.ssh/authorized_keys` is read for
public keys, at the end of the session for a shell redirect and at the end of
the transfer for an SFTP upload. The SHA-256 of
each key is appended to `var/lib/cowrie/implanted_keys` beside the account
name. A later public-key login for that account with one of those keys is
told the key is acceptable, must then sign the request as it would for sshd,
and reaches the same emulated shell a password login reaches. Its
`cowrie.login.success` event carries `implanted: true` and the key, and the
daily review lists such sessions first.

The file that is read was written by an attacker. At most 64 KiB of it is
read, at most 16 keys are taken from it, and 2,000 keys are kept in all, the
oldest dropped first. A key is parsed by Twisted's key reader and anything it
rejects is skipped. A failure anywhere in the recording or the check leaves
the login refused, which is what Cowrie does without the patch, so this path
cannot stop password logins. Nothing an attacker sends is run. `[ssh]
auth_publickey_implanted = false` in `cowrie.cfg` turns it off, and deleting
the file forgets every key. Keys written by `scp`, `wget -O` or `cp` are not
recorded.

## Ownership on the sensor

The account Cowrie runs as owns `var/` and nothing else. Everything else in
`/opt/cowrie`, including the patched upstream source, `cowrie.cfg`, the userdb,
the validator that gates start-up and the forced-command wrapper, belongs to
root and is readable by the account through group and mode rather than
ownership.

That account runs the process attackers are invited to break. If it can write `bin/pull-logs.sh` it decides
what the collector receives on the next pull. If it can write its own
`authorized_keys` it can drop the forced command. If it can write
`bin/validate_userdb.py` it can remove the check that keeps a malformed userdb
from breaking authentication without an error, which once took this sensor
offline for seventeen days.

`bin/install-ownership.sh` moves an existing install onto that model, and
`sshd/10-radar.conf.example` shows the matching sshd configuration, with the
pull key in a root-owned `AuthorizedKeysFile` outside the account's home.

## Never committed, in either repository

- Canary credentials, wherever they are planted.
- `etc/userdb.txt`, regenerated from observed data by `bin/build_userdb.py`.
  Install it with that script's `--out`, which writes a temporary file and
  renames it into place. A shell redirect truncates the live file, and Cowrie
  re-reads it on every authentication attempt, so a redirect has a window in
  which the sensor authenticates against half a file.
- `var/lib/cowrie/fs.pickle`, a ~1.2MB binary rebuilt from the spec.
