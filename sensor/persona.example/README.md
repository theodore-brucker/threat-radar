# Example persona

A minimal, generic persona with the same file shapes as a live one. Nothing here matches a deployed sensor. Copy it to build your own:

```bash
cp persona.example/cowrie.cfg          /opt/cowrie/cowrie.cfg
cp persona.example/fs_spec.json        /opt/cowrie/persona/fs_spec.json
cp -r persona.example/honeyfs/.        /opt/cowrie/honeyfs/
sudo -u cowrie python3 /opt/cowrie/bin/persona_fs.py apply --dry-run
```

Lessons from running a live sensor:

- Hostname, banner, `uname` values and `ssh_version` must agree with each
  other. A banner claiming one OpenSSH build while the shell reports another
  is an easy tell.
- Anything the spec creates takes the time of the apply unless `ctime` is set,
  so a node that claims months of uptime should not have home directories
  dated today.
- Override every identity file Cowrie embeds in its shipped filesystem:
  `/etc/hostname` and `/etc/hosts` (they still say `svr04` and `nas3`),
  `/etc/issue`, `/etc/debian_version` and `/etc/resolv.conf`. Add
  `/etc/lsb-release` if the persona is Ubuntu, because the shipped tree has
  none. `bin/mirror-host.sh` covers `/proc` and the hardware commands.
- Keep the SSH offer to algorithms Twisted implements, listed in the order
  OpenSSH uses. A server claiming OpenSSH 9.6 still lacks `chacha20`, GCM,
  ETM MACs, `sntrup761` and the strict key exchange marker, so the offer reads
  as an administrator-restricted configuration, which is common on hardened
  hosts.
- Supply `/etc/passwd` and `/etc/group`. Without them Cowrie falls back to its
  shipped pair and renders uid 1000 as its old default user.
- Place tokens in shared service paths rather than one user's home. `$HOME`
  resolves per account, so a token under one home is invisible to every other
  login that types `~`. Use a distinct token per path so an alert says which
  file was read.
