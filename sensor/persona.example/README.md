# Example persona

A minimal, deliberately generic persona with the same file shapes as a live
one. Nothing here matches a deployed sensor. Copy it to build your own:

```bash
cp persona.example/cowrie.cfg          /opt/cowrie/cowrie.cfg
cp persona.example/fs_spec.json        /opt/cowrie/persona/fs_spec.json
cp -r persona.example/honeyfs/.        /opt/cowrie/honeyfs/
sudo -u cowrie python3 /opt/cowrie/bin/persona_fs.py apply --dry-run
```

Things worth getting right in a real persona, each learned from a live sensor:

- Hostname, banner, `uname` values and `ssh_version` must agree with each
  other. A banner claiming one OpenSSH build while the shell reports another
  is an easy tell.
- Anything the spec creates takes the time of the apply unless `ctime` is set,
  so a node that claims months of uptime should not have home directories
  dated today.
- Supply `/etc/passwd` and `/etc/group`. Without them Cowrie falls back to its
  shipped pair and renders uid 1000 as its old default user.
- Place tokens in shared service paths rather than one user's home. `$HOME`
  resolves per account, so a token under one home is invisible to every other
  login that types `~`. Use a distinct token per path so an alert says which
  file was read.
