# Threat Radar Setup Runbook

There are two machines. The VPS is the internet-facing sensor (Cowrie) and can be
rebuilt at any time. The Pi is the trusted analytics host (ingest, enrichment,
dashboard). They connect over a Tailscale tailnet, and no traffic from the
internet reaches the Pi.

```
  Internet ──▶ VPS :22  (Cowrie honeypot)
                 │  cowrie.json
                 ▼
             tailnet (WireGuard)
                 │  Pi pulls logs (Pi holds the creds, not the VPS)
                 ▼
  Pi ─▶ ingest ─▶ SQLite ─▶ enrich (GeoLite2) ─▶ FastAPI dashboard
```

Work from top to bottom. Each code block can be pasted as it is unless it says to edit a value.

---

## PART A: VPS sensor

Provision the box first (Oracle Cloud Always Free ARM, or a ~$4/mo Hetzner CX22).
Use Ubuntu 24.04. In the provider's firewall or security list, allow inbound TCP 22
from anywhere and nothing else. The host gets its own firewall in step A4.

SSH in as your sudo user, then:

### A1. Base + Tailscale

```bash
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get -y install curl nftables python3-venv python3-pip git authbind unattended-upgrades
sudo systemctl enable --now unattended-upgrades

# Tailscale, the management plane, keeps admin SSH off the public internet
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --ssh
tailscale ip -4          # note this VPS tailnet IP, e.g. 100.x.y.z
```

### A2. Move your real SSH off port 22 (Cowrie takes 22)

Admin logins go over Tailscale SSH. Move the OpenSSH daemon to port 2200 and bind
it to the tailnet address only, so everything reaching port 22 from the internet
lands in the honeypot.

```bash
TS_IP=$(tailscale ip -4)
sudo tee /etc/ssh/sshd_config.d/10-radar.conf >/dev/null <<EOF
Port 2200
ListenAddress ${TS_IP}
PermitRootLogin no
PasswordAuthentication no
EOF
sudo systemctl restart ssh
```

Before closing this session, confirm from a second terminal that
`ssh -p 2200 user@${TS_IP}` (or `tailscale ssh`) works.

### A3. Cowrie as an unprivileged user

```bash
sudo useradd -r -m -d /opt/cowrie -s /bin/bash cowrie
sudo -u cowrie -H bash <<'EOF'
cd /opt/cowrie
git clone https://github.com/cowrie/cowrie.git .
python3 -m venv cowrie-env
./cowrie-env/bin/pip install --upgrade pip wheel
./cowrie-env/bin/pip install -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg
EOF
```

Tell Cowrie to listen on 2222. nftables redirects port 22 to 2222, so Cowrie
never needs root:

```bash
sudo -u cowrie sed -i \
  -e 's/^#listen_endpoints = tcp:2222:interface=0.0.0.0/listen_endpoints = tcp:2222:interface=0.0.0.0/' \
  /opt/cowrie/etc/cowrie.cfg
```

Systemd unit:

```bash
sudo tee /etc/systemd/system/cowrie.service >/dev/null <<'EOF'
[Unit]
Description=Cowrie SSH/Telnet honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cowrie
Group=cowrie
Environment=VIRTUAL_ENV=/opt/cowrie/cowrie-env
Environment=PATH=/opt/cowrie/cowrie-env/bin:/usr/bin:/bin
ExecStart=/opt/cowrie/cowrie-env/bin/python /opt/cowrie/bin/cowrie start -n
WorkingDirectory=/opt/cowrie
Restart=on-failure
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/cowrie/var
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie
sleep 5 && sudo systemctl status cowrie --no-pager | head -5
```

### A4. Firewall + egress lockdown (nftables)

Inbound traffic is denied by default except for the honeypot and the tailnet.
Outbound traffic from the `cowrie` UID is limited to DNS, NTP and web, so a
process that escapes the emulation cannot scan, flood or pivot. The outbound
rules also block internal ranges. Cowrie fetches the URLs attackers give it,
which is how samples are captured, and its own destination check does not
cover the Tailscale range and runs before it follows redirects.

The ruleset is versioned at `sensor/nftables-radar.nft`. Install it, adjusting
the uid in the file first if Cowrie does not run as 999:

```bash
id -u cowrie                      # confirm the uid the rules assume
sudo cp sensor/nftables-radar.nft /etc/nftables.d/radar.nft 2>/dev/null \
  || sudo tee -a /etc/nftables.conf < sensor/nftables-radar.nft >/dev/null
sudo nft -c -f /etc/nftables.conf
sudo systemctl enable --now nftables
sudo nft list table inet radar
```

On a host where `/etc/nftables.conf` starts with `flush ruleset`, reload with
care: that line removes the tables other software manages, including the ones
Tailscale installs, which will cut an SSH session that arrived over the
tailnet. Applying only this table with `nft -f` on the table file, or a reboot,
avoids that.

Verify the confinement from the sensor, as root. The first three should be
blocked and the last should succeed:

```bash
for t in http://169.254.169.254/ http://<pi-tailnet-ip>/ http://100.100.100.100/ https://example.com/; do
  printf '%s  %s\n' "$(sudo -u cowrie curl -s -m 5 -o /dev/null -w '%{http_code}' "$t")" "$t"; done
sudo -u cowrie getent hosts example.com
```

### A5. Confirm it is receiving traffic

Connections usually start within minutes, and always within an hour:

```bash
sudo tail -f /opt/cowrie/var/log/cowrie/cowrie.json
```

Leave it running and move to the Pi.

---

## PART B: Pi analytics

The Pi joins the same tailnet. Copy the app onto it, either by cloning the
repository or with `scp`. These steps assume it is at `~/threat-radar`.

### B1. Install to /opt and create the venv

```bash
sudo mkdir -p /opt/threat-radar
sudo cp -r ~/threat-radar/* /opt/threat-radar/
sudo useradd -r -s /usr/sbin/nologin radar 2>/dev/null || true
sudo mkdir -p /opt/threat-radar/{data,spool}
sudo chown -R radar:radar /opt/threat-radar

sudo -u radar python3 -m venv /opt/threat-radar/venv
sudo -u radar /opt/threat-radar/venv/bin/pip install --upgrade pip
sudo -u radar /opt/threat-radar/venv/bin/pip install -r /opt/threat-radar/requirements.txt
```

### B2. Tailscale on the Pi

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

### B3. Pull Cowrie logs from the VPS

The Pi starts every connection, so the Pi holds the key and the VPS never has
credentials for the Pi. Generate the key on the Pi and install the public half
on the VPS, restricted to reading logs.

```bash
# On the Pi:
sudo -u radar ssh-keygen -t ed25519 -f /opt/threat-radar/.ssh_pull -N ""
sudo -u radar cat /opt/threat-radar/.ssh_pull.pub
```

On the VPS, add that public key with a forced command that only reads the log:

```bash
# EDIT the key string below to the line you just printed on the Pi
PULLKEY='ssh-ed25519 AAAA... radar@pi'
echo "command=\"cat /opt/cowrie/var/log/cowrie/cowrie.json\",no-port-forwarding,no-pty,no-agent-forwarding,no-X11-forwarding ${PULLKEY}" \
  | sudo tee -a /opt/cowrie/.ssh/authorized_keys
# ensure the cowrie account can be reached over the tailnet on 2200
```

Back on the Pi, create a script that copies the remote log into the spool. The
ingester skips any line it has already stored (it hashes each line), so pulling
the whole file every time is safe.

```bash
# EDIT VPS_TS_IP to the VPS tailnet IP from step A1
sudo tee /opt/threat-radar/pull.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
VPS_TS_IP="100.x.y.z"       # <-- EDIT
KEY=/opt/threat-radar/.ssh_pull
OUT=/opt/threat-radar/spool/cowrie.json
ssh -i "$KEY" -p 2200 -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 cowrie@"$VPS_TS_IP" > "${OUT}.tmp" 2>/dev/null \
  && mv "${OUT}.tmp" "$OUT"
EOF
sudo chmod +x /opt/threat-radar/pull.sh
sudo chown radar:radar /opt/threat-radar/pull.sh
```

Timer:

```bash
sudo install -m 644 deploy/systemd/radar-pull.service deploy/systemd/radar-pull.timer \
  /etc/systemd/system/
sudo install -d -m 755 /etc/threat-radar
printf 'SENSOR_TS_IP=<vps-tailnet-ip>\n' | sudo tee /etc/threat-radar/pull.env >/dev/null
sudo systemctl daemon-reload && sudo systemctl enable --now radar-pull.timer
```

### B4. GeoLite2 databases

GeoLite2 is free and runs locally, so lookups need no network call.

Create a free MaxMind account and a licence key, then:

```bash
sudo apt-get -y install geoipupdate
# EDIT with your MaxMind account ID + license key
sudo tee /etc/GeoIP.conf >/dev/null <<'EOF'
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-ASN
EOF
sudo geoipupdate
ls -la /var/lib/GeoIP/     # expect GeoLite2-City.mmdb, GeoLite2-ASN.mmdb
```

`geoipupdate` installs a weekly refresh timer automatically.

### B5. Services: ingest, enrich, dashboard

The unit files live in `deploy/systemd/` and are installed from there, so the
deployed configuration stays reviewable and can be rebuilt from the
repository. Each unit can reach only the paths and network it needs, and
`deploy/README.md` explains the ownership model they assume.

```bash
sudo /opt/threat-radar/deploy/install-ownership.sh
sudo install -m 644 /opt/threat-radar/deploy/systemd/radar-ingest.service \
  /opt/threat-radar/deploy/systemd/radar-enrich.service \
  /opt/threat-radar/deploy/systemd/radar-web.service \
  /opt/threat-radar/deploy/systemd/radar-intel.service \
  /opt/threat-radar/deploy/systemd/radar-intel.timer \
  /opt/threat-radar/deploy/systemd/radar-prune.service \
  /opt/threat-radar/deploy/systemd/radar-prune.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now radar-ingest radar-enrich radar-web
sudo systemctl enable --now radar-intel.timer radar-prune.timer
sleep 3
curl -s http://127.0.0.1:8080/api/v1/meta; echo
```

You should see JSON counts climbing as logs flow in.

### B6. View the dashboard

- Private: browse to `http://<pi-tailnet-ip>:8080` from any device on the
  tailnet. Nothing is exposed publicly.
- Public, with no router changes: a Cloudflare Tunnel, either
  `cloudflared tunnel --url http://127.0.0.1:8080` for a temporary link or a
  named tunnel on your own domain, such as `radar.theobrucker.us`.

---

## Verify end to end

```bash
# Pi: logs arriving
watch -n5 'wc -l /opt/threat-radar/spool/cowrie.json'
# Pi: events + enrichment progressing
sudo -u radar sqlite3 /opt/threat-radar/data/radar.db \
  "SELECT (SELECT COUNT(*) FROM raw_events) events,
          (SELECT COUNT(*) FROM sources) ips,
          (SELECT COUNT(*) FROM sources WHERE enriched_at IS NOT NULL) enriched;"
```

## Notes

- Attribution: a single honeypot on a cloud VPS mostly sees botnets and mass
  scanners. The dashboard describes source locations as where infrastructure is
  hosted, and should never present them as who is behind an attack.
- Rebuilding: Part A is short enough to run again from scratch if the VPS is
  reclaimed. The sensor holds nothing that is not also on the Pi.
- More enrichment: GreyNoise Community or AbuseIPDB lookups would fit in
  `enrich.py` next to the GeoLite2 lookups, using the same batch loop and
  rate limiting for free-tier APIs.
```
