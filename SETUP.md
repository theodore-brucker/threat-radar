# Threat Radar Setup Runbook

Two machines. The **VPS** is the disposable internet-facing sensor (Cowrie). The
**Pi** is the trusted analytics box (ingest, enrich, dashboard). They talk over a
Tailscale tailnet; nothing from the internet ever reaches the Pi.

```
  Internet ──▶ VPS :22  (Cowrie honeypot)
                 │  cowrie.json
                 ▼
             tailnet (WireGuard)
                 │  Pi pulls logs (Pi holds the creds, not the VPS)
                 ▼
  Pi ─▶ ingest ─▶ SQLite ─▶ enrich (GeoLite2) ─▶ FastAPI dashboard
```

Work top to bottom. Each fenced block is copy-paste as-is unless it says to edit a value.

---

## PART A — VPS sensor

Provision the box first (Oracle Cloud Always Free ARM, or a ~$4/mo Hetzner CX22).
Ubuntu 24.04. When creating it, in the provider's firewall/security-list **allow
inbound TCP 22 from anywhere** and nothing else. You'll do host firewalling too.

SSH in as your sudo user, then:

### A1. Base + Tailscale

```bash
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get -y install curl nftables python3-venv python3-pip git authbind unattended-upgrades
sudo systemctl enable --now unattended-upgrades

# Tailscale — management plane, keeps admin SSH off the public internet
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --ssh
tailscale ip -4          # note this VPS tailnet IP, e.g. 100.x.y.z
```

### A2. Move your real SSH off port 22 (Cowrie takes 22)

Real admin login will be Tailscale SSH over the tailnet. Move the OpenSSH daemon
to 2200 and bind it to the tailnet only, so port 22 to the world is 100% honeypot.

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

Confirm from a second terminal that `ssh -p 2200 user@${TS_IP}` (or `tailscale ssh`)
works **before closing this session**.

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

Tell Cowrie to listen on 2222 (we redirect 22 → 2222 with nftables, so Cowrie
never needs root):

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

Default-deny inbound except the honeypot and the tailnet. Egress is allow-listed
by the `cowrie` UID: DNS/NTP/package repos only. If the emulation is ever escaped,
the box **cannot** scan, DDoS, or pivot outward — this is what keeps your provider
account clean.

```bash
COWRIE_UID=$(id -u cowrie)
sudo tee /etc/nftables.conf >/dev/null <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet radar {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif "lo" accept
    iifname "tailscale0" accept
    ip protocol icmp accept
    tcp dport 22 accept        # honeypot (redirected to 2222)
    tcp dport 2222 accept
    # tcp dport 23 accept      # uncomment to also run Telnet honeypot
  }
  chain forward { type filter hook forward priority 0; policy drop; }

  chain output {
    type filter hook output priority 0; policy accept;
    # Restrict what the cowrie user may reach outbound
    meta skuid ${COWRIE_UID} ct state established,related accept
    meta skuid ${COWRIE_UID} udp dport { 53, 123 } accept
    meta skuid ${COWRIE_UID} tcp dport 53 accept
    meta skuid ${COWRIE_UID} tcp dport { 80, 443 } accept  # package/git; tighten to repo IPs if desired
    meta skuid ${COWRIE_UID} drop
  }

  chain prerouting {
    type nat hook prerouting priority -100;
    tcp dport 22 redirect to :2222
    # tcp dport 23 redirect to :2223
  }
}
EOF
sudo systemctl enable --now nftables
sudo nft -f /etc/nftables.conf
sudo nft list ruleset | head -20
```

### A5. Confirm it's catching traffic

Within an hour (usually minutes) you'll see hits:

```bash
sudo tail -f /opt/cowrie/var/log/cowrie/cowrie.json
```

Leave it. Move to the Pi.

---

## PART B — Pi analytics

On the Pi (also joined to the same tailnet). Get the app files onto it — clone your
repo, or `scp` the `threat-radar/` directory. Assume it lands at `~/threat-radar`.

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

### B3. Pull Cowrie logs from the VPS (Pi-initiated = Pi holds the keys)

Generate a key **on the Pi**, install the public half on the VPS as a restricted,
read-only puller. The VPS never gets credentials to reach into the Pi.

```bash
# On the Pi:
sudo -u radar ssh-keygen -t ed25519 -f /opt/threat-radar/.ssh_pull -N ""
sudo -u radar cat /opt/threat-radar/.ssh_pull.pub
```

On the **VPS**, add that public key restricted to log reads only:

```bash
# EDIT the key string below to the line you just printed on the Pi
PULLKEY='ssh-ed25519 AAAA... radar@pi'
echo "command=\"cat /opt/cowrie/var/log/cowrie/cowrie.json\",no-port-forwarding,no-pty,no-agent-forwarding,no-X11-forwarding ${PULLKEY}" \
  | sudo tee -a /opt/cowrie/.ssh/authorized_keys
# ensure the cowrie account can be reached over the tailnet on 2200
```

Back on the **Pi**, a puller that appends the remote log into the spool every 30s.
The ingester's line-hash dedupe makes repeated full pulls safe.

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
sudo tee /etc/systemd/system/radar-pull.service >/dev/null <<'EOF'
[Unit]
Description=Pull Cowrie logs from sensor
[Service]
Type=oneshot
User=radar
ExecStart=/opt/threat-radar/pull.sh
EOF
sudo tee /etc/systemd/system/radar-pull.timer >/dev/null <<'EOF'
[Unit]
Description=Pull Cowrie logs every 30s
[Timer]
OnBootSec=30
OnUnitActiveSec=30
[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now radar-pull.timer
```

### B4. GeoLite2 databases (free, local, no per-lookup latency)

Sign up for a free MaxMind account, create a license key, then:

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

```bash
sudo tee /etc/systemd/system/radar-ingest.service >/dev/null <<'EOF'
[Unit]
Description=Threat Radar ingester
After=network-online.target
[Service]
User=radar
Environment=TR_BASE=/opt/threat-radar
ExecStart=/opt/threat-radar/venv/bin/python /opt/threat-radar/ingest.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/radar-enrich.service >/dev/null <<'EOF'
[Unit]
Description=Threat Radar enricher
After=radar-ingest.service
[Service]
User=radar
Environment=TR_BASE=/opt/threat-radar
ExecStart=/opt/threat-radar/venv/bin/python /opt/threat-radar/enrich.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/radar-web.service >/dev/null <<'EOF'
[Unit]
Description=Threat Radar dashboard
After=radar-ingest.service
[Service]
User=radar
Environment=TR_BASE=/opt/threat-radar
ExecStart=/opt/threat-radar/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
WorkingDirectory=/opt/threat-radar
Restart=always
[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now radar-ingest radar-enrich radar-web
sleep 3
curl -s http://127.0.0.1:8080/api/summary; echo
```

You should see JSON counts climbing as logs flow in.

### B6. View the dashboard

- **Just you / interviews:** browse to `http://<pi-tailnet-ip>:8080` from any device
  on your tailnet. Nothing exposed publicly.
- **Public URL (optional, still no router changes):** free Cloudflare Tunnel —
  `cloudflared tunnel --url http://127.0.0.1:8080` for a quick link, or a named
  tunnel on your own domain for `radar.theobrucker.us`.

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

- **Attribution honesty.** A residential-grade honeypot catches commodity botnets
  and mass scanners, not nation-state APTs. The dashboard footer already frames
  origins as telemetry, not confirmed attribution. Keep it that way — it reads as
  competence, not the reverse.
- **Rebuild cheaply.** Part A is short enough to re-run from zero if the free VPS
  gets reclaimed. Nothing on the sensor is precious; the data lives on the Pi.
- **Extending enrichment.** GreyNoise Community, AbuseIPDB, and VirusTotal (on the
  payload hashes Cowrie captures) slot into `enrich.py` alongside the GeoLite2
  lookups — same batch loop, add rate-limit-aware queuing for the free tiers.
```
