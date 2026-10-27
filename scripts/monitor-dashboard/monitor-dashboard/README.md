# Monitor Dashboard

Multi-client dashboard for Monitor-Master data.

- Each **client** (school, charity, ...) has its own **API key**. Its Monitor-Master / Push script uses that key to POST to `/api/ingest`.
- Each client has its own **dashboard login(s)** and can only ever see its own servers.
- **Admin** logins can switch between all clients.

## Security built in

| Area | What it does |
|---|---|
| Passwords | Hashed (werkzeug scrypt/pbkdf2), minimum 12 characters |
| API keys | 256-bit random, shown once, stored only as SHA-256 hashes; `rotate-key` to replace |
| Brute force | 5 failed logins per username or 20 per IP → 15 min lockout; 10 bad API keys per IP → 15 min block |
| Sessions | `__Host-` Secure/HttpOnly/SameSite=Strict cookie, 8 h lifetime, new session on login, dropped if IP/browser changes |
| Forms | CSRF tokens on login/logout |
| Headers | CSP, HSTS, X-Frame-Options DENY, nosniff, no-referrer, no-store |
| Tenancy | Non-admin users are tied to one client in the DB; the client can't be chosen from the URL |
| Ingest | HTTPS enforced, 5 MB max body, max 2,000 servers per run, input validated |
| Data | 90-day retention (`RETENTION_DAYS`), parameterised SQL throughout, Jinja auto-escaping |
| Logging | Successful/failed logins and ingests logged with IP |

---

## 1. Test locally (Windows)

```powershell
cd monitor-dashboard
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:SECRET_KEY    = py -c "import secrets; print(secrets.token_hex(32))"
$env:COOKIE_SECURE = "0"      # LOCAL ONLY - allows plain http
$env:DATABASE      = "$PWD\monitor-test.db"

flask --app app create-client "Test School"     # copy the API key it prints
flask --app app create-user nat --admin
flask --app app create-user testschool --client "Test School"

flask --app app run
```

Open http://127.0.0.1:5000 and log in.

Send a test report from a second PowerShell window:

```powershell
$key = "PASTE-API-KEY"
$body = @{
    generated = (Get-Date).ToString("o")
    servers   = @(
        @{ ComputerName = "SRV-DC01";  CPU = 12; RAMUsedPct = 61; DiskC_FreeGB = 48 },
        @{ ComputerName = "SRV-FILE01"; CPU = 4; RAMUsedPct = 40; DiskC_FreeGB = 7 }
    )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/ingest" -Method Post `
    -Headers @{ "X-API-Key" = $key } -ContentType "application/json" -Body $body
```

Refresh the dashboard. Also try: logging in as `testschool` (sees only Test School), a wrong key (401), and 6 bad passwords (lockout).

Delete `monitor-test.db` when finished. Don't copy the test DB to the VPS.

---

## 2. Deploy to the Fasthosts VPS (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y python3-venv nginx certbot python3-certbot-nginx
sudo useradd --system --home /opt/monitor-dashboard --shell /usr/sbin/nologin monitor
sudo mkdir -p /opt/monitor-dashboard /var/lib/monitor-dashboard
# copy app.py, templates/, requirements.txt into /opt/monitor-dashboard (scp/WinSCP)
cd /opt/monitor-dashboard
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo chown -R monitor:monitor /opt/monitor-dashboard /var/lib/monitor-dashboard
sudo chmod 750 /var/lib/monitor-dashboard
```

### Secrets file

```bash
sudo tee /etc/monitor-dashboard.env >/dev/null <<EOF
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
DATABASE=/var/lib/monitor-dashboard/monitor.db
BEHIND_PROXY=1
EOF
sudo chmod 600 /etc/monitor-dashboard.env
```

### systemd service: `/etc/systemd/system/monitor-dashboard.service`

```ini
[Unit]
Description=Monitor Dashboard
After=network.target

[Service]
User=monitor
Group=monitor
WorkingDirectory=/opt/monitor-dashboard
EnvironmentFile=/etc/monitor-dashboard.env
ExecStart=/opt/monitor-dashboard/.venv/bin/gunicorn -w 3 -b 127.0.0.1:8001 app:app
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/monitor-dashboard

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now monitor-dashboard
```

### nginx: `/etc/nginx/sites-available/monitor-dashboard`

```nginx
server {
    listen 80;
    server_name dashboard.example.com;
    client_max_body_size 5m;
    server_tokens off;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/monitor-dashboard /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d dashboard.example.com --redirect   # HTTPS + auto-renew
```

### Firewall

```bash
sudo ufw allow OpenSSH && sudo ufw allow 'Nginx Full' && sudo ufw enable
```

Port 8001 stays bound to localhost only.

### Create real clients and logins on the VPS

```bash
cd /opt/monitor-dashboard
sudo -u monitor bash -c 'set -a; . /etc/monitor-dashboard.env; .venv/bin/flask --app app create-client "Eastwood Primary"'
sudo -u monitor bash -c 'set -a; . /etc/monitor-dashboard.env; .venv/bin/flask --app app create-user nat --admin'
```

(`/etc/monitor-dashboard.env` is root-only. Run these as root with `sudo bash -c ...` if `-u monitor` can't read it.)

### Logs

```bash
journalctl -u monitor-dashboard -f
```

---


## Data format (POST /api/ingest)

Header `X-API-Key: <client key>`, JSON body:

```json
{
  "generated": "2026-10-22T18:00:00+01:00",
  "items": [
    { "type": "server", "host": "EW-SRV-DC01",
      "collected": "2026-10-22T17:58:12+01:00",
      "metrics": { "CPU_Pct": 12, "RAM_UsedPct": 61, "DiskC_FreeGB": 48 } }
  ]
}
```

- `type`: `server`, `pc`, `switch`, `wifi`, `m365`, `defender`, `intune`, `sophos`, `google` or `other`
- `host`: device name (unique per client + type)
- `collected`: when the data was gathered (ISO 8601, e.g. PowerShell `(Get-Date).ToString("o")`)
- `metrics`: any flat key/value pairs; these become the table columns

The old `{ "generated": ..., "servers": [ ... ] }` format is still accepted (treated as `server`).

### Offline thresholds

| Type | Offline after | Shown as |
|---|---|---|
| server, switch | 45 min | red **Offline** |
| pc | 45 min | grey **Not seen** (PCs are normally off at night) |
| wifi | 26 h | red **Offline** |
| m365 | 90 min | red **Offline** |

Change them in `DEVICE_TYPES` at the top of `app.py`. Use `flask --app app forget-device "Client" HOSTNAME` to remove a decommissioned device.


## Connecting a site (Monitor-Master → dashboard)

Files in `site-scripts/` go in the same folder as Monitor-Master on the site's host server.

| File | What it does |
|---|---|
| `Export-DashboardJson.ps1` | Called by Monitor-Master (one added line). Turns the data Master already collected (agents, M365, Defender, Intune, switches) into one JSON file in `C:\Monitor\DashboardOutbox`. No network calls; errors can't stop the HTML/email. |
| `Push-Dashboard.ps1` | The relay. Sends outbox files to `/api/ingest`, moves them to `sent\`; retries automatically if the dashboard is unreachable. |
| `monitormaster3.ps1` | Exact copy of monitormaster2.ps1 plus the one export line (search for "Web dashboard export"). |

1. `flask --app app create-client "YMCA"` on the dashboard → copy the key.
2. On the site server, as the account the tasks run as:
   `Get-Credential -UserName dashboard -Message "API key as password" | Export-CliXml C:\Monitor\dashboard_key.xml`
3. Edit the CONFIG block at the top of `Export-DashboardJson.ps1` (site name, PC name pattern, report intervals) and `$DashboardUrl` in `Push-Dashboard.ps1`.
4. Run `monitormaster3.ps1` by hand → check the HTML/email are unchanged and a file appears in the outbox.
5. Run `Push-Dashboard.ps1` by hand → check the dashboard.
6. Point the Master scheduled task at `monitormaster3.ps1`; add a task for `Push-Dashboard.ps1` every 15 minutes.

Undo: point the task back at `monitormaster2.ps1`.

### Item status and intervals

Each item may include `"status"` (`ok` / `warning` / `critical` / `down`) and `"interval_minutes"` (how often it reports). Stale data always wins: nothing new for `interval_minutes + 15` → Offline. A collector saying `down` (e.g. a switch not answering ping) → Offline straight away.

## Admin commands

| Command | Purpose |
|---|---|
| `create-client "Name"` | New client + API key (shown once) |
| `rotate-key "Name"` | Replace a client's API key |
| `list-clients` | Clients and their users |
| `create-user NAME --client "Name"` / `--admin` | New login |
| `set-password NAME` | Reset password and clear lockout |
| `delete-user NAME` | Remove a login |
| `forget-device "Client" HOST` | Remove a decommissioned device and its history |

## Backups

`sqlite3 /var/lib/monitor-dashboard/monitor.db ".backup '/root/monitor-$(date +%F).db'"`, run nightly from cron.
