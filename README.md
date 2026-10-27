# Monitor Dashboard

Multi-client dashboard for Monitor-Master data.

- Each **client** (school, charity, ...) has its own **API key**. Its Monitor-Master / Push script uses that key to POST to `/api/ingest`.
- Each client has its own **dashboard login(s)** and can only ever see its own servers.
- **Admin** logins can switch between all clients.

## Security built in

| Area | What it does |
|---|---|
| Passwords | Hashed (werkzeug scrypt/pbkdf2), minimum 12 characters |
| Two-factor | Authenticator-app codes (TOTP) per user; **required for admin logins** (`REQUIRE_ADMIN_2FA=0` turns that off); each code works once |
| API keys | 256-bit random, shown once, stored only as SHA-256 hashes; `rotate-key` to replace |
| Brute force | 5 failed logins per username or 20 per IP → 15 min lockout; 10 bad API keys per IP → 15 min block |
| Sessions | `__Host-` Secure/HttpOnly/SameSite=Strict cookie, 8 h lifetime, new session on login, dropped if IP/browser changes |
| Forms | CSRF tokens on login/2FA/logout |
| Headers | Strict CSP (no scripts at all; CSS only from our own `static/app.css`), HSTS, X-Frame-Options DENY, nosniff, no-referrer, no-store |
| Tenancy | Non-admin users are tied to one client in the DB; the client can't be chosen from the URL |
| Ingest | HTTPS enforced, 10 MB max body, max 2,000 servers per run, input validated |
| Data | 90-day retention (`RETENTION_DAYS`), parameterised SQL throughout, Jinja auto-escaping |
| Logging | Successful/failed logins and ingests logged with IP |
| nginx (`deploy/`) | Rate limits on sign-in and ingest; ingest limited to the sites' public IPs; real visitor IPs behind Cloudflare; ports 80/443 open to Cloudflare only; noindex |
| Dependencies | Exact versions pinned in `requirements.txt`; `Deploy-ToVps.ps1` runs `pip-audit` before uploading |

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
flask --app app enable-2fa nat                   # scan the QR code with your authenticator app
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

## 2. First-time VPS setup (Fasthosts, Ubuntu 22.04+ / Debian 12+)

The VPS needs Python 3.10 or newer (`python3 --version`).

### 2a. Lock down the server first

1. On your PC: `ssh-keygen -t ed25519` (if you don't already have a key), then put the contents of `~/.ssh/id_ed25519.pub` into `~/.ssh/authorized_keys` on the VPS.
2. Check `ssh youruser@server` logs in **without asking for a password**.
3. Install `deploy/sshd-hardening.conf` (instructions are inside it). This turns off password and root logins. Keep your existing SSH window open while you test a new login.

```bash
sudo apt update && sudo apt install -y python3-venv nginx certbot python3-certbot-nginx fail2ban unattended-upgrades sqlite3
sudo dpkg-reconfigure -plow unattended-upgrades      # automatic security updates
sudo ufw allow OpenSSH && sudo ufw allow 'Nginx Full' && sudo ufw enable
```

fail2ban protects SSH out of the box. Also turn on the firewall in the Fasthosts control panel (allow 22, 80 and 443 only).

### 2b. App user, folders and secrets

```bash
sudo useradd --system --home /opt/monitor-dashboard --shell /usr/sbin/nologin monitor
sudo mkdir -p /opt/monitor-dashboard /var/lib/monitor-dashboard
sudo chown monitor:monitor /var/lib/monitor-dashboard && sudo chmod 750 /var/lib/monitor-dashboard

KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
printf 'SECRET_KEY=%s\nDATABASE=/var/lib/monitor-dashboard/monitor.db\nBEHIND_PROXY=1\n' "$KEY" | sudo tee /etc/monitor-dashboard.env >/dev/null
sudo chmod 600 /etc/monitor-dashboard.env
```

Never copy your local `.env` up. The VPS has its own `SECRET_KEY`.

### 2c. Service file

Copy `deploy/monitor-dashboard.service` to `/etc/systemd/system/` on the VPS (WinSCP, or paste it into `sudo nano`), then:

```bash
sudo systemctl daemon-reload && sudo systemctl enable monitor-dashboard
```

### 2d. Deploy the code (from your PC)

```powershell
cd D:\Monitor
.\Deploy-ToVps.ps1 -Server <vps-ip-or-hostname> -User <you>
```

The script uploads **only** `app.py`, `requirements.txt`, `templates\`, `static\` and `deploy\`. It refuses to send `.env`, `.db`, `.xml`, `.json` or `.zip` files, and runs `pip-audit` first if you have it (`pip install pip-audit`). On the VPS it installs the packages, restarts the service and checks it answers.

### 2e. nginx and HTTPS (on the VPS)

```bash
sudo cp /opt/monitor-dashboard/deploy/nginx-monitor-dashboard.conf /etc/nginx/sites-available/monitor-dashboard
sudo cp /opt/monitor-dashboard/deploy/monitor-ingest-allow.conf /etc/nginx/
sudo nano /etc/nginx/sites-available/monitor-dashboard        # set your real hostname
sudo ln -s /etc/nginx/sites-available/monitor-dashboard /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d dashboard.example.com --redirect       # HTTPS + auto-renew
```

Port 8001 stays bound to localhost only.

### 2f. Restrict ingest to your sites

Edit `/etc/nginx/monitor-ingest-allow.conf` with each site's public IP (the file says how to find it), end with `deny all;`, then `sudo nginx -t && sudo systemctl reload nginx`. Until you do this, anyone holding a valid API key can post from anywhere.

### 2g. Cloudflare (recommended)

1. Add the domain to Cloudflare (free plan), with the dashboard's DNS record **proxied** (orange cloud).
2. Set SSL/TLS mode to **Full (strict)**.
3. On the VPS: `sudo /opt/monitor-dashboard/deploy/cloudflare-lockdown.sh`. nginx then sees real visitor IPs, and ports 80/443 accept connections from Cloudflare only. Add the monthly cron line from the top of the script.

Optional extra layer: **Cloudflare Access** (Zero Trust, free up to 50 users) in front of the dashboard, with a bypass rule for `/api/ingest` only. Nobody even reaches the sign-in page without first passing Cloudflare's email-code check.

### 2h. Create real clients and logins

```bash
A=/opt/monitor-dashboard/deploy/flask-admin.sh
sudo $A create-client "Eastwood Primary"     # copy the API key it prints
sudo $A create-user nat --admin
sudo $A enable-2fa nat                       # scan the QR code shown in the terminal
sudo $A list-users
```

Admin logins **can't sign in until 2FA is enabled**. Client logins can use 2FA too (`enable-2fa NAME`), but it's optional for them. Lost phone: `disable-2fa NAME`, then `enable-2fa NAME` again.

### Later deploys

Run `.\Deploy-ToVps.ps1 -Server ... -User ...` again. The database and secrets on the VPS are never touched. The previous code is kept in `/var/backups/monitor-dashboard-code/` (last 10) in case you need to roll back.

### Logs

```bash
journalctl -u monitor-dashboard -f
```

### Rebuilding the CSS

The page styles come from `static/app.css`, built from the classes used in `templates/`. After adding or changing classes in a template, rebuild it on your PC (needs Node.js):

```powershell
cd D:\Monitor\tailwind
npx tailwindcss@3.4.17 -c tailwind.config.js -i input.css -o ..\static\app.css --minify
```

No Node.js? Download `tailwindcss-windows-x64.exe` (v3.4.17) from Tailwind's GitHub releases and run it with the same arguments.

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
| `list-users` | All logins, their client and 2FA status |
| `enable-2fa NAME` / `disable-2fa NAME` | Turn authenticator-app codes on (shows a QR code) / off |
| `set-password NAME` | Reset password and clear lockout |
| `delete-user NAME` | Remove a login |
| `forget-device "Client" HOST` | Remove a decommissioned device and its history |

## Backups

`sqlite3 /var/lib/monitor-dashboard/monitor.db ".backup '/root/monitor-$(date +%F).db'"`, run nightly from cron.

A backup on the same VPS doesn't help if the VPS is lost or compromised. Copy it off the server too, encrypted (e.g. `restic` to Backblaze B2 or similar). The database holds client data, so treat the backups the same way.
