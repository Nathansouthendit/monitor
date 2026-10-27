#!/usr/bin/env bash
# remote-install.sh - run by Deploy-ToVps.ps1 on the VPS (as root via sudo).
# Installs a new copy of the code into /opt/monitor-dashboard and restarts the service.
# The database (/var/lib/monitor-dashboard) and secrets (/etc/monitor-dashboard.env) are never touched.
set -euo pipefail

SRC="${1:?usage: remote-install.sh <unpacked-folder>}"
APP=/opt/monitor-dashboard
BACKUPS=/var/backups/monitor-dashboard-code

for f in app.py requirements.txt templates/base.html static/app.css; do
    [ -e "$SRC/$f" ] || { echo "Missing $f in upload - aborting, nothing changed." >&2; exit 1; }
done
if [ ! -f /etc/monitor-dashboard.env ]; then
    echo "/etc/monitor-dashboard.env not found - do the first-time setup in README.md first." >&2
    exit 1
fi
id monitor >/dev/null 2>&1 || { echo "No 'monitor' user - do the first-time setup in README.md first." >&2; exit 1; }

# Keep the previous code so you can roll back
mkdir -p "$BACKUPS"
if [ -f "$APP/app.py" ]; then
    stamp=$(date +%F-%H%M%S)
    tar -czf "$BACKUPS/code-$stamp.tgz" -C "$APP" app.py requirements.txt templates static 2>/dev/null || true
    ls -1t "$BACKUPS"/code-*.tgz | tail -n +11 | xargs -r rm -f      # keep the last 10
    echo "Previous code saved to $BACKUPS/code-$stamp.tgz"
fi

mkdir -p "$APP"
rm -rf "$APP/templates" "$APP/static" "$APP/deploy"
cp "$SRC/app.py" "$SRC/requirements.txt" "$APP/"
cp -r "$SRC/templates" "$SRC/static" "$SRC/deploy" "$APP/"
chmod 755 "$APP/deploy/"*.sh

[ -x "$APP/.venv/bin/pip" ] || python3 -m venv "$APP/.venv"
"$APP/.venv/bin/pip" install --quiet --upgrade pip
"$APP/.venv/bin/pip" install --quiet -r "$APP/requirements.txt"

# Code is owned by root and only readable by the app, so the app can never rewrite itself.
# (Its only writable place is /var/lib/monitor-dashboard.)
chown -R root:monitor "$APP"
chmod -R u=rwX,g=rX,o= "$APP"
chown -R root:root "$APP/deploy"
chmod 755 "$APP/deploy"

systemctl restart monitor-dashboard
sleep 3
if systemctl is-active --quiet monitor-dashboard; then
    code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8001/login || true)
    echo "Service running. /login answered HTTP $code."
else
    echo "Service FAILED to start - last log lines:" >&2
    journalctl -u monitor-dashboard -n 30 --no-pager >&2
    echo "Roll back with: sudo tar -xzf <latest file in $BACKUPS> -C $APP && sudo systemctl restart monitor-dashboard" >&2
    exit 1
fi
