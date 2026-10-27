#!/usr/bin/env bash
# flask-admin.sh - run the dashboard's admin commands on the VPS with the right secrets and user.
#   sudo /opt/monitor-dashboard/deploy/flask-admin.sh create-client "Eastwood Primary"
#   sudo /opt/monitor-dashboard/deploy/flask-admin.sh create-user nat --admin
#   sudo /opt/monitor-dashboard/deploy/flask-admin.sh enable-2fa nat
#   sudo /opt/monitor-dashboard/deploy/flask-admin.sh list-users
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
set -a
# shellcheck disable=SC1091
. /etc/monitor-dashboard.env
set +a
cd /opt/monitor-dashboard
exec runuser -u monitor -- /opt/monitor-dashboard/.venv/bin/flask --app app "$@"
