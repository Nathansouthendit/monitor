"""
Monitor Dashboard - multi-client live monitoring.

- Each client (school, charity, etc.) has its own API key. Its relay / Monitor-Master
  script POSTs device data to /api/ingest with that key.
- Every device (server, PC, switch, Wi-Fi controller, M365 tenant...) is tracked with a
  type, its latest metrics, a "last seen" time and history.
- A device that hasn't reported within its type's threshold is shown as offline.
- Each client has its own dashboard login(s) and only sees its own devices.
- Admin users can see and switch between all clients.

Setup (see README.md):
    flask --app app create-client "Eastwood Primary"
    flask --app app create-user nat --admin
    flask --app app create-user eastwood-it --client "Eastwood Primary"
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

try:                                   # load .env for local testing (python app.py or flask run)
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

import click
import pyotp
from flask import (Flask, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key or len(secret_key) < 32:
    raise RuntimeError("Set SECRET_KEY to a long random value "
                       "(e.g. python -c \"import secrets; print(secrets.token_hex(32))\")")

# Only trust X-Forwarded-* headers when running behind a reverse proxy you control
# (nginx/Apache in front of gunicorn). Otherwise clients could spoof their IP.
if os.environ.get("BEHIND_PROXY") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"   # set 0 ONLY for local http testing

app.config.update(
    SECRET_KEY=secret_key,
    DATABASE=os.environ.get("DATABASE", os.path.join(app.root_path, "monitor.db")),
    RETENTION_DAYS=int(os.environ.get("RETENTION_DAYS", "90")),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,         # 10 MB max request body
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=SECURE,
    SESSION_COOKIE_NAME="__Host-session" if SECURE else "session",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),   # forced re-login after 8 hours
    REMEMBER_COOKIE_DURATION=timedelta(seconds=0),
    WTF_CSRF_TIME_LIMIT=None,                        # token lasts as long as the session
)

try:
    DISPLAY_TZ = ZoneInfo(os.environ.get("DISPLAY_TZ", "Europe/London"))
except Exception:                 # Windows without the 'tzdata' package
    print("WARNING: timezone data missing - run 'pip install tzdata'. Showing times in UTC.")
    DISPLAY_TZ = timezone.utc
REFRESH_SECONDS = 60                                 # dashboard auto-refresh

csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"   # session dropped if IP/browser changes

# Brute-force protection
MAX_FAILS_PER_USER = 5      # failed logins per username ...
MAX_FAILS_PER_IP = 20       # ... or per IP address ...
LOCKOUT_MINUTES = 15        # ... within this window → locked out for the window
MAX_BAD_KEYS_PER_IP = 10    # failed API-key attempts per IP in the window

# Two-factor login (authenticator app codes). Set up per user with: flask --app app enable-2fa USER
# Admin logins can see every client, so by default they can't sign in until 2FA is set up.
REQUIRE_ADMIN_2FA = os.environ.get("REQUIRE_ADMIN_2FA", "1") == "1"
TOTP_PENDING_SECONDS = 300  # time allowed between password and code
TOTP_ISSUER = os.environ.get("TOTP_ISSUER", "Monitor Dashboard")

# --------------------------------------------------------------------------
# Device types
#   offline_minutes: no report for this long → offline
#   offline_is_alert: False for PCs, which are normally switched off at night
# --------------------------------------------------------------------------
DEVICE_TYPES = {
    "server": {"label": "Servers",      "offline_minutes": 45,      "offline_is_alert": True},
    "pc":     {"label": "PCs",          "offline_minutes": 45,      "offline_is_alert": False},
    "switch": {"label": "Switches",     "offline_minutes": 45,      "offline_is_alert": True},
    "wifi":   {"label": "Wi-Fi",        "offline_minutes": 26 * 60, "offline_is_alert": True},
    "m365":   {"label": "Microsoft 365", "offline_minutes": 90,     "offline_is_alert": True},
    "defender": {"label": "Defender",   "offline_minutes": 90,      "offline_is_alert": True},
    "intune": {"label": "Intune",       "offline_minutes": 90,      "offline_is_alert": True},
    "sophos": {"label": "Sophos",       "offline_minutes": 90,      "offline_is_alert": True},
    "google": {"label": "Google Workspace", "offline_minutes": 90,  "offline_is_alert": True},
    "other":  {"label": "Other",        "offline_minutes": 60,      "offline_is_alert": True},
}

# Field names the old Monitor-Master format might use for the device name, checked in order.
HOST_KEYS = ("ComputerName", "Hostname", "HostName", "Server", "ServerName", "Name")
# Optional per-item health reported by the collector ("down" = collector says it's unreachable)
REPORTED_STATUSES = ("ok", "warning", "critical", "down")
OFFLINE_GRACE_MINUTES = 15       # added to an item's interval_minutes before it counts as offline
MAX_ITEMS_PER_POST = 2000
MAX_METRIC_KEYS = 200
# Optional detail lists per item (e.g. the non-compliant devices behind an Intune summary)
MAX_DETAIL_SECTIONS = 40
MAX_DETAIL_ROWS = 2000          # per section
MAX_DETAIL_COLUMNS = 40
MAX_CELL_CHARS = 2000


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'none'; "                         # the dashboard uses no JavaScript at all
        "style-src 'self'; "                          # only our own built static/app.css
        "img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if SECURE:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"     # don't cache server data in browsers
    return resp


SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id           INTEGER PRIMARY KEY,
    name         TEXT UNIQUE NOT NULL,
    api_key_hash TEXT UNIQUE NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    client_id     INTEGER REFERENCES clients(id),
    is_admin      INTEGER NOT NULL DEFAULT 0
);
-- One row per POST received (a relay batch)
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY,
    client_id    INTEGER NOT NULL REFERENCES clients(id),
    generated_at TEXT,
    received_at  TEXT NOT NULL,
    server_count INTEGER NOT NULL           -- number of items in the batch
);
-- Current state of every device
CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY,
    client_id      INTEGER NOT NULL REFERENCES clients(id),
    type           TEXT NOT NULL,
    host           TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,           -- newest 'collected' time (UTC)
    latest_metrics TEXT NOT NULL,
    UNIQUE (client_id, type, host)
);
-- History of readings
CREATE TABLE IF NOT EXISTS readings (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    client_id   INTEGER NOT NULL REFERENCES clients(id),
    collected   TEXT NOT NULL,
    received    TEXT NOT NULL,
    metrics     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_failures (
    id       INTEGER PRIMARY KEY,
    kind     TEXT NOT NULL,         -- 'login-user', 'login-ip', 'apikey-ip'
    subject  TEXT NOT NULL,
    at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_fail        ON auth_failures(kind, subject, at);
CREATE INDEX IF NOT EXISTS ix_runs_client ON runs(client_id, received_at);
CREATE INDEX IF NOT EXISTS ix_dev_client  ON devices(client_id, type);
CREATE INDEX IF NOT EXISTS ix_read_dev    ON readings(device_id, collected);
CREATE INDEX IF NOT EXISTS ix_read_client ON readings(client_id, received);
"""


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"], timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()


MIGRATIONS = {   # columns added after the first release: table -> {column: definition}
    "devices": {"reported_status": "TEXT", "interval_minutes": "INTEGER", "latest_details": "TEXT"},
    "users": {"totp_secret": "TEXT", "totp_last": "INTEGER"},   # 2FA secret, last code step used
}


def init_db():
    con = sqlite3.connect(app.config["DATABASE"])
    con.execute("PRAGMA journal_mode = WAL")      # readers don't block the ingest writer
    con.executescript(SCHEMA)
    for table, cols in MIGRATIONS.items():
        have = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
        for col, ddl in cols.items():
            if col not in have:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    con.commit()
    con.close()


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def now_iso():
    return iso(utcnow())


def parse_time(value):
    """Parse an ISO timestamp from PowerShell/anything; naive times are treated as UTC."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).strip()[:40].replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def hash_key(key: str) -> str:
    # API keys are long random tokens, so a plain SHA-256 is sufficient.
    return hashlib.sha256(key.encode()).hexdigest()


init_db()


# --------------------------------------------------------------------------
# Brute-force tracking (stored in SQLite so it works across gunicorn workers)
# --------------------------------------------------------------------------
def _window_start():
    return iso(utcnow() - timedelta(minutes=LOCKOUT_MINUTES))


def fail_count(kind, subject):
    return db().execute(
        "SELECT COUNT(*) FROM auth_failures WHERE kind = ? AND subject = ? AND at >= ?",
        (kind, subject, _window_start())).fetchone()[0]


def record_fail(*pairs):
    con = db()
    with con:
        con.executemany("INSERT INTO auth_failures (kind, subject, at) VALUES (?, ?, ?)",
                        [(k, s, now_iso()) for k, s in pairs])
        con.execute("DELETE FROM auth_failures WHERE at < ?", (iso(utcnow() - timedelta(days=1)),))


def clear_fails(kind, subject):
    with db() as con:
        con.execute("DELETE FROM auth_failures WHERE kind = ? AND subject = ?", (kind, subject))


def client_ip():
    return request.remote_addr or "unknown"


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
class User(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.username = row["username"]
        self.client_id = row["client_id"]
        self.is_admin = bool(row["is_admin"])


@login_manager.user_loader
def load_user(user_id):
    row = db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return User(row) if row else None


_DUMMY_HASH = generate_password_hash("timing-equaliser")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()[:64]
        password = request.form.get("password", "")[:256]
        ip = client_ip()

        if (fail_count("login-user", username) >= MAX_FAILS_PER_USER
                or fail_count("login-ip", ip) >= MAX_FAILS_PER_IP):
            app.logger.warning("Locked-out login attempt user=%s ip=%s", username, ip)
            flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.")
            return render_template("login.html"), 429

        row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        # Always run a hash check so response time doesn't reveal valid usernames.
        ok = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password)
        if row and ok:
            if row["totp_secret"]:
                # Password right - now ask for the authenticator code. Not logged in yet.
                session.clear()
                session["2fa_uid"] = row["id"]
                session["2fa_at"] = time.time()
                return redirect(url_for("login_2fa"))
            if row["is_admin"] and REQUIRE_ADMIN_2FA:
                app.logger.warning("Admin login refused - 2FA not set up user=%s ip=%s", username, ip)
                flash("This admin account needs two-factor set up first "
                      "(on the server: flask --app app enable-2fa USERNAME).")
                return render_template("login.html"), 403
            return finish_login(row, ip)

        record_fail(("login-user", username), ("login-ip", ip))
        app.logger.warning("Login failed user=%s ip=%s", username, ip)
        flash("Invalid username or password.")
    return render_template("login.html")


def finish_login(row, ip):
    clear_fails("login-user", row["username"])
    session.clear()                      # new session on login (prevents fixation)
    session.permanent = True
    login_user(User(row))
    app.logger.info("Login ok user=%s ip=%s 2fa=%s", row["username"], ip, bool(row["totp_secret"]))
    return redirect(url_for("dashboard"))


def check_totp(row, code):
    """Accept the current code or one step either side (clock drift). Each code works once."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6:
        return None
    totp = pyotp.TOTP(row["totp_secret"])
    step_now = int(time.time()) // totp.interval
    last = row["totp_last"] or 0
    for step in (step_now - 1, step_now, step_now + 1):
        if step > last and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    uid, started = session.get("2fa_uid"), session.get("2fa_at", 0)
    if not uid or time.time() - started > TOTP_PENDING_SECONDS:
        session.clear()
        flash("Please sign in again.")
        return redirect(url_for("login"))

    row = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None or not row["totp_secret"]:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        ip = client_ip()
        if (fail_count("login-user", row["username"]) >= MAX_FAILS_PER_USER
                or fail_count("login-ip", ip) >= MAX_FAILS_PER_IP):
            session.clear()
            flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.")
            return redirect(url_for("login"))

        step = check_totp(row, request.form.get("code", "")[:20])
        if step is not None:
            with db() as con:
                con.execute("UPDATE users SET totp_last = ? WHERE id = ?", (step, row["id"]))
            return finish_login(row, ip)

        record_fail(("login-user", row["username"]), ("login-ip", ip))
        app.logger.warning("2FA code failed user=%s ip=%s", row["username"], ip)
        flash("That code wasn't right. Use the current 6-digit code from your authenticator app.")
    return render_template("login_2fa.html")


@app.post("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Ingest API (called by the site relay / Monitor-Master)
#
# New format:
#   { "items": [ { "type": "server", "host": "EW-SRV-DC01",
#                  "collected": "2026-10-22T18:00:00+01:00",
#                  "status": "warning",            # optional: ok / warning / critical / down
#                  "interval_minutes": 60,         # optional: how often this item reports
#                  "metrics": { "CPU_Pct": 12, ... } }, ... ] }
#
# Old format (still accepted, treated as type "server"):
#   { "generated": "...", "servers": [ { "ComputerName": "...", ... }, ... ] }
# --------------------------------------------------------------------------
class BadPayload(ValueError):
    pass


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, (int, float)):
        return v
    s = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    return s[:MAX_CELL_CHARS]


def clean_details(raw, i):
    """Validate optional detail sections:
       [ {"title": "...", "rows": [ {...}, ... ], "error": "...", "note": "..."}, ... ]
    Returns a list safe to store, or None."""
    if raw is None:
        return None
    if isinstance(raw, dict):                # PowerShell 5.1 lone object
        raw = [raw]
    if not isinstance(raw, list):
        raise BadPayload(f"Item {i}: 'details' must be a list of sections")
    if len(raw) > MAX_DETAIL_SECTIONS:
        raise BadPayload(f"Item {i}: too many detail sections (max {MAX_DETAIL_SECTIONS})")
    out = []
    for j, sec in enumerate(raw):
        if not isinstance(sec, dict) or not sec.get("title"):
            raise BadPayload(f"Item {i}: detail section {j} needs a 'title'")
        rows = sec.get("rows") or []
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise BadPayload(f"Item {i}: detail section {j} 'rows' must be a list of objects")
        if len(rows) > MAX_DETAIL_ROWS:
            raise BadPayload(f"Item {i}: detail section {j} has too many rows (max {MAX_DETAIL_ROWS})")
        clean_rows = []
        for r in rows:
            if len(r) > MAX_DETAIL_COLUMNS:
                raise BadPayload(f"Item {i}: detail section {j} has too many columns (max {MAX_DETAIL_COLUMNS})")
            clean_rows.append({str(k)[:100]: _cell(v) for k, v in r.items()})
        out.append({"title": str(sec["title"])[:200],
                    "error": str(sec.get("error") or "")[:1000],
                    "note": str(sec.get("note") or "")[:1000],
                    "rows": clean_rows})
    return out


def normalise_items(payload):
    """Turn either payload format into a list of
    (type, host, collected_dt, metrics, reported_status, interval_minutes, details)."""
    if not isinstance(payload, dict):
        raise BadPayload("Expected a JSON object")

    if "items" in payload:
        raw = payload["items"]
        if isinstance(raw, dict):            # PowerShell 5.1 sends a lone object, not a list
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            raise BadPayload("'items' must be a non-empty list")
        legacy = False
    elif "servers" in payload:
        raw = payload["servers"]
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            raise BadPayload("'servers' must be a non-empty list")
        legacy = True
    else:
        raise BadPayload("Expected 'items' (or old-style 'servers')")

    if len(raw) > MAX_ITEMS_PER_POST:
        raise BadPayload(f"Too many items in one post (max {MAX_ITEMS_PER_POST})")

    now = utcnow()
    batch_time = parse_time(payload.get("generated"))
    out = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise BadPayload(f"Item {i} must be an object")

        status, interval, details = None, None, None
        if legacy:
            dtype = "server"
            host = next((str(entry[k]) for k in HOST_KEYS if entry.get(k)), None)
            metrics = entry
            collected = batch_time
        else:
            status = entry.get("status")
            if status is not None:
                status = str(status).strip().lower()
                if status not in REPORTED_STATUSES:
                    raise BadPayload(f"Item {i}: status must be one of {', '.join(REPORTED_STATUSES)}")
            interval = entry.get("interval_minutes")
            if interval is not None:
                try:
                    interval = int(interval)
                except (TypeError, ValueError):
                    raise BadPayload(f"Item {i}: interval_minutes must be a whole number")
                if not 1 <= interval <= 7 * 24 * 60:
                    raise BadPayload(f"Item {i}: interval_minutes must be between 1 and 10080")
            dtype = str(entry.get("type", "")).strip().lower()
            host = str(entry.get("host", "")).strip() or None
            metrics = entry.get("metrics", {})
            collected = parse_time(entry.get("collected")) or batch_time
            if dtype not in DEVICE_TYPES:
                raise BadPayload(f"Item {i}: type must be one of {', '.join(DEVICE_TYPES)}")
            if not isinstance(metrics, dict):
                raise BadPayload(f"Item {i}: 'metrics' must be an object")
            details = clean_details(entry.get("details"), i)

        if not host:
            raise BadPayload(f"Item {i}: missing host name")
        if len(metrics) > MAX_METRIC_KEYS:
            raise BadPayload(f"Item {i}: too many metrics (max {MAX_METRIC_KEYS})")

        collected = collected or now
        # Clock-skewed machines can't make themselves look "online" in the future.
        if collected > now + timedelta(minutes=5):
            collected = now
        out.append((dtype, host[:255], collected, metrics, status, interval, details))
    return out


@app.post("/api/ingest")
@csrf.exempt
def ingest():
    if SECURE and not request.is_secure:
        return jsonify(error="HTTPS required"), 403

    ip = client_ip()
    if fail_count("apikey-ip", ip) >= MAX_BAD_KEYS_PER_IP:
        return jsonify(error="Too many failed attempts"), 429

    key = request.headers.get("X-API-Key", "")[:200]
    client = db().execute("SELECT id, name FROM clients WHERE api_key_hash = ?",
                          (hash_key(key),)).fetchone() if key else None
    if not client:
        record_fail(("apikey-ip", ip))
        app.logger.warning("Ingest rejected: bad API key ip=%s", ip)
        abort(401)

    payload = request.get_json(silent=True)
    try:
        items = normalise_items(payload)
    except BadPayload as e:
        return jsonify(error=str(e)), 400

    received = now_iso()
    generated = payload.get("generated")
    con = db()
    with con:
        cur = con.execute(
            "INSERT INTO runs (client_id, generated_at, received_at, server_count) VALUES (?, ?, ?, ?)",
            (client["id"], str(generated)[:64] if generated else None, received, len(items)))
        run_id = cur.lastrowid

        new_readings = 0
        for dtype, host, collected_dt, metrics, status, interval, details in items:
            collected = iso(collected_dt)
            metrics_json = json.dumps(metrics)
            details_json = json.dumps(details) if details is not None else None
            dev = con.execute(
                "SELECT id, last_seen FROM devices WHERE client_id = ? AND type = ? AND host = ?",
                (client["id"], dtype, host)).fetchone()
            if dev is None:
                dev_id = con.execute(
                    "INSERT INTO devices (client_id, type, host, first_seen, last_seen, latest_metrics, "
                    "reported_status, interval_minutes, latest_details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (client["id"], dtype, host, collected, collected, metrics_json,
                     status, interval, details_json)).lastrowid
            else:
                dev_id = dev["id"]
                # Only move forward: an old file delivered late doesn't overwrite newer data.
                if collected >= dev["last_seen"]:
                    con.execute("UPDATE devices SET last_seen = ?, latest_metrics = ?, "
                                "reported_status = ?, interval_minutes = ?, latest_details = ? "
                                "WHERE id = ?",
                                (collected, metrics_json, status, interval, details_json, dev_id))
            # The same reading sent twice (relay retry, unchanged CSV) is stored once.
            if con.execute("SELECT 1 FROM readings WHERE device_id = ? AND collected = ?",
                           (dev_id, collected)).fetchone() is None:
                con.execute(
                    "INSERT INTO readings (device_id, client_id, collected, received, metrics) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (dev_id, client["id"], collected, received, metrics_json))
                new_readings += 1

        prune_old(con, client["id"])

    app.logger.info("Ingest ok client=%s items=%d new=%d ip=%s",
                    client["name"], len(items), new_readings, ip)
    return jsonify(status="ok", run_id=run_id, items=len(items), new_readings=new_readings), 201


def prune_old(con, client_id):
    cutoff = iso(utcnow() - timedelta(days=app.config["RETENTION_DAYS"]))
    con.execute("DELETE FROM readings WHERE client_id = ? AND received < ?", (client_id, cutoff))
    con.execute("DELETE FROM runs WHERE client_id = ? AND received_at < ?", (client_id, cutoff))


# --------------------------------------------------------------------------
# Dashboard helpers
# --------------------------------------------------------------------------
def ago(dt):
    secs = int((utcnow() - dt).total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h {secs % 3600 // 60} min ago"
    return f"{secs // 86400} day(s) ago"


def local_time(dt):
    return dt.astimezone(DISPLAY_TZ).strftime("%d %b %Y %H:%M")


def device_status(dtype, last_seen_dt, reported=None, interval=None):
    """online / warning / critical / offline / not-seen.

    Stale data wins: if nothing has arrived within the expected interval the device is
    offline (or 'not seen' for PCs) whatever it last reported. Otherwise the collector's
    own verdict is used ("down" = the collector couldn't reach it, e.g. a switch not
    answering ping)."""
    cfg = DEVICE_TYPES.get(dtype, DEVICE_TYPES["other"])
    limit = (interval + OFFLINE_GRACE_MINUTES) if interval else cfg["offline_minutes"]
    if utcnow() - last_seen_dt > timedelta(minutes=limit):
        return "offline" if cfg["offline_is_alert"] else "not-seen"
    return {"warning": "warning", "critical": "critical", "down": "offline"}.get(reported, "online")


STATUS_ORDER = {"offline": 0, "critical": 1, "warning": 2, "not-seen": 3, "online": 4}
PROBLEM_STATUSES = ("offline", "critical", "warning")


def display_value(v, max_len=80):
    if v is None:
        return ""
    s = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    return s if len(s) <= max_len else s[:max_len - 3] + "..."


LINK_KEYS = ("Link", "Url", "URL")


def safe_link(v):
    """Only plain https links are rendered as clickable (never javascript:, data: etc.)."""
    v = str(v or "").strip()
    return v if v.lower().startswith("https://") and " " not in v and len(v) < 2000 else None


def build_sections(details_json):
    """Prepare stored detail sections for the template."""
    try:
        sections = json.loads(details_json) if details_json else []
    except ValueError:
        return []
    out = []
    for sec in sections:
        rows = sec.get("rows") or []
        columns = []
        for r in rows:
            for k in r:
                if k not in columns and k not in LINK_KEYS:
                    columns.append(k)
        if "Issues" in columns:
            columns.remove("Issues")
            columns.insert(0, "Issues")
        prepared = []
        for r in rows:
            link = next((safe_link(r[k]) for k in LINK_KEYS if r.get(k)), None)
            flag = ""
            sev = str(r.get("Severity", "")).lower()
            if sev == "high" or str(r.get("Status", "")).lower() in ("offline", "critical"):
                flag = "red"
            elif r.get("Issues") or sev == "medium":
                flag = "amber"
            prepared.append({
                "cells": {k: display_value(r.get(k), 300 if k in ("Issues", "Title", "Impact") else 120)
                          for k in columns},
                "full": {k: display_value(r.get(k), 2000) for k in columns},
                "link": link, "flag": flag})
        out.append({"title": sec.get("title", ""), "error": sec.get("error", ""),
                    "note": sec.get("note", ""), "columns": columns, "rows": prepared,
                    "has_links": any(p["link"] for p in prepared),
                    "problems": sum(1 for p in prepared if p["flag"])})
    return out


def resolve_client(con):
    """Which client the current user may view. Non-admins are always pinned to their own."""
    clients = None
    if current_user.is_admin:
        clients = con.execute("SELECT id, name FROM clients ORDER BY name").fetchall()
        valid_ids = {c["id"] for c in clients}
        client_id = request.args.get("client", type=int)
        if client_id not in valid_ids:
            client_id = clients[0]["id"] if clients else None
    else:
        client_id = current_user.client_id
    client = con.execute("SELECT id, name FROM clients WHERE id = ?",
                         (client_id,)).fetchone() if client_id else None
    return clients, client


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
@app.get("/")
@login_required
def dashboard():
    con = db()
    clients, client = resolve_client(con)
    if client is None:
        return render_template("dashboard.html", clients=clients, client=None, tabs=[],
                               active_type=None, devices=[], columns=[], summary=None,
                               last_report=None, refresh=REFRESH_SECONDS)

    rows = con.execute("SELECT * FROM devices WHERE client_id = ? ORDER BY host",
                       (client["id"],)).fetchall()

    devices_by_type = {}
    for r in rows:
        last_seen = parse_time(r["last_seen"])
        devices_by_type.setdefault(r["type"], []).append({
            "id": r["id"],
            "host": r["host"],
            "status": device_status(r["type"], last_seen, r["reported_status"], r["interval_minutes"]),
            "last_seen_ago": ago(last_seen),
            "last_seen_local": local_time(last_seen),
            "metrics": json.loads(r["latest_metrics"]),
            "details_raw": r["latest_details"],
        })

    # Tabs in a fixed order, only for types this client actually has
    tabs = []
    for t, cfg in DEVICE_TYPES.items():
        devs = devices_by_type.get(t)
        if devs:
            tabs.append({"type": t, "label": cfg["label"], "count": len(devs),
                         "problems": sum(d["status"] in PROBLEM_STATUSES for d in devs),
                         "red": any(d["status"] in ("offline", "critical") for d in devs)})

    active_type = request.args.get("type")
    if active_type not in devices_by_type:
        active_type = tabs[0]["type"] if tabs else None

    devices = devices_by_type.get(active_type, [])
    devices.sort(key=lambda d: (STATUS_ORDER[d["status"]], d["host"].lower()))

    columns = []
    for d in devices:
        for k in d["metrics"]:
            if k not in HOST_KEYS and k not in columns:
                columns.append(k)
        d["cells"] = {k: display_value(v, 300 if k == "Issues" else 80) for k, v in d["metrics"].items()}
    if "Issues" in columns:                      # problems first, right after Last seen
        columns.remove("Issues")
        columns.insert(0, "Issues")

    detail_blocks = [{"host": d["host"], "id": d["id"], "sections": build_sections(d["details_raw"])}
                     for d in devices if d.get("details_raw")]

    all_devs = [d for ds in devices_by_type.values() for d in ds]
    summary = {
        "total": len(all_devs),
        "online": sum(d["status"] == "online" for d in all_devs),
        "attention": sum(d["status"] in ("warning", "critical") for d in all_devs),
        "offline": sum(d["status"] == "offline" for d in all_devs),
        "not_seen": sum(d["status"] == "not-seen" for d in all_devs),
    }

    last = con.execute("SELECT received_at FROM runs WHERE client_id = ? "
                       "ORDER BY received_at DESC LIMIT 1", (client["id"],)).fetchone()
    last_report = ago(parse_time(last["received_at"])) if last else None

    return render_template("dashboard.html", clients=clients, client=client, tabs=tabs,
                           detail_blocks=detail_blocks,
                           active_type=active_type, devices=devices, columns=columns,
                           summary=summary, last_report=last_report, refresh=REFRESH_SECONDS)


@app.get("/device/<int:device_id>")
@login_required
def device_detail(device_id):
    con = db()
    dev = con.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    # Same 404 whether it doesn't exist or belongs to another client - no information leak.
    if dev is None or (not current_user.is_admin and dev["client_id"] != current_user.client_id):
        abort(404)

    client = con.execute("SELECT id, name FROM clients WHERE id = ?", (dev["client_id"],)).fetchone()
    last_seen = parse_time(dev["last_seen"])
    readings = con.execute(
        "SELECT collected, metrics FROM readings WHERE device_id = ? ORDER BY collected DESC LIMIT 100",
        (device_id,)).fetchall()

    history, columns = [], []
    for r in readings:
        m = json.loads(r["metrics"])
        for k in m:
            if k not in HOST_KEYS and k not in columns:
                columns.append(k)
        history.append({"when": local_time(parse_time(r["collected"])),
                        "cells": {k: display_value(v) for k, v in m.items()}})

    return render_template(
        "device.html", client=client, dev=dev,
        type_label=DEVICE_TYPES.get(dev["type"], DEVICE_TYPES["other"])["label"],
        status=device_status(dev["type"], last_seen, dev["reported_status"], dev["interval_minutes"]),
        last_seen_ago=ago(last_seen), last_seen_local=local_time(last_seen),
        first_seen_local=local_time(parse_time(dev["first_seen"])),
        history=history, columns=columns, refresh=REFRESH_SECONDS,
        sections=build_sections(dev["latest_details"]))


# --------------------------------------------------------------------------
# Admin CLI
# --------------------------------------------------------------------------
@app.cli.command("init-db")
def init_db_cmd():
    """Create the database tables."""
    init_db()
    click.echo(f"Database ready at {app.config['DATABASE']}")


@app.cli.command("create-client")
@click.argument("name")
def create_client(name):
    """Create a client and print its API key (shown once)."""
    key = secrets.token_urlsafe(32)
    try:
        with db() as con:
            con.execute("INSERT INTO clients (name, api_key_hash, created_at) VALUES (?, ?, ?)",
                        (name, hash_key(key), now_iso()))
    except sqlite3.IntegrityError:
        raise click.ClickException(f"Client '{name}' already exists")
    click.echo(f"Client '{name}' created.\nAPI key (store it now, it won't be shown again):\n{key}")


@app.cli.command("rotate-key")
@click.argument("name")
def rotate_key(name):
    """Issue a new API key for a client (the old one stops working)."""
    key = secrets.token_urlsafe(32)
    with db() as con:
        cur = con.execute("UPDATE clients SET api_key_hash = ? WHERE name = ?", (hash_key(key), name))
    if cur.rowcount == 0:
        raise click.ClickException(f"No client named '{name}'")
    click.echo(f"New API key for '{name}':\n{key}")


@app.cli.command("list-clients")
def list_clients():
    """List clients, their dashboard users and device counts."""
    con = db()
    for c in con.execute("SELECT * FROM clients ORDER BY name"):
        users = [u["username"] for u in con.execute(
            "SELECT username FROM users WHERE client_id = ?", (c["id"],))]
        n = con.execute("SELECT COUNT(*) FROM devices WHERE client_id = ?", (c["id"],)).fetchone()[0]
        click.echo(f"{c['name']}  (users: {', '.join(users) or 'none'}; devices: {n})")


@app.cli.command("forget-device")
@click.argument("client_name")
@click.argument("host")
@click.option("--type", "dtype", default=None, help="Only this device type")
def forget_device(client_name, host, dtype):
    """Remove a decommissioned device and its history."""
    con = db()
    row = con.execute("SELECT id FROM clients WHERE name = ?", (client_name,)).fetchone()
    if not row:
        raise click.ClickException(f"No client named '{client_name}'")
    q, args = "SELECT id FROM devices WHERE client_id = ? AND host = ?", [row["id"], host]
    if dtype:
        q += " AND type = ?"
        args.append(dtype)
    ids = [r["id"] for r in con.execute(q, args)]
    if not ids:
        raise click.ClickException("No matching device")
    with con:
        for i in ids:
            con.execute("DELETE FROM readings WHERE device_id = ?", (i,))
            con.execute("DELETE FROM devices WHERE id = ?", (i,))
    click.echo(f"Removed {len(ids)} device(s).")


@app.cli.command("create-user")
@click.argument("username")
@click.option("--client", "client_name", help="Client this user belongs to")
@click.option("--admin", is_flag=True, help="Admin: can view all clients")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def create_user(username, client_name, admin, password):
    """Create a dashboard login."""
    username = username.strip().lower()
    if not admin and not client_name:
        raise click.ClickException("Give --client NAME or --admin")
    if len(password) < 12:
        raise click.ClickException("Password must be at least 12 characters")
    con = db()
    client_id = None
    if client_name:
        row = con.execute("SELECT id FROM clients WHERE name = ?", (client_name,)).fetchone()
        if not row:
            raise click.ClickException(f"No client named '{client_name}'")
        client_id = row["id"]
    try:
        with con:
            con.execute(
                "INSERT INTO users (username, password_hash, client_id, is_admin) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), client_id, int(admin)))
    except sqlite3.IntegrityError:
        raise click.ClickException(f"User '{username}' already exists")
    click.echo(f"User '{username}' created.")


@app.cli.command("set-password")
@click.argument("username")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def set_password(username, password):
    """Reset a user's password (also clears any lockout)."""
    username = username.strip().lower()
    if len(password) < 12:
        raise click.ClickException("Password must be at least 12 characters")
    with db() as con:
        cur = con.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                          (generate_password_hash(password), username))
    if cur.rowcount == 0:
        raise click.ClickException(f"No user named '{username}'")
    clear_fails("login-user", username)
    click.echo("Password updated.")


@app.cli.command("list-users")
def list_users():
    """List dashboard logins, their client and whether 2FA is on."""
    con = db()
    for u in con.execute("SELECT u.username, u.is_admin, u.totp_secret, c.name AS client "
                         "FROM users u LEFT JOIN clients c ON c.id = u.client_id ORDER BY u.username"):
        role = "ADMIN" if u["is_admin"] else (u["client"] or "?")
        click.echo(f"{u['username']:<24} {role:<28} 2FA: {'on' if u['totp_secret'] else 'OFF'}")


@app.cli.command("enable-2fa")
@click.argument("username")
def enable_2fa(username):
    """Turn on authenticator-app codes for a user (replaces any existing setup)."""
    username = username.strip().lower()
    secret = pyotp.random_base32()
    with db() as con:
        cur = con.execute("UPDATE users SET totp_secret = ?, totp_last = NULL WHERE username = ?",
                          (secret, username))
    if cur.rowcount == 0:
        raise click.ClickException(f"No user named '{username}'")
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)
    click.echo(f"2FA enabled for '{username}'. Add it to an authenticator app "
               "(Microsoft Authenticator, Google Authenticator, 1Password...):\n")
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.print_ascii(invert=True)
    except ImportError:
        pass
    click.echo(f"\nOr enter this key by hand: {secret}\n(Shown once. Run enable-2fa again to reset.)")


@app.cli.command("disable-2fa")
@click.argument("username")
def disable_2fa(username):
    """Turn off 2FA for a user (e.g. lost phone). Re-enable straight after."""
    username = username.strip().lower()
    with db() as con:
        cur = con.execute("UPDATE users SET totp_secret = NULL, totp_last = NULL WHERE username = ?",
                          (username,))
    if cur.rowcount == 0:
        raise click.ClickException(f"No user named '{username}'")
    click.echo(f"2FA disabled for '{username}'.")


@app.cli.command("delete-user")
@click.argument("username")
def delete_user(username):
    """Remove a dashboard login (e.g. when a client's staff member leaves)."""
    with db() as con:
        cur = con.execute("DELETE FROM users WHERE username = ?", (username.strip().lower(),))
    if cur.rowcount == 0:
        raise click.ClickException(f"No user named '{username}'")
    click.echo(f"User '{username}' deleted.")


if __name__ == "__main__":
    # Local testing only. In production run behind gunicorn - never with debug on.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8080")), debug=False)
