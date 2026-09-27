#!/usr/bin/env python3
"""Contest control server: enrollment, signed command delivery, health + alerts,
long-polling, per-venue scoped tokens, roster, coordinator UI.

Stdlib only. Ed25519 signing is delegated to `openssl` (like scripts/build.sh).
Single process (long-poll + SSE keep in-memory state). Put TLS in front.

Run:  CONTROL_ADMIN_TOKEN=... python3 server.py
Test: python3 test_server.py
"""
import base64
import hmac
import json
import os
import queue
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))


def _env_path(name, default):
    return os.path.abspath(os.environ.get(name, os.path.join(HERE, default)))


DB_PATH = _env_path("CONTROL_DB", "data/control.db")
SIGNING_KEY = _env_path("CONTROL_SIGNING_KEY", "keys/command-signing.key")
GROUPS_FILE = _env_path("CONTROL_GROUP_TOKENS", "groups.json")
USERS_FILE = os.environ.get("AUTH_USERS", os.path.join(HERE, "users.json"))
INDEX_HTML = os.path.join(HERE, "index.html")
BRAND_LOGO_SVG = os.path.join(HERE, "icpc-bolivia-logo.svg")
BRAND_WALLPAPER_SVG = os.path.join(HERE, "icpc-bolivia-wallpaper.svg")
BIND = os.environ.get("CONTROL_BIND", "127.0.0.1:8090")
ADMIN_TOKEN = os.environ.get("CONTROL_ADMIN_TOKEN", "")
SERVER_NAME = os.environ.get("CONTROL_SERVER_NAME", "control")
DEFAULT_HOMEPAGE = os.environ.get(
    "AUTH_DEFAULT_HOMEPAGE", "file:///usr/share/doc/contest/index.html")
COMMAND_TTL_SECONDS = int(os.environ.get("CONTROL_COMMAND_TTL", "3600"))
LONGPOLL_MAX = int(os.environ.get("CONTROL_LONGPOLL_MAX", "30"))
SAMPLES_PER_MACHINE = int(os.environ.get("CONTROL_SAMPLES_MAX", "400"))
JOURNAL_BYTES_PER_MACHINE = int(os.environ.get("CONTROL_JOURNAL_MAX", "65536"))
SCREENSHOT_DIR = _env_path("CONTROL_SCREENSHOT_DIR", "data/screenshots")
SCREENSHOT_MAX_BYTES = int(os.environ.get("CONTROL_SCREENSHOT_MAX", str(6 * 1024 * 1024)))
# 'collect-home': tar.gz del home de cada equipo, para juntar el código al final.
HOME_DIR = _env_path("CONTROL_HOME_DIR", "data/homes")
HOME_MAX_BYTES = int(os.environ.get("CONTROL_HOME_MAX", str(400 * 1024 * 1024)))
HOME_KEEP = int(os.environ.get("CONTROL_HOME_KEEP", "10"))       # copias de codigo por equipo
PHASES = ("idle", "practice", "live", "frozen", "ended")
# Alertas calculadas en el servidor con los datos que ya llegan (sin tocar la ISO).
OFFLINE_SECS = int(os.environ.get("CONTROL_OFFLINE_SECS", "90"))   # sin reportar -> offline
OFFLINE_PHASES = ("practice", "live", "frozen")                    # solo vigilamos en concurso
DISK_FULL_PCT = 95
STATUS_EVERY = 30   # las PCs reportan estado cada ~29s (medido en samples)
# Historial de capturas manuales en disco, por equipo (sobrevive reinicios).
SHOT_KEEP = int(os.environ.get("CONTROL_SHOT_KEEP", "20"))       # ultimas N por equipo

MACHINE_ID_RE = "[A-Za-z0-9._-]{1,64}"
_MID_OK = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z").match

# action -> required arg keys. Anything not listed here is rejected.
# 'precontest', 'donottouch', 'cantouch', 'net-open', 'net-lock' are macros /
# state actions handled partly server-side (see _apply_state).
ACTIONS = {
    "lock": (),
    "unlock": (),
    "logout": (),                   # coordinador: cierra la sesion del concursante en esa maquina
    "reset-home": (),
    "message": ("text",),
    "reboot": (),
    "poweroff": (),
    "set-allowlist": ("hosts",),
    "usb-block": (),
    "usb-unblock": (),
    "set-wallpaper": ("url",),
    "set-homepage": ("url",),       # página de inicio de Firefox
    "precontest": (),
    "donottouch": (),
    "cantouch": (),
    "net-open": (),
    "net-lock": (),
    "screenshot": (),
    "collect-home": (),             # sube /home/<equipo> al control-server
    "unlock-root": ("password",),   # solo superadmin (ver _admin_cmd)
    "lock-root": (),                # solo superadmin
}
# Acciones peligrosas: solo el token superadmin (no un coordinador de sede).
# net-open/usb-unblock aflojan seguridad, collect-home saca el código de las
# máquinas y set-allowlist cambia a qué dominios llegan: un coordinador de
# sede puede bloquear/restringir pero no destrabar ni recolectar.
SUPERADMIN_ONLY = {
    "unlock-root", "lock-root",
    "net-open", "usb-block", "usb-unblock", "collect-home", "set-allowlist",
}
# Commands still handed to a frozen machine (unfreeze, and the freeze itself so
# the agent can set its local flag too).
FROZEN_ALLOWED = {"cantouch", "donottouch"}
MAX_PAYLOAD_BYTES = 8192
MAX_BODY_BYTES = 262144

# ponytail: one global DB lock + one condvar for long-poll wakeups; fine at
# contest scale (hundreds of machines). Per-group condvars if it ever matters.
_DB_LOCK = threading.RLock()
_CMD_COND = threading.Condition()
_conn = None

_SUBS_LOCK = threading.Lock()
_SUBSCRIBERS = []  # list of (scope_group_or_None, queue.Queue)


# --------------------------------------------------------------------------- db

def db():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS machines (
                machine_id  TEXT PRIMARY KEY,
                group_id    TEXT NOT NULL,
                bearer      TEXT NOT NULL,
                hostname    TEXT,
                ip          TEXT,
                enrolled_at TEXT NOT NULL,
                last_seen   TEXT,
                lock_state  INTEGER NOT NULL DEFAULT 0,
                frozen      INTEGER NOT NULL DEFAULT 0,
                status_json TEXT,
                status_at   TEXT,
                binding_json TEXT
            );
            CREATE TABLE IF NOT EXISTS commands (
                nonce      TEXT PRIMARY KEY,
                group_id   TEXT NOT NULL,
                machine_id TEXT NOT NULL,          -- '*' = whole group
                action     TEXT NOT NULL,
                args_json  TEXT NOT NULL,
                payload    BLOB NOT NULL,
                signature  TEXT NOT NULL,
                issued_at  TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status     TEXT NOT NULL DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS deliveries (
                nonce        TEXT NOT NULL,
                machine_id   TEXT NOT NULL,
                delivered_at TEXT,
                acked_at     TEXT,
                status       TEXT,
                detail       TEXT,
                PRIMARY KEY (nonce, machine_id)
            );
            CREATE TABLE IF NOT EXISTS samples (
                machine_id TEXT NOT NULL,
                t          INTEGER NOT NULL,
                mem        REAL, ld REAL, sw REAL, hd REAL
            );
            CREATE INDEX IF NOT EXISTS samples_m ON samples(machine_id, t);
            -- owner = user_id del equipo logueado (sobrevive al reinicio: el
            -- machine_id de la ISO live cambia en cada arranque); machine_id si no hay login.
            CREATE TABLE IF NOT EXISTS app_usage (
                group_id TEXT NOT NULL,
                owner    TEXT NOT NULL,
                app      TEXT NOT NULL,
                secs     INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (group_id, owner, app)
            );
            CREATE TABLE IF NOT EXISTS app_sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_id TEXT NOT NULL,
                app        TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                last_at    INTEGER NOT NULL,
                open       INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS app_sessions_m ON app_sessions (machine_id, id);
            CREATE TABLE IF NOT EXISTS journal (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_id TEXT NOT NULL,
                at         TEXT NOT NULL,
                nbytes     INTEGER NOT NULL,
                text       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS journal_m ON journal(machine_id, id);
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id     TEXT NOT NULL,
                machine_id   TEXT NOT NULL,
                kind         TEXT NOT NULL,
                detail       TEXT,
                raised_at    TEXT NOT NULL,
                dismissed_at TEXT,
                dismissed_by TEXT
            );
            CREATE INDEX IF NOT EXISTS alerts_open ON alerts(group_id, dismissed_at);
            CREATE TABLE IF NOT EXISTS roster (
                group_id TEXT NOT NULL,
                user_id  TEXT NOT NULL,
                name     TEXT NOT NULL,
                org      TEXT, seat TEXT, country TEXT,
                PRIMARY KEY (group_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS group_config (
                group_id       TEXT PRIMARY KEY,
                allowlist_json TEXT NOT NULL DEFAULT '[]',
                updated_at     TEXT
            );
            """
        )
        try:
            _conn.execute("ALTER TABLE group_config ADD COLUMN phase TEXT NOT NULL DEFAULT 'idle'")
        except sqlite3.OperationalError:
            pass  # ya existe
        try:
            _conn.execute("ALTER TABLE group_config ADD COLUMN homepage TEXT")
        except sqlite3.OperationalError:
            pass  # ya existe
        try:
            _conn.execute("ALTER TABLE group_config ADD COLUMN homepage_updated_at TEXT")
        except sqlite3.OperationalError:
            pass  # ya existe
        try:
            _conn.execute("ALTER TABLE group_config ADD COLUMN logo_url TEXT")
        except sqlite3.OperationalError:
            pass  # ya existe
        try:
            _conn.execute("ALTER TABLE group_config ADD COLUMN logo_updated_at TEXT")
        except sqlite3.OperationalError:
            pass  # ya existe
        try:
            _conn.execute("ALTER TABLE machines ADD COLUMN location TEXT")
        except sqlite3.OperationalError:
            pass  # ya existe
        try:
            _conn.execute("ALTER TABLE machines ADD COLUMN hidden_at TEXT")
        except sqlite3.OperationalError:
            pass  # ya existe
    return _conn


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def since_seconds(ts):
    if not ts:
        return None
    try:
        return int((now() - datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                    .replace(tzinfo=timezone.utc)).total_seconds())
    except ValueError:
        return None


def new_nonce():
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True).encode("utf-8") + b"\n"


def sign(payload: bytes) -> str:
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(payload)
        tmp.flush()
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", SIGNING_KEY, "-in", tmp.name],
            capture_output=True,
        )
    if proc.returncode != 0:
        raise RuntimeError("openssl sign failed: " + proc.stderr.decode("utf-8", "replace"))
    return base64.b64encode(proc.stdout).decode("ascii")


def group_records():
    """{group_id: {"enroll_token": str, "admin_token": str|None, "label": str}}.

    Accepts the legacy shape {group_id: "enroll-token"} too.
    """
    try:
        with open(GROUPS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise RuntimeError(f"{GROUPS_FILE} must be a JSON object")
    out = {}
    for gid, rec in data.items():
        if gid.startswith("_"):
            continue
        if isinstance(rec, str):
            out[str(gid)] = {"enroll_token": rec, "admin_token": None, "label": str(gid)}
        elif isinstance(rec, dict):
            out[str(gid)] = {
                "enroll_token": str(rec.get("enroll_token", "")),
                "admin_token": (str(rec["admin_token"]) if rec.get("admin_token") else None),
                "label": str(rec.get("label", gid)),
            }
    return out


def users_for_group(group_id):
    """[{"username", "password", "team_name"}] desde users.json (mismo archivo que auth-server.py)."""
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    out = []
    for username, rec in data.items():
        if username.startswith("_") or not isinstance(rec, dict):
            continue
        if not rec.get("team_id"):  # solo cuentas de equipo, no staff/admin sin team_id
            continue
        if str(rec.get("region", "")).strip() != group_id:
            continue
        out.append({
            "username": username,
            "password": str(rec.get("password", "")),
            "team_name": str(rec.get("team_name") or rec.get("display") or username),
        })
    out.sort(key=lambda u: u["username"])
    return out


# ------------------------------------------------------------------------ pubsub

def publish(evt, data, group_id=None):
    msg = f"event: {evt}\ndata: {json.dumps(data)}\n\n"
    with _SUBS_LOCK:
        for scope, q in _SUBSCRIBERS:
            if scope is None or scope == group_id or group_id is None:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass


# ---------------------------------------------------------------- state actions

def _targets(conn, group_id, machine_id):
    if machine_id == "*":
        return [r["machine_id"] for r in conn.execute(
            "SELECT machine_id FROM machines WHERE group_id=?", (group_id,))]
    return [machine_id]


def _apply_state(conn, group_id, machine_id, action):
    """Server-side effect of state/macro actions (in addition to delivering the
    signed command to the agent)."""
    mids = _targets(conn, group_id, machine_id)
    if not mids:
        return
    qmarks = ",".join("?" * len(mids))
    # lock_state applies immediately so a machine that reboots re-locks before it
    # even acks. frozen is applied on ack instead (see _ack) so the donottouch /
    # cantouch command itself still gets delivered in queue order.
    if action in ("lock", "precontest"):
        conn.execute(f"UPDATE machines SET lock_state=1 WHERE machine_id IN ({qmarks})", mids)
        for m in mids:
            publish("machine.locked", {"machine_id": m}, group_id)
    elif action == "unlock":
        conn.execute(f"UPDATE machines SET lock_state=0 WHERE machine_id IN ({qmarks})", mids)
        for m in mids:
            publish("machine.unlocked", {"machine_id": m}, group_id)
    elif action == "logout":
        # Quita la asignacion de equipo y saca la maquina de la vista principal
        # hasta que alguien vuelva a loguearse ahi (auto_bind limpia hidden_at).
        conn.execute(f"UPDATE machines SET binding_json=NULL, hidden_at=? WHERE machine_id IN ({qmarks})",
                     [iso(now())] + mids)
        for m in mids:
            publish("machine.logged_out", {"machine_id": m}, group_id)


def enqueue_command(conn, group_id, machine_id, action, args, ttl=None):
    """Build, sign and store one signed command. Caller holds _DB_LOCK.
    Raises ValueError (payload too big) or RuntimeError (openssl). Returns the
    payload dict."""
    issued = now()
    expires = issued + timedelta(seconds=max(60, ttl or COMMAND_TTL_SECONDS))
    payload_obj = {
        "action": action, "args": args, "expires_at": iso(expires),
        "group_id": group_id, "issued_at": iso(issued), "machine_id": machine_id,
        "nonce": new_nonce(), "server": SERVER_NAME,
    }
    payload = canonical(payload_obj)
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"signed payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    signature = sign(payload)
    conn.execute(
        """INSERT INTO commands (nonce, group_id, machine_id, action, args_json,
               payload, signature, issued_at, expires_at, created_at, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,'pending')""",
        (payload_obj["nonce"], group_id, machine_id, action, json.dumps(args),
         payload, signature, iso(issued), iso(expires), iso(issued)))
    return payload_obj


def stored_allowlist(conn, group_id):
    row = conn.execute("SELECT allowlist_json, updated_at FROM group_config WHERE group_id=?",
                       (group_id,)).fetchone()
    return (json.loads(row["allowlist_json"]) if row else [],
            row["updated_at"] if row else None)


def raise_alert(conn, group_id, machine_id, kind, detail=None):
    """Una alerta abierta por (maquina, tipo, detalle). -> (id, es_nueva)."""
    dup = conn.execute(
        "SELECT id FROM alerts WHERE group_id=? AND machine_id=? AND kind=? "
        "AND IFNULL(detail,'')=IFNULL(?,'') AND dismissed_at IS NULL",
        (group_id, machine_id, kind, detail)).fetchone()
    if dup:
        return dup["id"], False
    aid = conn.execute(
        "INSERT INTO alerts (group_id, machine_id, kind, detail, raised_at) VALUES (?,?,?,?,?)",
        (group_id, machine_id, kind, detail, iso(now()))).lastrowid
    publish("alert.raised", {"id": aid, "machine_id": machine_id, "kind": kind, "detail": detail}, group_id)
    return aid, True


def resolve_alerts(conn, machine_id, kind):
    conn.execute("UPDATE alerts SET dismissed_at=?, dismissed_by='auto' "
                 "WHERE machine_id=? AND kind=? AND dismissed_at IS NULL", (iso(now()), machine_id, kind))


def detect_restart(conn, group_id, machine_id, uid):
    """El machine_id de la ISO live cambia en cada arranque: el mismo equipo aparece
    con un machine_id nuevo y el anterior lleva rato en silencio = la PC se reinicio
    o colgo. No alerta si el logout la oculto, si el anterior sigue reportando (dos
    PCs del mismo equipo) ni si un admin ordeno reboot/poweroff hace poco.
    La IP no sirve: es la IP publica de la sede, compartida por todas sus PCs."""
    for old in conn.execute(
            "SELECT machine_id, last_seen FROM machines WHERE group_id=? AND machine_id!=? "
            "AND hidden_at IS NULL AND json_extract(binding_json,'$.user_id')=?",
            (group_id, machine_id, uid)).fetchall():
        age = since_seconds(old["last_seen"])
        if age is None or age <= 2 * STATUS_EVERY:
            continue   # sigue reportando: es otra PC, no un reinicio
        resolve_alerts(conn, old["machine_id"], "offline")   # volvio: ya no esta offline
        if age > 1800:
            continue
        ordered = conn.execute(
            "SELECT 1 FROM commands WHERE group_id=? AND machine_id IN (?, '*') "
            "AND action IN ('reboot','poweroff') AND created_at>=?",
            (group_id, old["machine_id"], iso(now() - timedelta(seconds=1800)))).fetchone()
        if not ordered:
            raise_alert(conn, group_id, machine_id, "restart",
                        f"reinicio inesperado (sin señal hace {age}s)")
        return


def check_offline():
    """PC que dejo de reportar durante el concurso -> alerta 'offline'.
    Solo PCs con equipo logueado. ponytail: ventana 1h para no alertar PCs viejas al
    arrancar el servidor; una PC reemplazada (mismo equipo con last_seen mas nuevo,
    p.ej. tras reiniciar) no cuenta."""
    with _DB_LOCK:
        conn = db()
        live = {r["group_id"] for r in conn.execute("SELECT group_id, phase FROM group_config")
                if r["phase"] in OFFLINE_PHASES}
        for m in conn.execute("SELECT machine_id, group_id, last_seen, "
                              "json_extract(binding_json,'$.user_id') AS uid FROM machines "
                              "WHERE hidden_at IS NULL AND binding_json IS NOT NULL"):
            age = since_seconds(m["last_seen"])
            if m["group_id"] not in live or age is None or not OFFLINE_SECS < age < 3600:
                continue
            if conn.execute("SELECT 1 FROM machines WHERE group_id=? AND machine_id!=? "
                            "AND json_extract(binding_json,'$.user_id')=? AND last_seen>?",
                            (m["group_id"], m["machine_id"], m["uid"], m["last_seen"])).fetchone():
                continue
            raise_alert(conn, m["group_id"], m["machine_id"], "offline",
                        f"sin reportar desde {m['last_seen']}")


def watchdog():
    while True:
        time.sleep(30)
        try:
            check_offline()
        except Exception as e:  # el vigilante nunca debe morir
            print(f"watchdog: {e}", flush=True)


def stored_phase(conn, group_id):
    row = conn.execute("SELECT phase FROM group_config WHERE group_id=?", (group_id,)).fetchone()
    return row["phase"] if row else "idle"


def stored_homepage(conn, group_id):
    row = conn.execute("SELECT homepage, homepage_updated_at FROM group_config WHERE group_id=?",
                       (group_id,)).fetchone()
    fallback = conn.execute(
        "SELECT homepage FROM group_config WHERE group_id='__global__'").fetchone()
    own = (row["homepage"] or "") if row else ""
    default = (fallback["homepage"] or "") if fallback else ""
    return (own or default or DEFAULT_HOMEPAGE,
            row["homepage_updated_at"] if row else None)


def valid_homepage(url):
    parsed = urlparse(url)
    return ((parsed.scheme in ("http", "https") and bool(parsed.netloc))
            or url.startswith("file:///usr/share/doc/contest/")
            or url == "about:blank")


def stored_logo(conn, group_id):
    row = conn.execute("SELECT logo_url, logo_updated_at FROM group_config WHERE group_id=?",
                       (group_id,)).fetchone()
    own = (row["logo_url"] or "") if row else ""
    fallback = conn.execute(
        "SELECT logo_url FROM group_config WHERE group_id='__global__'").fetchone()
    effective = own or ((fallback["logo_url"] or "") if fallback else "")
    return own, effective, row["logo_updated_at"] if row else None


def valid_logo_url(url):
    parsed = urlparse(url)
    return not url or (parsed.scheme in ("http", "https") and bool(parsed.netloc))


def auto_bind(conn, group_id, machine_id, login):
    """La máquina reporta qué equipo inició sesión -> se liga sola. Si el
    user_id está en el roster usa ese registro (con asiento, etc.); si no,
    liga con el nombre auto-reportado. Devuelve el binding nuevo o None."""
    uid = str(login.get("user_id") or login.get("team_id") or "").strip()
    if not uid:
        return None
    row = conn.execute("SELECT binding_json FROM machines WHERE machine_id=?", (machine_id,)).fetchone()
    if row and row["binding_json"]:
        try:
            if (json.loads(row["binding_json"]) or {}).get("user_id") == uid:
                return None  # ya ligado a este equipo
        except (ValueError, TypeError):
            pass
    region = str(login.get("region") or "").strip() or None
    region_name = str(login.get("region_name") or "").strip() or None
    e = conn.execute("SELECT * FROM roster WHERE group_id=? AND user_id=?", (group_id, uid)).fetchone()
    if e:
        binding = {"user_id": e["user_id"], "name": e["name"], "org": e["org"],
                   "seat": e["seat"], "country": e["country"]}
    else:
        binding = {"user_id": uid, "org": None, "seat": None, "country": None,
                   "name": str(login.get("team_name") or login.get("username") or uid)[:128],
                   "self_reported": True}
    if region:
        binding["region"] = region
        binding["region_name"] = region_name
        binding["region_mismatch"] = region.lower() not in ("", group_id.lower())
    conn.execute("UPDATE machines SET binding_json=?, hidden_at=NULL WHERE machine_id=?",
                 (json.dumps(binding), machine_id))
    return binding


def screenshot_path(machine_id):
    return os.path.join(SCREENSHOT_DIR, machine_id + ".png")


def _safe_seg(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s or "_")


def shot_owner(conn, machine_id):
    """Historial por equipo (user_id), no por machine_id: este cambia en cada arranque."""
    r = conn.execute("SELECT binding_json FROM machines WHERE machine_id=?", (machine_id,)).fetchone()
    b = json.loads(r["binding_json"]) if r and r["binding_json"] else {}
    return b.get("user_id") or machine_id


def shot_hist_dir(group_id, owner):
    return os.path.join(SCREENSHOT_DIR, "hist", _safe_seg(group_id), _safe_seg(owner))


def shot_hist_list(group_id, owner):
    """Marcas de tiempo (epoch, ms) de las capturas guardadas, mas nuevas primero."""
    try:
        names = [n[:-4] for n in os.listdir(shot_hist_dir(group_id, owner)) if n.endswith(".png")]
    except OSError:
        return []
    return sorted((n for n in names if n.isdigit()), key=int, reverse=True)


def home_dir(group_id, owner):
    """Codigo recogido por equipo (no por machine_id): cada recogida es una copia nueva
    <epoch_ms>.tar.gz y no pisa a la anterior; se conservan las ultimas HOME_KEEP."""
    return os.path.join(HOME_DIR, _safe_seg(group_id), _safe_seg(owner))


def home_stamps(group_id, owner):
    """Marcas de tiempo (epoch ms) de las copias del equipo, mas nueva primero."""
    try:
        names = [n[:-7] for n in os.listdir(home_dir(group_id, owner)) if n.endswith(".tar.gz")]
    except OSError:
        return []
    return sorted((n for n in names if n.isdigit()), key=int, reverse=True)


def home_meta_of(group_id, owner):
    """(edad_s, bytes, team_id) de la copia mas nueva, o (None, None, None)."""
    stamps = home_stamps(group_id, owner)
    if not stamps:
        return None, None, None
    d = home_dir(group_id, owner)
    try:
        with open(os.path.join(d, "team")) as fh:
            team = fh.read().strip() or None
    except OSError:
        team = None
    return (int(time.time() - int(stamps[0]) / 1000),
            os.path.getsize(os.path.join(d, stamps[0] + ".tar.gz")), team)


def home_age_of(group_id, owner):
    return home_meta_of(group_id, owner)[0]


# --------------------------------------------------------------------- handler

class ControlHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], ConnectionResetError):
            super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    server_version = "contest-control/2"
    protocol_version = "HTTP/1.1"

    # -- io helpers ---------------------------------------------------------
    def _send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _error(self, code, message):
        self._json(code, {"error": message})

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _read_text(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            return ""
        return self.rfile.read(length).decode("utf-8", "replace")

    def _bearer(self):
        h = self.headers.get("Authorization", "")
        return h[7:] if h.startswith("Bearer ") else ""

    def _client_ip(self):
        return (self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or self.client_address[0])

    def log_message(self, fmt, *args):
        super().log_message(fmt, *args)

    # -- auth -------------------------------------------------------------
    def _admin_scope(self, token=None):
        """Returns (ok, scope): scope is None for superadmin, or a group_id for a
        venue-scoped admin token. Sends the error response itself on failure."""
        tok = token if token is not None else self._bearer()
        if ADMIN_TOKEN and hmac.compare_digest(tok, ADMIN_TOKEN):
            return True, None
        for gid, rec in group_records().items():
            if rec["admin_token"] and hmac.compare_digest(tok, rec["admin_token"]):
                return True, gid
        if not ADMIN_TOKEN:
            self._error(503, "CONTROL_ADMIN_TOKEN is not set")
        else:
            self._error(401, "bad admin token")
        return False, None

    def _scope_ok(self, scope, group_id):
        """404 (not 403) for cross-venue access so names of other venues leak."""
        if scope is not None and scope != group_id:
            self._error(404, "not found")
            return False
        return True

    def _auth_machine(self, group_id, machine_id):
        row = db().execute("SELECT * FROM machines WHERE machine_id=?", (machine_id,)).fetchone()
        if not row or row["group_id"] != group_id:
            return None
        if not hmac.compare_digest(self._bearer(), row["bearer"]):
            return None
        return row

    # -- routing --------------------------------------------------------
    def _route(self):
        parsed = urlparse(self.path)
        return [p for p in parsed.path.split("/") if p], parse_qs(parsed.query)

    def do_GET(self):
        p, q = self._route()
        if p in ([], ["index.html"]):
            return self._serve_index()
        if p == ["icpc-bolivia-logo.svg"]:
            return self._serve_brand_logo()
        if p == ["icpc-bolivia-wallpaper.svg"]:
            return self._serve_brand_wallpaper()
        if p == ["healthz"]:
            return self._json(200, {"ok": True})
        if p == ["admin", "machines"]:
            return self._admin_machines()
        if p == ["admin", "commands"]:
            return self._admin_commands(q)
        if p == ["admin", "alerts"]:
            return self._admin_alerts()
        if p == ["admin", "roster"]:
            return self._admin_roster_get()
        if p == ["admin", "allowlist"]:
            return self._admin_allowlist_get(q)
        if p == ["admin", "homepage"]:
            return self._admin_homepage_get(q)
        if p == ["admin", "logo"]:
            return self._admin_logo_get(q)
        if p == ["admin", "phase"]:
            return self._admin_phase_get(q)
        if p == ["admin", "events"]:
            return self._sse(q)
        if p == ["admin", "quota"]:
            return self._admin_quota()
        if p == ["admin", "report"]:
            return self._admin_report(q)
        if p == ["admin", "credentials"]:
            return self._admin_credentials(q)
        if len(p) == 5 and p[0] == "admin" and p[1] == "machines" and p[4] == "screenshot":
            return self._screenshot_get(p[2], p[3], q)
        if len(p) in (5, 6) and p[0] == "admin" and p[1] == "machines" and p[4] == "shots":
            return self._shots(p[2], p[3], p[5] if len(p) == 6 else None, q)
        if len(p) == 5 and p[0] == "admin" and p[1] == "machines" and p[4] == "home":
            return self._home_get(p[2], p[3], q)
        if len(p) == 3 and p[0] == "admin" and p[1] == "homes":
            return self._homes_zip(p[2], q)
        if len(p) == 4 and p[0] == "admin" and p[1] == "machines":
            return self._admin_machine_detail(p[2], p[3])
        if len(p) == 3 and p[0] == "cmd":
            return self._poll(p[1], p[2], q)
        return self._error(404, "not found")

    def do_POST(self):
        p, _ = self._route()
        if p == ["enroll"]:
            return self._enroll()
        if p == ["admin", "cmd"]:
            return self._admin_cmd()
        if len(p) == 4 and p[0] == "cmd" and p[3] == "ack":
            return self._ack(p[1], p[2])
        if len(p) == 4 and p[0] == "cmd" and p[3] == "status":
            return self._status(p[1], p[2])
        if len(p) == 4 and p[0] == "cmd" and p[3] == "journal":
            return self._journal(p[1], p[2])
        if len(p) == 4 and p[0] == "cmd" and p[3] == "events":
            return self._machine_event(p[1], p[2])
        if len(p) == 4 and p[0] == "cmd" and p[3] == "screenshot":
            return self._screenshot_upload(p[1], p[2])
        if len(p) == 4 and p[0] == "cmd" and p[3] == "home":
            return self._home_upload(p[1], p[2])
        if p == ["admin", "phase"]:
            return self._admin_phase_put()
        if len(p) == 4 and p[0] == "admin" and p[1] == "alerts" and p[3] == "dismiss":
            return self._admin_alert_dismiss(p[2])
        if p == ["admin", "roster"]:
            return self._admin_roster_put()
        if p == ["admin", "allowlist"]:
            return self._admin_allowlist_put()
        if p == ["admin", "homepage"]:
            return self._admin_homepage_put()
        if p == ["admin", "logo"]:
            return self._admin_logo_put()
        if len(p) == 5 and p[0] == "admin" and p[1] == "machines" and p[4] == "binding":
            return self._admin_binding(p[2], p[3])
        if len(p) == 5 and p[0] == "admin" and p[1] == "machines" and p[4] == "location":
            return self._admin_location(p[2], p[3])
        return self._error(404, "not found")

    def do_PUT(self):
        return self.do_POST()

    # -- pages / boot ---------------------------------------------------
    def _serve_index(self):
        try:
            with open(INDEX_HTML, "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
        except FileNotFoundError:
            self._error(404, "index.html missing")

    def _serve_brand_logo(self):
        try:
            with open(BRAND_LOGO_SVG, "rb") as fh:
                self._send(200, fh.read(), "image/svg+xml")
        except FileNotFoundError:
            self._error(404, "logo missing")

    def _serve_brand_wallpaper(self):
        try:
            with open(BRAND_WALLPAPER_SVG, "rb") as fh:
                self._send(200, fh.read(), "image/svg+xml")
        except FileNotFoundError:
            self._error(404, "wallpaper missing")

    def _enroll(self):
        body = self._read_json()
        if not isinstance(body, dict):
            return self._error(400, "expected a JSON object")
        machine_id = str(body.get("machine_id", ""))
        group_id = str(body.get("group_id", ""))
        token = str(body.get("enroll_token", ""))
        hostname = str(body.get("hostname", ""))[:128] or None
        if not _MID_OK(machine_id):
            return self._error(400, f"machine_id must match {MACHINE_ID_RE}")
        rec = group_records().get(group_id)
        if not rec or not rec["enroll_token"] or not hmac.compare_digest(token, rec["enroll_token"]):
            return self._error(401, "unknown group or bad enroll token")
        bearer = secrets.token_urlsafe(32)
        with _DB_LOCK:
            conn = db()
            first = conn.execute("SELECT 1 FROM machines WHERE machine_id=?", (machine_id,)).fetchone() is None
            conn.execute(
                """INSERT INTO machines (machine_id, group_id, bearer, hostname, ip, enrolled_at, last_seen)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(machine_id) DO UPDATE SET
                     group_id=excluded.group_id, bearer=excluded.bearer,
                     hostname=excluded.hostname, ip=excluded.ip, last_seen=excluded.last_seen""",
                (machine_id, group_id, bearer, hostname, self._client_ip(), iso(now()), iso(now())),
            )
            # A machine reverts /etc to the squashfs on every boot, so re-push the
            # group's persistent allowlist right after (re-)enrollment.
            hosts, _ = stored_allowlist(conn, group_id)
            if hosts:
                try:
                    enqueue_command(conn, group_id, machine_id, "set-allowlist", {"hosts": hosts})
                except (ValueError, RuntimeError):
                    pass
        if first:
            publish("machine.first_seen", {"machine_id": machine_id, "group_id": group_id}, group_id)
        return self._json(200, {"bearer": bearer, "machine_id": machine_id, "group_id": group_id})

    def _poll(self, group_id, machine_id, query):
        row = self._auth_machine(group_id, machine_id)
        if not row:
            return self._error(401, "enroll first / bad bearer")
        try:
            wait = max(0, min(LONGPOLL_MAX, int((query.get("wait") or ["0"])[0])))
        except ValueError:
            wait = 0
        deadline = time.monotonic() + wait
        while True:
            with _DB_LOCK:
                conn = db()
                conn.execute("UPDATE machines SET last_seen=?, ip=? WHERE machine_id=?",
                             (iso(now()), self._client_ip(), machine_id))
                fresh = conn.execute("SELECT lock_state, frozen, binding_json FROM machines WHERE machine_id=?",
                                     (machine_id,)).fetchone()
                frozen = fresh["frozen"]
                cmd = conn.execute(
                    f"""SELECT nonce, payload, signature, action FROM commands
                       WHERE group_id=? AND (machine_id=? OR machine_id='*')
                         AND expires_at > ? AND status != 'acked'
                         {"AND action IN ('%s')" % "','".join(FROZEN_ALLOWED) if frozen else ""}
                         AND nonce NOT IN (
                             SELECT nonce FROM deliveries WHERE machine_id=? AND acked_at IS NOT NULL)
                       ORDER BY created_at ASC LIMIT 1""",
                    (group_id, machine_id, iso(now()), machine_id),
                ).fetchone()
                if cmd:
                    conn.execute(
                        """INSERT INTO deliveries (nonce, machine_id, delivered_at, status)
                           VALUES (?,?,?,'delivered')
                           ON CONFLICT(nonce, machine_id) DO UPDATE SET delivered_at=excluded.delivered_at""",
                        (cmd["nonce"], machine_id, iso(now())),
                    )
                    meta = {"lock_state": fresh["lock_state"], "frozen": frozen,
                            "phase": stored_phase(conn, group_id),
                            "binding": json.loads(fresh["binding_json"]) if fresh["binding_json"] else None}
            if cmd:
                return self._json(200, {
                    "nonce": cmd["nonce"], "action": cmd["action"],
                    "payload_b64": base64.b64encode(cmd["payload"]).decode("ascii"),
                    "signature": cmd["signature"], "command": json.loads(cmd["payload"]),
                    "meta": meta,
                })
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with _DB_LOCK:
                    phase = stored_phase(db(), group_id)
                meta = {"lock_state": fresh["lock_state"], "frozen": frozen, "phase": phase,
                        "binding": json.loads(fresh["binding_json"]) if fresh["binding_json"] else None}
                return self._send(200, json.dumps({"meta": meta}), "application/json") \
                    if wait else self._send(204, b"")
            with _CMD_COND:
                _CMD_COND.wait(timeout=min(remaining, 5))

    def _ack(self, group_id, machine_id):
        body = self._read_json()
        if not isinstance(body, dict) or "nonce" not in body:
            return self._error(400, "expected {nonce, status?, detail?}")
        with _DB_LOCK:
            conn = db()
            if not self._auth_machine(group_id, machine_id):
                return self._error(401, "enroll first / bad bearer")
            nonce = str(body["nonce"])
            status = str(body.get("status", "ok"))[:32]
            detail = str(body.get("detail", ""))[:512] or None
            cmd = conn.execute("SELECT * FROM commands WHERE nonce=?", (nonce,)).fetchone()
            if not cmd or cmd["group_id"] != group_id:
                return self._error(404, "unknown nonce")
            conn.execute(
                """INSERT INTO deliveries (nonce, machine_id, delivered_at, acked_at, status, detail)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(nonce, machine_id) DO UPDATE SET
                     acked_at=excluded.acked_at, status=excluded.status, detail=excluded.detail""",
                (nonce, machine_id, iso(now()), iso(now()), status, detail),
            )
            if cmd["machine_id"] != "*":
                conn.execute("UPDATE commands SET status='acked' WHERE nonce=?", (nonce,))
            if status == "ok" and cmd["action"] == "donottouch":
                conn.execute("UPDATE machines SET frozen=1 WHERE machine_id=?", (machine_id,))
            elif status == "ok" and cmd["action"] == "cantouch":
                conn.execute("UPDATE machines SET frozen=0 WHERE machine_id=?", (machine_id,))
        publish("command.acked", {"nonce": nonce, "machine_id": machine_id,
                                  "action": cmd["action"], "status": status}, group_id)
        return self._json(200, {"ok": True})

    def _status(self, group_id, machine_id):
        body = self._read_json()
        if not self._auth_machine(group_id, machine_id):
            return self._error(401, "enroll first / bad bearer")
        if not isinstance(body, dict):
            return self._error(400, "expected a JSON object")
        t = int(time.time())
        num = lambda k: (float(body[k]) if isinstance(body.get(k), (int, float)) else None)
        bound = None
        with _DB_LOCK:
            conn = db()
            # Tiempo por programa: cada editor presente suma el intervalo desde el
            # reporte anterior. ponytail: tope 60s (una PC offline no suma horas);
            # mide "abierto", no "en foco".
            prev = conn.execute("SELECT status_at FROM machines WHERE machine_id=?",
                                (machine_id,)).fetchone()
            gap = (since_seconds(prev["status_at"]) or 0) if prev else 0
            dt = min(gap, 60)
            if gap > OFFLINE_SECS:
                resolve_alerts(conn, machine_id, "offline")   # volvio a reportar
            if (num("hd") or 0) >= DISK_FULL_PCT:
                raise_alert(conn, group_id, machine_id, "disk.full", f">= {DISK_FULL_PCT}%")
            login = body.get("login") if isinstance(body.get("login"), dict) else {}
            owner = str(login.get("user_id") or login.get("team_id") or "").strip() or machine_id
            apps = body.get("editors")
            for app in (apps if isinstance(apps, dict) and dt > 0 else ()):
                conn.execute("INSERT INTO app_usage (group_id, owner, app, secs) VALUES (?,?,?,?) "
                             "ON CONFLICT(group_id, owner, app) DO UPDATE SET secs=secs+excluded.secs",
                             (group_id, owner, str(app)[:64], dt))
            # Historial: una sesion por programa mientras siga apareciendo en el reporte.
            # Deja de aparecer (o la PC estuvo offline > OFFLINE_SECS) -> se cierra.
            present = [str(a)[:64] for a in apps] if isinstance(apps, dict) else []
            conn.execute("UPDATE app_sessions SET open=0 WHERE machine_id=? AND open=1 AND "
                         "(? - last_at > ? OR app NOT IN (%s))" % ",".join("?" * len(present)),
                         (machine_id, t, OFFLINE_SECS, *present))
            for app in present:
                if not conn.execute("UPDATE app_sessions SET last_at=? WHERE machine_id=? "
                                    "AND app=? AND open=1", (t, machine_id, app)).rowcount:
                    conn.execute("INSERT INTO app_sessions (machine_id, app, started_at, last_at) "
                                 "VALUES (?,?,?,?)", (machine_id, app, t, t))
            conn.execute("UPDATE machines SET status_json=?, status_at=?, last_seen=? WHERE machine_id=?",
                         (json.dumps(body)[:8192], iso(now()), iso(now()), machine_id))
            conn.execute("INSERT INTO samples (machine_id, t, mem, ld, sw, hd) VALUES (?,?,?,?,?,?)",
                         (machine_id, t, num("mem"), num("ld"), num("sw"), num("hd")))
            conn.execute(
                """DELETE FROM samples WHERE machine_id=? AND t NOT IN (
                       SELECT t FROM samples WHERE machine_id=? ORDER BY t DESC LIMIT ?)""",
                (machine_id, machine_id, SAMPLES_PER_MACHINE))
            if isinstance(body.get("login"), dict):
                bound = auto_bind(conn, group_id, machine_id, body["login"])
                if bound:
                    detect_restart(conn, group_id, machine_id, bound["user_id"])
        publish("machine.status", {"machine_id": machine_id, **{k: body.get(k) for k in
                ("mem", "ld", "hd", "virt", "usb", "locked")}}, group_id)
        if bound:
            publish("machine.bound", {"machine_id": machine_id, "user_id": bound["user_id"],
                                      "auto": True}, group_id)
        return self._json(200, {"ok": True})

    def _journal(self, group_id, machine_id):
        if not self._auth_machine(group_id, machine_id):
            return self._error(401, "enroll first / bad bearer")
        text = self._read_text()
        if not text.strip():
            return self._json(200, {"ok": True})
        with _DB_LOCK:
            conn = db()
            conn.execute("INSERT INTO journal (machine_id, at, nbytes, text) VALUES (?,?,?,?)",
                         (machine_id, iso(now()), len(text.encode()), text[:JOURNAL_BYTES_PER_MACHINE]))
            total = conn.execute("SELECT COALESCE(SUM(nbytes),0) FROM journal WHERE machine_id=?",
                                 (machine_id,)).fetchone()[0]
            while total > JOURNAL_BYTES_PER_MACHINE:
                oldest = conn.execute("SELECT id, nbytes FROM journal WHERE machine_id=? ORDER BY id ASC LIMIT 1",
                                      (machine_id,)).fetchone()
                if not oldest:
                    break
                conn.execute("DELETE FROM journal WHERE id=?", (oldest["id"],))
                total -= oldest["nbytes"]
        return self._json(200, {"ok": True})

    def _screenshot_upload(self, group_id, machine_id):
        if not self._auth_machine(group_id, machine_id):
            return self._error(401, "enroll first / bad bearer")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > SCREENSHOT_MAX_BYTES:
            return self._error(413, "captura vacía o demasiado grande")
        data = self.rfile.read(length)
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return self._error(400, "se esperaba PNG")
        os.makedirs(SCREENSHOT_DIR, exist_ok=True)
        dst = screenshot_path(machine_id)
        tmp = dst + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, dst)
        with _DB_LOCK:
            hist = shot_hist_dir(group_id, shot_owner(db(), machine_id))
        os.makedirs(hist, exist_ok=True)
        with open(os.path.join(hist, "%d.png" % (time.time() * 1000)), "wb") as fh:
            fh.write(data)
        for old in sorted((n for n in os.listdir(hist) if n.endswith(".png")), key=lambda n: int(n[:-4]))[:-SHOT_KEEP]:
            os.remove(os.path.join(hist, old))
        publish("machine.screenshot", {"machine_id": machine_id, "at": iso(now())}, group_id)
        return self._json(200, {"ok": True, "bytes": len(data)})

    def _screenshot_get(self, group_id, machine_id, query=None):
        # <img> no manda cabeceras: se acepta ?token= además del header.
        ok, scope = self._admin_scope(token=((query or {}).get("token") or [None])[0])
        if not ok:
            return
        if not self._scope_ok(scope, group_id):
            return
        try:
            with open(screenshot_path(machine_id), "rb") as fh:
                data = fh.read()
        except FileNotFoundError:
            return self._error(404, "sin captura")
        return self._send(200, data, "image/png", {"Cache-Control": "no-store"})

    def _shots(self, group_id, machine_id, ts, query):
        """Historial: sin ts lista las marcas; con ts sirve esa captura (PNG)."""
        ok, scope = self._admin_scope(token=((query or {}).get("token") or [None])[0])
        if not ok or not self._scope_ok(scope, group_id):
            return
        with _DB_LOCK:
            owner = shot_owner(db(), machine_id)
        if ts is None:
            return self._json(200, {"shots": shot_hist_list(group_id, owner)})
        if not ts.isdigit():
            return self._error(400, "ts invalido")
        try:
            with open(os.path.join(shot_hist_dir(group_id, owner), ts + ".png"), "rb") as fh:
                return self._send(200, fh.read(), "image/png", {"Cache-Control": "max-age=3600"})
        except FileNotFoundError:
            return self._error(404, "sin captura")

    def _home_meta(self, group_id, machine_id):
        """(age_seconds, size_bytes, team_id) o (None, None, None) si no hay."""
        with _DB_LOCK:
            owner = shot_owner(db(), machine_id)
        return home_meta_of(group_id, owner)

    def _home_upload(self, group_id, machine_id):
        if not self._auth_machine(group_id, machine_id):
            return self._error(401, "enroll first / bad bearer")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > HOME_MAX_BYTES:
            return self._error(413, "home vacío o demasiado grande")
        data = self.rfile.read(length)
        if data[:2] != b"\x1f\x8b":
            return self._error(400, "se esperaba gzip")
        with _DB_LOCK:
            owner = shot_owner(db(), machine_id)
        hdir = home_dir(group_id, owner)
        os.makedirs(hdir, exist_ok=True)
        ts = "%d" % (time.time() * 1000)
        tmp = os.path.join(hdir, ts + ".part")
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, os.path.join(hdir, ts + ".tar.gz"))   # copia nueva: no pisa la anterior
        for old in home_stamps(group_id, owner)[HOME_KEEP:]:
            os.remove(os.path.join(hdir, old + ".tar.gz"))
        team = (self.headers.get("X-Team-Id") or "").strip()[:64]
        if team:
            with open(os.path.join(hdir, "team"), "w") as fh:
                fh.write(team)
        publish("machine.home", {"machine_id": machine_id, "bytes": len(data),
                                 "at": iso(now())}, group_id)
        return self._json(200, {"ok": True, "bytes": len(data)})

    def _home_get(self, group_id, machine_id, query=None):
        ok, scope = self._admin_scope(token=((query or {}).get("token") or [None])[0])
        if not ok:
            return
        if not self._scope_ok(scope, group_id):
            return
        with _DB_LOCK:
            owner = shot_owner(db(), machine_id)
        stamps = home_stamps(group_id, owner)
        if not stamps:
            return self._error(404, "sin código recogido")
        with open(os.path.join(home_dir(group_id, owner), stamps[0] + ".tar.gz"), "rb") as fh:
            data = fh.read()
        _, _, team = home_meta_of(group_id, owner)
        name = ((team + "__") if team else "") + owner + ".tar.gz"
        return self._send(200, data, "application/gzip", {
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="%s"' % name.replace('"', ""),
        })

    def _homes_zip(self, group_id, query=None):
        ok, scope = self._admin_scope(token=((query or {}).get("token") or [None])[0])
        if not ok:
            return
        if not self._scope_ok(scope, group_id):
            return
        import io
        import zipfile
        gdir = os.path.join(HOME_DIR, _safe_seg(group_id))
        owners = sorted(o for o in os.listdir(gdir) if os.path.isdir(os.path.join(gdir, o))) \
            if os.path.isdir(gdir) else []
        buf = io.BytesIO()
        n = 0
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            for owner in owners:   # la copia mas nueva de cada equipo
                stamps = home_stamps(group_id, owner)
                if not stamps:
                    continue
                team = home_meta_of(group_id, owner)[2]
                z.write(os.path.join(gdir, owner, stamps[0] + ".tar.gz"),
                        ((team + "__") if team else "") + owner + ".tar.gz")
                n += 1
        if not n:
            return self._error(404, "sin código recogido en el grupo")
        return self._send(200, buf.getvalue(), "application/zip", {
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="%s-codigo.zip"' % _safe_seg(group_id),
        })

    def _admin_phase_get(self, query):
        ok, scope = self._admin_scope()
        if not ok:
            return
        group_id = (query.get("group") or [scope or ""])[0]
        if not group_id:
            return self._error(400, "group required")
        if not self._scope_ok(scope, group_id):
            return
        return self._json(200, {"group_id": group_id, "phase": stored_phase(db(), group_id)})

    def _admin_phase_put(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        body = self._read_json()
        if not isinstance(body, dict):
            return self._error(400, "expected {group_id, phase}")
        group_id = str(body.get("group_id", "")) or scope
        phase = str(body.get("phase", ""))
        if not group_id:
            return self._error(400, "group_id required")
        if phase not in PHASES:
            return self._error(400, "phase inválida: %s" % ", ".join(PHASES))
        if not self._scope_ok(scope, group_id):
            return
        with _DB_LOCK:
            db().execute(
                """INSERT INTO group_config (group_id, phase, updated_at) VALUES (?,?,?)
                   ON CONFLICT(group_id) DO UPDATE SET phase=excluded.phase, updated_at=excluded.updated_at""",
                (group_id, phase, iso(now())))
        with _CMD_COND:
            _CMD_COND.notify_all()   # despierta los long-poll para que reciban meta.phase
        publish("phase.changed", {"group_id": group_id, "phase": phase}, group_id)
        return self._json(200, {"ok": True, "group_id": group_id, "phase": phase})

    def _machine_event(self, group_id, machine_id):
        body = self._read_json()
        if not self._auth_machine(group_id, machine_id):
            return self._error(401, "enroll first / bad bearer")
        if not isinstance(body, dict) or not body.get("kind"):
            return self._error(400, "expected {kind, detail?}")
        kind = str(body["kind"])[:64]
        detail = str(body.get("detail", ""))[:256] or None
        with _DB_LOCK:
            aid, new = raise_alert(db(), group_id, machine_id, kind, detail)
        if not new:
            return self._json(200, {"ok": True, "alert_id": aid, "duplicate": True})
        return self._json(200, {"ok": True, "alert_id": aid})

    # -- admin: commands ---------------------------------------------
    def _admin_cmd(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        body = self._read_json()
        if not isinstance(body, dict):
            return self._error(400, "expected a JSON object")
        target = body.get("target") or {}
        action = str(body.get("action", ""))
        args = body.get("args") or {}
        ttl = int(body.get("ttl_seconds") or COMMAND_TTL_SECONDS)
        if action not in ACTIONS:
            return self._error(400, f"unknown action; allowed: {sorted(ACTIONS)}")
        if action in SUPERADMIN_ONLY and scope is not None:
            return self._error(403, f"'{action}' solo con el token superadmin")
        if not isinstance(args, dict):
            return self._error(400, "args must be an object")
        for key in ACTIONS[action]:
            if not args.get(key):
                return self._error(400, f"action '{action}' requires args.{key}")
        if action == "set-allowlist" and not isinstance(args.get("hosts"), list):
            return self._error(400, "args.hosts must be a list")

        if target.get("all"):
            # Toda Bolivia (todos los grupos): solo superadmin y solo capturas; bloquear o
            # apagar el pais entero de un clic seria demasiado peligroso.
            if scope is not None or action != "screenshot":
                return self._error(403, "target 'all' solo con el token superadmin y solo para 'screenshot'")
            with _DB_LOCK:
                conn = db()
                groups = [r["group_id"] for r in conn.execute("SELECT DISTINCT group_id FROM machines")]
                try:
                    nonces = [enqueue_command(conn, g, "*", action, args, ttl)["nonce"] for g in groups]
                except (ValueError, RuntimeError) as exc:
                    return self._error(500, str(exc))
            with _CMD_COND:
                _CMD_COND.notify_all()
            for g, n in zip(groups, nonces):
                publish("command.sent", {"nonce": n, "action": action, "machine_id": "*"}, g)
            return self._json(200, {"groups": groups, "nonces": nonces})

        machine_id = str(target.get("machine_id", "")) or "*"
        group_id = str(target.get("group_id", ""))
        with _DB_LOCK:
            conn = db()
            if machine_id != "*":
                row = conn.execute("SELECT group_id FROM machines WHERE machine_id=?", (machine_id,)).fetchone()
                if not row:
                    return self._error(404, "unknown machine_id")
                group_id = group_id or row["group_id"]
                if group_id != row["group_id"]:
                    return self._error(400, "machine_id is not in that group")
            if not group_id:
                return self._error(400, "target needs group_id and/or a known machine_id")
            if not self._scope_ok(scope, group_id):
                return
            try:
                payload_obj = enqueue_command(conn, group_id, machine_id, action, args, ttl)
            except ValueError as exc:
                return self._error(400, str(exc))
            except RuntimeError as exc:
                return self._error(500, str(exc))
            _apply_state(conn, group_id, machine_id, action)
        with _CMD_COND:
            _CMD_COND.notify_all()
        publish("command.sent", {"nonce": payload_obj["nonce"], "action": action,
                                 "machine_id": machine_id}, group_id)
        return self._json(200, {"nonce": payload_obj["nonce"], "group_id": group_id,
                                "machine_id": machine_id, "expires_at": payload_obj["expires_at"]})

    # -- admin: dashboards -----------------------------------------
    def _machine_rows(self, scope):
        rows = db().execute("SELECT * FROM machines ORDER BY group_id, machine_id").fetchall()
        alert_ct = {}
        for r in db().execute(
                "SELECT machine_id, COUNT(*) c FROM alerts WHERE dismissed_at IS NULL GROUP BY machine_id"):
            alert_ct[r["machine_id"]] = r["c"]
        out = []
        for r in rows:
            if scope is not None and r["group_id"] != scope:
                continue
            if r["hidden_at"]:  # logout: fuera del Home hasta el proximo login
                continue
            st = json.loads(r["status_json"]) if r["status_json"] else {}
            out.append({
                "machine_id": r["machine_id"], "group_id": r["group_id"],
                "hostname": r["hostname"], "ip": r["ip"],
                "location": r["location"],
                "seconds_since_seen": since_seconds(r["last_seen"]),
                "lock_state": r["lock_state"], "frozen": r["frozen"],
                "open_alerts": alert_ct.get(r["machine_id"], 0),
                "binding": json.loads(r["binding_json"]) if r["binding_json"] else None,
                "mem": st.get("mem"), "ld": st.get("ld"), "hd": st.get("hd"),
                "virt": st.get("virt"), "usb": st.get("usb"),
                "editors": st.get("editors") or {},
                "status_age": since_seconds(r["status_at"]),
                "home_age": home_age_of(r["group_id"], (json.loads(r["binding_json"] or "{}").get("user_id"))
                                        or r["machine_id"]),
            })
        return out

    def _admin_machines(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        phases = {r["group_id"]: r["phase"] for r in db().execute(
            "SELECT group_id, phase FROM group_config")}
        return self._json(200, {"machines": self._machine_rows(scope), "now": iso(now()),
                                "scope": scope, "phases": phases})

    def _admin_machine_detail(self, group_id, machine_id):
        ok, scope = self._admin_scope()
        if not ok:
            return
        if not self._scope_ok(scope, group_id):
            return
        conn = db()
        m = conn.execute("SELECT * FROM machines WHERE machine_id=? AND group_id=?",
                         (machine_id, group_id)).fetchone()
        if not m:
            return self._error(404, "not found")
        samples = [dict(r) for r in conn.execute(
            "SELECT t, mem, ld, sw, hd FROM samples WHERE machine_id=? ORDER BY t DESC LIMIT ?",
            (machine_id, SAMPLES_PER_MACHINE))][::-1]
        owner = (json.loads(m["binding_json"] or "{}").get("user_id")) or machine_id
        app_usage = {r["app"]: r["secs"] for r in conn.execute(
            "SELECT app, secs FROM app_usage WHERE group_id=? AND owner=?", (group_id, owner))}
        app_history = [dict(r) for r in conn.execute(
            "SELECT app, started_at, last_at, open FROM app_sessions WHERE machine_id=? "
            "ORDER BY id DESC LIMIT 200", (machine_id,))]
        jrn = "\n".join(r["text"] for r in conn.execute(
            "SELECT text FROM journal WHERE machine_id=? ORDER BY id ASC", (machine_id,)))
        alerts = [dict(r) for r in conn.execute(
            "SELECT * FROM alerts WHERE machine_id=? ORDER BY id DESC LIMIT 100", (machine_id,))]
        cmds = [dict(r) for r in conn.execute(
            """SELECT c.nonce, c.action, c.issued_at, c.status,
                      d.delivered_at, d.acked_at, d.status AS ack_status, d.detail
               FROM commands c LEFT JOIN deliveries d
                 ON d.nonce=c.nonce AND d.machine_id=?
               WHERE c.group_id=? AND (c.machine_id=? OR c.machine_id='*') 
               ORDER BY c.created_at DESC LIMIT 50""",
            (machine_id, group_id, machine_id))]
        try:
            shot_age = int(time.time() - os.path.getmtime(screenshot_path(machine_id)))
        except OSError:
            shot_age = None
        home_age, home_size, home_team = self._home_meta(group_id, machine_id)
        return self._json(200, {
            "machine_id": machine_id, "group_id": group_id,
            "status": json.loads(m["status_json"]) if m["status_json"] else None,
            "status_age": since_seconds(m["status_at"]),
            "lock_state": m["lock_state"], "frozen": m["frozen"],
            "location": m["location"],
            "phase": stored_phase(conn, group_id),
            "screenshot_age": shot_age,
            "home_age": home_age, "home_size": home_size, "home_team": home_team,
            "binding": json.loads(m["binding_json"]) if m["binding_json"] else None,
            "app_usage": app_usage,
            "app_history": app_history,
            "samples": samples, "journal": jrn[-JOURNAL_BYTES_PER_MACHINE:],
            "alerts": alerts, "commands": cmds,
        })

    def _admin_commands(self, query):
        ok, scope = self._admin_scope()
        if not ok:
            return
        limit = min(int((query.get("limit") or ["50"])[0]), 500)
        where = "WHERE c.group_id=?" if scope else ""
        params = ([scope] if scope else []) + [limit]
        rows = db().execute(
            f"""SELECT c.nonce, c.group_id, c.machine_id, c.action, c.args_json,
                       c.issued_at, c.expires_at, c.status,
                       (SELECT COUNT(*) FROM deliveries d WHERE d.nonce=c.nonce) AS delivered,
                       (SELECT COUNT(*) FROM deliveries d WHERE d.nonce=c.nonce AND d.acked_at IS NOT NULL) AS acked
                FROM commands c {where} ORDER BY c.created_at DESC LIMIT ?""", params).fetchall()
        cmds = [dict(r) for r in rows]
        if scope is not None:
            # un coordinador de sede no debe ver la password de unlock-root (solo superadmin)
            for c in cmds:
                if c["action"] == "unlock-root":
                    c["args_json"] = None
        return self._json(200, {"commands": cmds})

    def _admin_alerts(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        where = "WHERE dismissed_at IS NULL" + (" AND group_id=?" if scope else "")
        params = [scope] if scope else []
        rows = db().execute(
            f"SELECT * FROM alerts {where} ORDER BY id DESC", params).fetchall()
        return self._json(200, {"alerts": [dict(r) for r in rows]})

    def _admin_alert_dismiss(self, alert_id):
        ok, scope = self._admin_scope()
        if not ok:
            return
        who = scope or "admin"
        with _DB_LOCK:
            conn = db()
            a = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not a:
                return self._error(404, "not found")
            if not self._scope_ok(scope, a["group_id"]):
                return
            conn.execute("UPDATE alerts SET dismissed_at=?, dismissed_by=? WHERE id=? AND dismissed_at IS NULL",
                         (iso(now()), who, alert_id))
        publish("alert.dismissed", {"id": int(alert_id), "by": who}, a["group_id"])
        return self._json(200, {"ok": True})

    # -- admin: roster / bindings --------------------------------
    def _admin_roster_get(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        where = "WHERE group_id=?" if scope else ""
        params = [scope] if scope else []
        rows = db().execute(f"SELECT * FROM roster {where} ORDER BY group_id, seat, name", params).fetchall()
        return self._json(200, {"roster": [dict(r) for r in rows]})

    def _admin_roster_put(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        body = self._read_json()
        if not isinstance(body, dict) or not isinstance(body.get("entries"), list):
            return self._error(400, "expected {group_id, entries:[...]}")
        group_id = str(body.get("group_id", "")) or scope
        if not group_id:
            return self._error(400, "group_id required")
        if not self._scope_ok(scope, group_id):
            return
        with _DB_LOCK:
            conn = db()
            conn.execute("DELETE FROM roster WHERE group_id=?", (group_id,))
            for e in body["entries"]:
                if not isinstance(e, dict) or not e.get("user_id") or not e.get("name"):
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO roster (group_id, user_id, name, org, seat, country) VALUES (?,?,?,?,?,?)",
                    (group_id, str(e["user_id"])[:64], str(e["name"])[:128],
                     str(e.get("org", ""))[:128] or None, str(e.get("seat", ""))[:32] or None,
                     str(e.get("country", ""))[:8] or None))
        return self._json(200, {"ok": True})

    def _admin_binding(self, group_id, machine_id):
        ok, scope = self._admin_scope()
        if not ok:
            return
        if not self._scope_ok(scope, group_id):
            return
        body = self._read_json() or {}
        with _DB_LOCK:
            conn = db()
            m = conn.execute("SELECT 1 FROM machines WHERE machine_id=? AND group_id=?",
                             (machine_id, group_id)).fetchone()
            if not m:
                return self._error(404, "not found")
            uid = str(body.get("user_id", "")) if isinstance(body, dict) else ""
            if not uid:
                conn.execute("UPDATE machines SET binding_json=NULL WHERE machine_id=?", (machine_id,))
                publish("machine.unbound", {"machine_id": machine_id}, group_id)
                return self._json(200, {"ok": True})
            e = conn.execute("SELECT * FROM roster WHERE group_id=? AND user_id=?", (group_id, uid)).fetchone()
            if not e:
                return self._error(404, "unknown user_id in roster")
            binding = {"user_id": e["user_id"], "name": e["name"], "org": e["org"],
                       "seat": e["seat"], "country": e["country"]}
            conn.execute("UPDATE machines SET binding_json=? WHERE machine_id=?",
                         (json.dumps(binding), machine_id))
        publish("machine.bound", {"machine_id": machine_id, "user_id": uid}, group_id)
        return self._json(200, {"ok": True, "binding": binding})

    def _admin_location(self, group_id, machine_id):
        """Ubicación física manual (texto libre): 'Sala 3, PC 12', etc."""
        ok, scope = self._admin_scope()
        if not ok:
            return
        if not self._scope_ok(scope, group_id):
            return
        body = self._read_json() or {}
        loc = str(body.get("location", "")).strip()[:200] if isinstance(body, dict) else ""
        with _DB_LOCK:
            conn = db()
            m = conn.execute("SELECT 1 FROM machines WHERE machine_id=? AND group_id=?",
                             (machine_id, group_id)).fetchone()
            if not m:
                return self._error(404, "not found")
            conn.execute("UPDATE machines SET location=? WHERE machine_id=?",
                         (loc or None, machine_id))
        publish("machine.located", {"machine_id": machine_id, "location": loc}, group_id)
        return self._json(200, {"ok": True, "location": loc})

    # -- admin: persistent allowlist -----------------------------
    def _admin_allowlist_get(self, query):
        ok, scope = self._admin_scope()
        if not ok:
            return
        if scope is not None:
            return self._error(403, "allowlist persistente: solo con el token superadmin")
        group_id = (query.get("group") or [scope or ""])[0]
        if not group_id:
            return self._error(400, "group required")
        if not self._scope_ok(scope, group_id):
            return
        hosts, updated_at = stored_allowlist(db(), group_id)
        return self._json(200, {"group_id": group_id, "hosts": hosts, "updated_at": updated_at})

    def _admin_allowlist_put(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        if scope is not None:
            return self._error(403, "allowlist persistente: solo con el token superadmin")
        body = self._read_json()
        if not isinstance(body, dict) or not isinstance(body.get("hosts"), list):
            return self._error(400, "expected {group_id, hosts:[...]}")
        group_id = str(body.get("group_id", "")) or scope
        if not group_id:
            return self._error(400, "group_id required")
        if not self._scope_ok(scope, group_id):
            return
        hosts, seen = [], set()
        for h in body["hosts"]:
            h = str(h).strip()
            if h and not h.startswith("#") and len(h) <= 253 and h not in seen:
                seen.add(h)
                hosts.append(h)
        if len(hosts) > 500:
            return self._error(400, "too many hosts (max 500)")
        with _DB_LOCK:
            conn = db()
            conn.execute(
                """INSERT INTO group_config (group_id, allowlist_json, updated_at) VALUES (?,?,?)
                   ON CONFLICT(group_id) DO UPDATE SET
                     allowlist_json=excluded.allowlist_json, updated_at=excluded.updated_at""",
                (group_id, json.dumps(hosts), iso(now())))
            try:
                payload_obj = enqueue_command(conn, group_id, "*", "set-allowlist", {"hosts": hosts})
            except ValueError as exc:
                return self._error(400, str(exc))
            except RuntimeError as exc:
                return self._error(500, str(exc))
        with _CMD_COND:
            _CMD_COND.notify_all()
        publish("command.sent", {"nonce": payload_obj["nonce"], "action": "set-allowlist",
                                 "machine_id": "*"}, group_id)
        return self._json(200, {"ok": True, "group_id": group_id, "hosts": hosts,
                                "nonce": payload_obj["nonce"]})

    # -- admin: homepage entregada por el login -------------------
    def _admin_homepage_get(self, query):
        ok, scope = self._admin_scope()
        if not ok:
            return
        group_id = (query.get("group") or [scope or "__global__"])[0]
        if not self._scope_ok(scope, group_id):
            return
        url, updated_at = stored_homepage(db(), group_id)
        return self._json(200, {"group_id": group_id, "url": url, "updated_at": updated_at})

    def _admin_homepage_put(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        body = self._read_json()
        if not isinstance(body, dict):
            return self._error(400, "expected {group_id, url}")
        group_id = str(body.get("group_id", "")) or scope or "__global__"
        url = str(body.get("url", "")).strip()
        if not self._scope_ok(scope, group_id):
            return
        if not valid_homepage(url):
            return self._error(400, "url must be http(s), about:blank or local contest documentation")
        updated_at = iso(now())
        with _DB_LOCK:
            db().execute(
                """INSERT INTO group_config (group_id, homepage, homepage_updated_at) VALUES (?,?,?)
                   ON CONFLICT(group_id) DO UPDATE SET
                     homepage=excluded.homepage, homepage_updated_at=excluded.homepage_updated_at""",
                (group_id, url, updated_at))
        publish("homepage.changed", {"group_id": group_id, "url": url},
                None if group_id == "__global__" else group_id)
        return self._json(200, {"ok": True, "group_id": group_id, "url": url,
                                "updated_at": updated_at})

    # -- admin: logo SVG aplicado en el próximo login -------------
    def _admin_logo_get(self, query):
        ok, scope = self._admin_scope()
        if not ok:
            return
        group_id = (query.get("group") or [scope or "__global__"])[0]
        if not self._scope_ok(scope, group_id):
            return
        url, effective_url, updated_at = stored_logo(db(), group_id)
        return self._json(200, {"group_id": group_id, "url": url,
                                "effective_url": effective_url,
                                "inherited": not url and bool(effective_url),
                                "updated_at": updated_at})

    def _admin_logo_put(self):
        ok, scope = self._admin_scope()
        if not ok:
            return
        body = self._read_json()
        if not isinstance(body, dict):
            return self._error(400, "expected {group_id, url}")
        group_id = str(body.get("group_id", "")) or scope or "__global__"
        url = str(body.get("url", "")).strip()
        if not self._scope_ok(scope, group_id):
            return
        if not valid_logo_url(url):
            return self._error(400, "logo url must be http(s)")
        updated_at = iso(now())
        with _DB_LOCK:
            db().execute(
                """INSERT INTO group_config (group_id, logo_url, logo_updated_at) VALUES (?,?,?)
                   ON CONFLICT(group_id) DO UPDATE SET
                     logo_url=excluded.logo_url, logo_updated_at=excluded.logo_updated_at""",
                (group_id, url, updated_at))
        publish("logo.changed", {"group_id": group_id, "url": url},
                None if group_id == "__global__" else group_id)
        return self._json(200, {"ok": True, "group_id": group_id, "url": url,
                                "updated_at": updated_at})

    # -- admin: SSE + report ------------------------------------
    def _sse(self, query):
        # EventSource can't set headers → token in the query string (header still
        # works for curl / tests).
        ok, scope = self._admin_scope(token=(query.get("token") or [None])[0])
        if not ok:
            return
        q = queue.Queue(maxsize=256)
        with _SUBS_LOCK:
            _SUBSCRIBERS.append((scope, q))
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=20)
                except queue.Empty:
                    msg = ": ping\n\n"
                self.wfile.write(msg.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _SUBS_LOCK:
                try:
                    _SUBSCRIBERS.remove((scope, q))
                except ValueError:
                    pass

    def _admin_quota(self):
        """Por sede: equipos esperados (users.json), conectados ahora y los que faltan.
        Conectado = su usuario esta logueado en una PC que reporto en los ultimos 120s
        (el mismo umbral 'offline' del panel). Nunca devuelve contrasenas."""
        ok, scope = self._admin_scope()
        if not ok:
            return
        recs = group_records()
        rows = db().execute(
            "SELECT group_id, last_seen, json_extract(binding_json,'$.user_id') AS uid "
            "FROM machines WHERE hidden_at IS NULL").fetchall()
        out = []
        for g in sorted(recs):
            if g == "lobby" or (scope is not None and g != scope):
                continue
            users = users_for_group(g)
            live = [r for r in rows if r["group_id"] == g
                    and (lambda s: s is not None and s <= 4 * STATUS_EVERY)(since_seconds(r["last_seen"]))]
            on = {r["uid"] for r in live if r["uid"]}
            out.append({
                "group_id": g, "label": recs[g]["label"],
                "expected": len(users),
                "connected": sum(1 for u in users if u["username"] in on),
                "machines": len(live), "no_login": sum(1 for r in live if not r["uid"]),
                "missing": [{"username": u["username"], "team_name": u["team_name"]}
                            for u in users if u["username"] not in on],
            })
        return self._json(200, {"quota": out})

    def _admin_report(self, query):
        # opened in a new tab → allow ?token= as well as the header.
        ok, scope = self._admin_scope(token=(query.get("token") or [None])[0])
        if not ok:
            return
        group_id = (query.get("group") or [scope or ""])[0]
        if scope and group_id != scope:
            return self._error(404, "not found")
        machines = self._machine_rows(scope or (group_id or None))
        if group_id:
            machines = [m for m in machines if m["group_id"] == group_id]
        conn = db()
        where = "WHERE group_id=?" if group_id else ""
        params = [group_id] if group_id else []
        alerts = [dict(r) for r in conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT 500", params)]
        data = {"generated_at": iso(now()), "group": group_id or "(all)",
                "machines": machines, "alerts": alerts}
        if (query.get("format") or ["html"])[0] == "json":
            return self._json(200, data)
        return self._send(200, _report_html(data), "text/html; charset=utf-8")

    def _admin_credentials(self, query):
        # opened in a new tab → allow ?token= as well as the header.
        ok, scope = self._admin_scope(token=(query.get("token") or [None])[0])
        if not ok:
            return
        group_id = (query.get("group") or [scope or ""])[0]
        if not group_id:
            return self._error(400, "group required")
        if scope and group_id != scope:
            return self._error(404, "not found")
        users = users_for_group(group_id)
        if (query.get("format") or ["html"])[0] == "json":
            return self._json(200, {"group_id": group_id, "users": users})
        return self._send(200, _credentials_html(group_id, users), "text/html; charset=utf-8")


def _report_html(d):
    def esc(x):
        return (str(x) if x is not None else "").replace("&", "&amp;").replace("<", "&lt;")
    rows = "".join(
        f"<tr><td>{esc(m['machine_id'])}</td><td>{esc(m['group_id'])}</td>"
        f"<td>{esc(m['binding'] and m['binding'].get('name'))}</td>"
        f"<td>{esc(m['seconds_since_seen'])}</td><td>{esc(m['mem'])}</td><td>{esc(m['hd'])}</td>"
        f"<td>{'sí' if m['lock_state'] else ''}</td><td>{esc(m['virt'])}</td>"
        f"<td>{m['open_alerts'] or ''}</td></tr>" for m in d["machines"])
    arows = "".join(
        f"<tr><td>{esc(a['raised_at'])}</td><td>{esc(a['machine_id'])}</td><td>{esc(a['kind'])}</td>"
        f"<td>{esc(a['detail'])}</td><td>{esc(a['dismissed_by'])} {esc(a['dismissed_at'])}</td></tr>"
        for a in d["alerts"])
    return f"""<!doctype html><meta charset=utf-8><title>Reporte {esc(d['group'])}</title>
<style>body{{font:14px system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}
td,th{{border:1px solid #ccc;padding:.3rem .5rem;text-align:left}}</style>
<h1>Reporte — {esc(d['group'])}</h1><p>Generado {esc(d['generated_at'])}</p>
<h2>Máquinas ({len(d['machines'])})</h2>
<table><tr><th>máquina<th>grupo<th>equipo<th>visto (s)<th>mem%<th>disco%<th>bloqueada<th>virt<th>alertas</tr>{rows}</table>
<h2>Alertas ({len(d['alerts'])})</h2>
<table><tr><th>cuándo<th>máquina<th>tipo<th>detalle<th>descartada por</tr>{arows}</table>
""".encode("utf-8")


def _credentials_html(group_id, users):
    def esc(x):
        return (str(x) if x is not None else "").replace("&", "&amp;").replace("<", "&lt;")
    cards = "".join(
        f"""<div class="card">
          <img class="logo" src="https://icpcbolivia.org/brand/logo_icpc_bolivia_trimmed.png" alt="">
          <div class="team">{esc(u['team_name'])}</div>
          <div class="row"><span>usuario</span><b>{esc(u['username'])}</b></div>
          <div class="row"><span>clave</span><b>{esc(u['password'])}</b></div>
        </div>""" for u in users)
    return f"""<!doctype html><meta charset=utf-8><title>Credenciales {esc(group_id)}</title>
<style>
  body{{font:14px system-ui;margin:2rem;background:#fff}}
  .toolbar{{margin-bottom:1rem}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:.5rem}}
  .card{{position:relative;overflow:hidden;border:1px dashed #999;padding:.7rem .9rem;break-inside:avoid}}
  .logo{{position:absolute;left:50%;top:50%;width:50%;max-height:80%;transform:translate(-50%,-50%);object-fit:contain;opacity:.1;pointer-events:none}}
  .team{{font-weight:700;margin-bottom:.4rem}}
  .team,.row{{position:relative}}
  .row{{display:flex;justify-content:space-between;gap:.5rem;font-size:.9rem}}
  .row span{{color:#666}}
  @media print {{ .toolbar{{display:none}} .card{{border-style:dashed}} }}
</style>
<div class="toolbar"><button onclick="print()">Imprimir / Guardar como PDF</button></div>
<h1>Credenciales - {esc(group_id)} ({len(users)})</h1>
<div class="grid">{cards or "<p>sin usuarios para esta sede</p>"}</div>
""".encode("utf-8")


def main():
    if not ADMIN_TOKEN:
        print("WARNING: CONTROL_ADMIN_TOKEN unset; only per-group admin tokens work", flush=True)
    if not os.path.exists(SIGNING_KEY):
        raise SystemExit(f"signing key missing: {SIGNING_KEY}\nrun ./make-keys.sh first")
    host, _, port = BIND.partition(":")
    httpd = ControlHTTPServer((host, int(port)), Handler)
    httpd.daemon_threads = True
    threading.Thread(target=watchdog, daemon=True).start()
    print(f"contest-control on http://{BIND}  db={DB_PATH}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
