#!/usr/bin/env python3
"""Login del concurso. Valida contra users.json y devuelve equipo, sede y enrollToken."""
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from control.web import client_ip

HERE = os.path.dirname(os.path.abspath(__file__))
BIND = os.environ.get("AUTH_BIND", "0.0.0.0:6666")
USERS_FILE = os.environ.get("AUTH_USERS", os.path.join(HERE, "users.json"))
GROUPS_FILE = os.path.join(HERE, "groups.json")
LOG_FILE = os.path.join(HERE, "data", "auth-events.txt")
DB_FILE = os.environ.get("AUTH_DB", os.path.join(HERE, "data", "control.db"))
DEFAULT_HOMEPAGE = os.environ.get(
    "AUTH_DEFAULT_HOMEPAGE", "file:///usr/share/doc/contest/index.html")

TEAM_ID_RE = re.compile(r"[^A-Za-z0-9._-]")

# Limite de intentos fallidos por (IP, usuario). No solo por IP: toda una sede
# sale con la misma IP publica y un bloqueo por IP la dejaria sin login.
MAX_FAILS = 10
FAIL_WINDOW = 300   # segundos
_fails = {}
_fails_lock = threading.Lock()


def blocked(key):
    now = time.monotonic()
    with _fails_lock:
        recent = [t for t in _fails.get(key, ()) if now - t < FAIL_WINDOW]
        if recent:
            _fails[key] = recent
        else:
            _fails.pop(key, None)
        return len(recent) >= MAX_FAILS


def add_fail(key):
    now = time.monotonic()
    with _fails_lock:
        if len(_fails) > 10000:   # usuarios inventados: limpiar los viejos
            for k in [k for k, ts in _fails.items() if now - ts[-1] >= FAIL_WINDOW]:
                del _fails[k]
        _fails.setdefault(key, []).append(now)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else default
    except (FileNotFoundError, ValueError):
        return default


def regions():
    """{region_id: {"name": str, "enroll_token": str}} desde groups.json (sin lobby)."""
    out = {}
    for gid, rec in load_json(GROUPS_FILE, {}).items():
        if gid.startswith("_") or gid == "lobby":
            continue
        if isinstance(rec, dict):
            out[gid] = {"name": str(rec.get("label", gid)),
                        "enroll_token": str(rec.get("enroll_token", ""))}
    return out


def sanitize_team(v):
    return TEAM_ID_RE.sub("-", str(v or ""))[:64] or "equipo"


def cfg_for(col, region_id, default):
    """homepage o logo_url de la sede, con fallback a '__global__' y luego a default."""
    if not os.path.exists(DB_FILE):
        return default
    try:
        with sqlite3.connect(DB_FILE) as conn:
            row = conn.execute(
                f"SELECT {col} FROM group_config WHERE group_id IN (?, '__global__') "
                f"AND {col} <> '' ORDER BY group_id='__global__' LIMIT 1",
                (region_id,)).fetchone()
        return row[0] if row and row[0] else default
    except sqlite3.Error:
        return default


def homepage_for(region_id):
    return cfg_for("homepage", region_id, DEFAULT_HOMEPAGE)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _log(self, method, body=""):
        line = (f"[{now_iso()}] ip={self.client_address[0]} {method} {self.path} "
                f"ua={self.headers.get('User-Agent', '')}")
        print(line, flush=True)
        if method == "POST":
            try:
                os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
                with open(LOG_FILE, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n" + body + "\n\n")
            except OSError:
                pass

    def do_GET(self):
        self._log("GET")
        if self.path.rstrip("/") in ("", "/healthz"):
            n = sum(1 for k in load_json(USERS_FILE, {}) if not k.startswith("_"))
            return self._json(200, {"ok": True, "service": "auth", "users": n})
        return self._json(404, {"ok": False, "message": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        self._log("POST", raw)
        try:
            data = json.loads(raw or "{}")
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return self._json(400, {"ok": False, "message": "JSON inválido en la petición"})

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        key = (client_ip(self.client_address[0], self.headers.get("X-Forwarded-For", "")), username)
        if blocked(key):
            return self._json(200, {"ok": False,
                                    "message": "Demasiados intentos. Espera unos minutos."})
        users = load_json(USERS_FILE, {})
        rec = users.get(username) if isinstance(users.get(username), dict) else None
        if not rec or not hmac.compare_digest(password, str(rec.get("password", "\0"))):
            add_fail(key)
            return self._json(200, {"ok": False, "message": "Usuario o contraseña incorrectos"})

        region_id = str(rec.get("region", "")).strip()
        reg = regions().get(region_id, {})
        resp = {
            "ok": True,
            "userId": username,
            "displayName": str(rec.get("display") or rec.get("team_name") or username),
            "homepage": homepage_for(region_id),
            "logoUrl": cfg_for("logo_url", region_id, ""),
            "team": {
                "id": sanitize_team(rec.get("team_id") or username),
                "name": str(rec.get("team_name") or rec.get("display") or username),
            },
        }
        if region_id:
            resp["region"] = {
                "id": region_id,
                "name": str(rec.get("region_name") or reg.get("name") or region_id),
                "enrollToken": reg.get("enroll_token", ""),
            }
            if not reg.get("enroll_token"):
                print(f"  AVISO: la sede '{region_id}' del usuario '{username}' no esta en "
                      f"{GROUPS_FILE} (enrollToken vacio)", flush=True)
        return self._json(200, resp)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    host, _, port = BIND.rpartition(":")
    srv = ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler)
    print(f"auth en http://{BIND}  users={USERS_FILE}  groups={GROUPS_FILE}", flush=True)
    srv.serve_forever()
