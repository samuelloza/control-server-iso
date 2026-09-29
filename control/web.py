"""Servidor HTTP: helpers de request/response, permisos y rutas."""
import hmac
import http.cookies
import ipaddress
import json
import os
import shutil
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from control import commands, events, files, groups, machines, reports
from control.db import db
from control.groups import group_records
from control.settings import (ADMIN_TOKEN, BRAND_LOGO_SVG, BRAND_WALLPAPER_SVG, INDEX_HTML,
                              MAX_BODY_BYTES)


def client_ip(peer, xff):
    """X-Forwarded-For solo si la conexion viene del proxy (red privada o loopback).
    Se toma la ultima IP: es la que agrega el proxy; las anteriores las pone el cliente."""
    fwd = xff.split(",")[-1].strip()
    return fwd if fwd and ipaddress.ip_address(peer).is_private else peer


class ControlHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], ConnectionResetError):
            super().handle_error(request, client_address)


COOKIE = "cc_token"

# (partes de la ruta, handler). "*" captura ese segmento y se pasa al handler.
GET = [
    ((), lambda h, q: files.serve_file(h, INDEX_HTML, "text/html; charset=utf-8")),
    (("index.html",), lambda h, q: files.serve_file(h, INDEX_HTML, "text/html; charset=utf-8")),
    (("icpc-bolivia-logo.svg",), lambda h, q: files.serve_file(h, BRAND_LOGO_SVG, "image/svg+xml")),
    (("icpc-bolivia-wallpaper.svg",), lambda h, q: files.serve_file(h, BRAND_WALLPAPER_SVG, "image/svg+xml")),
    (("healthz",), lambda h, q: h.json(200, {"ok": True})),
    (("cmd", "*", "*"), lambda h, q, g, m: commands.poll(h, g, m, q)),
    (("admin", "machines"), lambda h, q: machines.admin_machines(h)),
    (("admin", "machines", "*", "*"), lambda h, q, g, m: machines.admin_machine_detail(h, g, m)),
    (("admin", "machines", "*", "*", "screenshot"), lambda h, q, g, m: files.screenshot_get(h, g, m, q)),
    (("admin", "machines", "*", "*", "shots"), lambda h, q, g, m: files.shots(h, g, m, None, q)),
    (("admin", "machines", "*", "*", "shots", "*"), lambda h, q, g, m, ts: files.shots(h, g, m, ts, q)),
    (("admin", "machines", "*", "*", "home"), lambda h, q, g, m: files.home_get(h, g, m, q)),
    (("admin", "homes", "*"), lambda h, q, g: files.homes_zip(h, g, q)),
    (("admin", "commands"), lambda h, q: commands.admin_commands(h, q)),
    (("admin", "alerts"), lambda h, q: machines.admin_alerts(h)),
    (("admin", "teams"), lambda h, q: groups.admin_teams_get(h)),
    (("admin", "allowlist"), lambda h, q: groups.admin_allowlist_get(h, q)),
    (("admin", "homepage"), lambda h, q: groups.admin_cfg_get(h, q, "homepage")),
    (("admin", "logo"), lambda h, q: groups.admin_cfg_get(h, q, "logo_url")),
    (("admin", "phase"), lambda h, q: groups.admin_phase_get(h, q)),
    (("admin", "quota"), lambda h, q: groups.admin_quota(h)),
    (("admin", "events"), lambda h, q: events.sse(h, q)),
    (("admin", "report"), lambda h, q: reports.admin_report(h, q)),
    (("admin", "credentials"), lambda h, q: reports.admin_credentials(h, q)),
]

POST = [
    (("enroll",), lambda h, q: machines.enroll(h)),
    (("cmd", "*", "*", "ack"), lambda h, q, g, m: commands.ack(h, g, m)),
    (("cmd", "*", "*", "status"), lambda h, q, g, m: machines.status(h, g, m)),
    (("cmd", "*", "*", "journal"), lambda h, q, g, m: machines.journal(h, g, m)),
    (("cmd", "*", "*", "events"), lambda h, q, g, m: machines.machine_event(h, g, m)),
    (("cmd", "*", "*", "screenshot"), lambda h, q, g, m: files.screenshot_upload(h, g, m)),
    (("cmd", "*", "*", "home"), lambda h, q, g, m: files.home_upload(h, g, m)),
    (("admin", "session"), lambda h, q: h.admin_session()),
    (("admin", "cmd"), lambda h, q: commands.admin_cmd(h)),
    (("admin", "alerts", "*", "dismiss"), lambda h, q, a: machines.admin_alert_dismiss(h, a)),
    (("admin", "machines", "*", "*", "binding"), lambda h, q, g, m: machines.admin_binding(h, g, m)),
    (("admin", "machines", "*", "*", "location"), lambda h, q, g, m: machines.admin_location(h, g, m)),
    (("admin", "teams"), lambda h, q: groups.admin_teams_put(h)),
    (("admin", "groups", "*"), lambda h, q, g: groups.admin_group_put(h, g)),
    (("admin", "allowlist"), lambda h, q: groups.admin_allowlist_put(h)),
    (("admin", "homepage"), lambda h, q: groups.admin_cfg_put(h, "homepage")),
    (("admin", "logo"), lambda h, q: groups.admin_cfg_put(h, "logo_url")),
    (("admin", "phase"), lambda h, q: groups.admin_phase_put(h)),
]


def match(routes, parts):
    """(handler, segmentos capturados) o (None, None)."""
    for pattern, handler in routes:
        if len(pattern) == len(parts) and all(a in ("*", b) for a, b in zip(pattern, parts)):
            return handler, [b for a, b in zip(pattern, parts) if a == "*"]
    return None, None


class Handler(BaseHTTPRequestHandler):
    server_version = "contest-control/2"
    protocol_version = "HTTP/1.1"

    def send(self, code, body=b"", ctype="application/json", extra=None):
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

    def send_file(self, fh, ctype, extra=None):
        """Manda un archivo abierto por partes, sin cargarlo entero en memoria."""
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(os.fstat(fh.fileno()).st_size))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            fh.seek(0)
            shutil.copyfileobj(fh, self.wfile)

    def json(self, code, obj):
        self.send(code, json.dumps(obj), "application/json")

    def error(self, code, message):
        self.json(code, {"error": message})

    def body_length(self, limit):
        """Content-Length valido y <= limit, o None (y se cierra la conexion: el body queda sin leer)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if 0 < length <= limit:
            return length
        self.close_connection = True
        return None

    def read_json(self):
        length = self.body_length(MAX_BODY_BYTES)
        if length is None:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def read_text(self):
        length = self.body_length(MAX_BODY_BYTES)
        if length is None:
            return ""
        return self.rfile.read(length).decode("utf-8", "replace")

    def bearer(self):
        h = self.headers.get("Authorization", "")
        return h[7:] if h.startswith("Bearer ") else ""

    def client_ip(self):
        return client_ip(self.client_address[0], self.headers.get("X-Forwarded-For", ""))

    def admin_token(self):
        """Bearer del header; en GET tambien la cookie (imagenes, SSE y descargas no mandan headers)."""
        tok = self.bearer()
        if not tok and self.command in ("GET", "HEAD"):
            try:
                c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            except http.cookies.CookieError:
                return ""
            tok = c[COOKIE].value if COOKIE in c else ""
        return tok

    def admin_scope(self):
        """(ok, scope): scope None = superadmin, si no el grupo del token."""
        tok = self.admin_token()
        if ADMIN_TOKEN and hmac.compare_digest(tok, ADMIN_TOKEN):
            return True, None
        for gid, rec in group_records().items():
            if rec["admin_token"] and hmac.compare_digest(tok, rec["admin_token"]):
                return True, gid
        if not ADMIN_TOKEN:
            self.error(503, "CONTROL_ADMIN_TOKEN is not set")
        else:
            self.error(401, "bad admin token")
        return False, None

    def admin_session(self):
        """Pasa el token del header a una cookie HttpOnly, asi nunca va en la URL."""
        ok, scope = self.admin_scope()
        if not ok:
            return
        c = http.cookies.SimpleCookie()
        c[COOKIE] = self.bearer()
        c[COOKIE].update({"path": "/admin", "httponly": True, "samesite": "Strict", "max-age": 43200})
        if self.headers.get("X-Forwarded-Proto") == "https":
            c[COOKIE]["secure"] = True
        self.send(200, json.dumps({"ok": True, "scope": scope}), "application/json",
                  {"Set-Cookie": c[COOKIE].OutputString()})

    def scope_ok(self, scope, group_id):
        """404 y no 403, para no revelar que sedes existen."""
        if scope is not None and scope != group_id:
            self.error(404, "not found")
            return False
        return True

    def auth_machine(self, group_id, machine_id):
        row = db().execute("SELECT * FROM machines WHERE machine_id=?", (machine_id,)).fetchone()
        if not row or row["group_id"] != group_id:
            return None
        if not hmac.compare_digest(self.bearer(), row["bearer"]):
            return None
        return row

    def dispatch(self, routes):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        handler, args = match(routes, parts)
        if handler is None:
            return self.error(404, "not found")
        return handler(self, parse_qs(parsed.query), *args)

    def do_GET(self):
        self.dispatch(GET)

    def do_POST(self):
        self.dispatch(POST)

    def do_PUT(self):
        self.dispatch(POST)
