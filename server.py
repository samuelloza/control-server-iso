#!/usr/bin/env python3
"""Servidor de control del concurso.

CONTROL_ADMIN_TOKEN=... python3 server.py
"""
import os
import threading

from control.groups import group_records
from control.machines import watchdog
from control.settings import ADMIN_TOKEN, BIND, DB_PATH, SIGNING_KEY
from control.web import ControlHTTPServer, Handler


MIN_TOKEN_LEN = 32


def weak_tokens():
    """Tokens demasiado cortos: con 32+ caracteres aleatorios no se pueden adivinar."""
    out = ["CONTROL_ADMIN_TOKEN"] if ADMIN_TOKEN and len(ADMIN_TOKEN) < MIN_TOKEN_LEN else []
    for gid, rec in group_records().items():
        for k in ("enroll_token", "admin_token"):
            if rec[k] and len(rec[k]) < MIN_TOKEN_LEN:
                out.append(f"{gid}.{k}")
    return out


def main():
    weak = weak_tokens()
    if weak:
        raise SystemExit(f"tokens con menos de {MIN_TOKEN_LEN} caracteres: {', '.join(weak)}\n"
                         "generar con: openssl rand -hex 24")
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
