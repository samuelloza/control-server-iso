"""Archivos: capturas de pantalla y codigo recogido de cada equipo."""
import json
import os
import re
import tempfile
import time
import zipfile

from control.db import DB_LOCK, db, iso, now
from control.events import publish
from control.settings import (
    HOME_DIR,
    HOME_KEEP,
    HOME_MAX_BYTES,
    SCREENSHOT_DIR,
    SCREENSHOT_MAX_BYTES,
    SHOT_KEEP)


def screenshot_path(machine_id):
    return os.path.join(SCREENSHOT_DIR, machine_id + ".png")


def safe_seg(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s or "_")


def shot_owner(conn, machine_id):
    """user_id del equipo, o machine_id si no hay login."""
    r = conn.execute("SELECT binding_json FROM machines WHERE machine_id=?", (machine_id,)).fetchone()
    b = json.loads(r["binding_json"]) if r and r["binding_json"] else {}
    return b.get("user_id") or machine_id


def shot_hist_dir(group_id, owner):
    return os.path.join(SCREENSHOT_DIR, "hist", safe_seg(group_id), safe_seg(owner))


def shot_hist_list(group_id, owner):
    """Timestamps en ms, mas nuevos primero."""
    try:
        names = [n[:-4] for n in os.listdir(shot_hist_dir(group_id, owner)) if n.endswith(".png")]
    except OSError:
        return []
    return sorted((n for n in names if n.isdigit()), key=int, reverse=True)


def home_dir(group_id, owner):
    """Carpeta con los <ms>.tar.gz del equipo."""
    return os.path.join(HOME_DIR, safe_seg(group_id), safe_seg(owner))


def home_stamps(group_id, owner):
    """Timestamps en ms, mas nuevos primero."""
    try:
        names = [n[:-7] for n in os.listdir(home_dir(group_id, owner)) if n.endswith(".tar.gz")]
    except OSError:
        return []
    return sorted((n for n in names if n.isdigit()), key=int, reverse=True)


def home_meta_of(group_id, owner):
    """(edad_s, bytes, team_id) de la ultima copia."""
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


def serve_file(h, path, ctype):
    try:
        with open(path, "rb") as fh:
            h.send(200, fh.read(), ctype)
    except FileNotFoundError:
        h.error(404, os.path.basename(path) + " missing")


def screenshot_upload(h, group_id, machine_id):
    if not h.auth_machine(group_id, machine_id):
        return h.error(401, "enroll first / bad bearer")
    length = h.body_length(SCREENSHOT_MAX_BYTES)
    if length is None:
        return h.error(413, "captura vacía o demasiado grande")
    data = h.rfile.read(length)
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return h.error(400, "se esperaba PNG")
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    dst = screenshot_path(machine_id)
    tmp = dst + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, dst)
    with DB_LOCK:
        hist = shot_hist_dir(group_id, shot_owner(db(), machine_id))
    os.makedirs(hist, exist_ok=True)
    with open(os.path.join(hist, "%d.png" % (time.time() * 1000)), "wb") as fh:
        fh.write(data)
    for old in sorted((n for n in os.listdir(hist) if n.endswith(".png")), key=lambda n: int(n[:-4]))[:-SHOT_KEEP]:
        os.remove(os.path.join(hist, old))
    publish("machine.screenshot", {"machine_id": machine_id, "at": iso(now())}, group_id)
    return h.json(200, {"ok": True, "bytes": len(data)})


def screenshot_get(h, group_id, machine_id, query=None):
    ok, scope = h.admin_scope()
    if not ok or not h.scope_ok(scope, group_id):
        return
    try:
        with open(screenshot_path(machine_id), "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        return h.error(404, "sin captura")
    return h.send(200, data, "image/png", {"Cache-Control": "no-store"})


def shots(h, group_id, machine_id, ts, query):
    """Sin ts lista las capturas; con ts devuelve esa."""
    ok, scope = h.admin_scope()
    if not ok or not h.scope_ok(scope, group_id):
        return
    with DB_LOCK:
        owner = shot_owner(db(), machine_id)
    if ts is None:
        return h.json(200, {"shots": shot_hist_list(group_id, owner)})
    if not ts.isdigit():
        return h.error(400, "ts invalido")
    try:
        with open(os.path.join(shot_hist_dir(group_id, owner), ts + ".png"), "rb") as fh:
            return h.send(200, fh.read(), "image/png", {"Cache-Control": "max-age=3600"})
    except FileNotFoundError:
        return h.error(404, "sin captura")


def home_upload(h, group_id, machine_id):
    if not h.auth_machine(group_id, machine_id):
        return h.error(401, "enroll first / bad bearer")
    length = h.body_length(HOME_MAX_BYTES)
    if length is None:
        return h.error(413, "home vacío o demasiado grande")
    head = h.rfile.read(2)
    if head != b"\x1f\x8b":
        h.close_connection = True
        return h.error(400, "se esperaba gzip")
    with DB_LOCK:
        owner = shot_owner(db(), machine_id)
    hdir = home_dir(group_id, owner)
    os.makedirs(hdir, exist_ok=True)
    ts = "%d" % (time.time() * 1000)
    tmp = os.path.join(hdir, ts + ".part")
    left = length - len(head)
    with open(tmp, "wb") as fh:
        fh.write(head)
        while left:
            chunk = h.rfile.read(min(left, 1 << 20))
            if not chunk:
                break
            fh.write(chunk)
            left -= len(chunk)
    if left:   # el cliente corto la conexion a medias
        os.remove(tmp)
        h.close_connection = True
        return h.error(400, "subida incompleta")
    os.replace(tmp, os.path.join(hdir, ts + ".tar.gz"))   # copia nueva: no pisa la anterior
    for old in home_stamps(group_id, owner)[HOME_KEEP:]:
        os.remove(os.path.join(hdir, old + ".tar.gz"))
    team = (h.headers.get("X-Team-Id") or "").strip()[:64]
    if team:
        with open(os.path.join(hdir, "team"), "w") as fh:
            fh.write(team)
    publish("machine.home", {"machine_id": machine_id, "bytes": length,
                             "at": iso(now())}, group_id)
    return h.json(200, {"ok": True, "bytes": length})


def home_get(h, group_id, machine_id, query=None):
    ok, scope = h.admin_scope()
    if not ok or not h.scope_ok(scope, group_id):
        return
    with DB_LOCK:
        owner = shot_owner(db(), machine_id)
    stamps = home_stamps(group_id, owner)
    if not stamps:
        return h.error(404, "sin código recogido")
    _, _, team = home_meta_of(group_id, owner)
    name = ((team + "__") if team else "") + owner + ".tar.gz"
    with open(os.path.join(home_dir(group_id, owner), stamps[0] + ".tar.gz"), "rb") as fh:
        return h.send_file(fh, "application/gzip", {
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="%s"' % name.replace('"', ""),
        })


def homes_zip(h, group_id, query=None):
    ok, scope = h.admin_scope()
    if not ok or not h.scope_ok(scope, group_id):
        return
    gdir = os.path.join(HOME_DIR, safe_seg(group_id))
    owners = sorted(o for o in os.listdir(gdir) if os.path.isdir(os.path.join(gdir, o))) \
        if os.path.isdir(gdir) else []
    files = []
    for owner in owners:   # la copia mas nueva de cada equipo
        stamps = home_stamps(group_id, owner)
        if stamps:
            team = home_meta_of(group_id, owner)[2]
            files.append((os.path.join(gdir, owner, stamps[0] + ".tar.gz"),
                          ((team + "__") if team else "") + owner + ".tar.gz"))
    if not files:
        return h.error(404, "sin código recogido en el grupo")
    # el zip se arma en disco (junto a los homes), no en memoria
    with tempfile.TemporaryFile(dir=HOME_DIR) as buf:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            for path, name in files:
                z.write(path, name)
        return h.send_file(buf, "application/zip", {
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="%s-codigo.zip"' % safe_seg(group_id),
        })
