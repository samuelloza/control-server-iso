"""Maquinas: registro, telemetria, alertas y asignacion de equipo."""
import hmac
import json
import os
import secrets
import time
from datetime import timedelta

from control.commands import enqueue_command
from control.db import DB_LOCK, db, iso, now, since_seconds, stored_phase
from control.events import publish
from control.files import home_meta_of, screenshot_path
from control.groups import group_records, stored_allowlist
from control.settings import (
    DISK_FULL_PCT,
    JOURNAL_BYTES_PER_MACHINE,
    MACHINE_ID_OK,
    MACHINE_ID_RE,
    OFFLINE_PHASES,
    OFFLINE_SECS,
    SAMPLES_PER_MACHINE,
    STATUS_EVERY)


def raise_alert(conn, group_id, machine_id, kind, detail=None):
    """Devuelve (id, es_nueva); no duplica alertas abiertas."""
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
    """Mismo equipo con machine_id nuevo y el viejo callado = la PC se reinicio sola."""
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
    """Alerta 'offline' para PCs con equipo que dejaron de reportar (ultima hora)."""
    with DB_LOCK:
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


def auto_bind(conn, group_id, machine_id, login):
    """Liga la maquina al equipo que inicio sesion. Devuelve el binding nuevo o None."""
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
    e = conn.execute("SELECT * FROM teams WHERE group_id=? AND user_id=?", (group_id, uid)).fetchone()
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


def enroll(h):
    body = h.read_json()
    if not isinstance(body, dict):
        return h.error(400, "expected a JSON object")
    machine_id = str(body.get("machine_id", ""))
    group_id = str(body.get("group_id", ""))
    token = str(body.get("enroll_token", ""))
    hostname = str(body.get("hostname", ""))[:128] or None
    if not MACHINE_ID_OK(machine_id):
        return h.error(400, f"machine_id must match {MACHINE_ID_RE}")
    rec = group_records().get(group_id)
    if not rec or not rec["enroll_token"] or not hmac.compare_digest(token, rec["enroll_token"]):
        return h.error(401, "unknown group or bad enroll token")
    bearer = secrets.token_urlsafe(32)
    with DB_LOCK:
        conn = db()
        first = conn.execute("SELECT 1 FROM machines WHERE machine_id=?", (machine_id,)).fetchone() is None
        conn.execute(
            """INSERT INTO machines (machine_id, group_id, bearer, hostname, ip, enrolled_at, last_seen)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(machine_id) DO UPDATE SET
                 group_id=excluded.group_id, bearer=excluded.bearer,
                 hostname=excluded.hostname, ip=excluded.ip, last_seen=excluded.last_seen""",
            (machine_id, group_id, bearer, hostname, h.client_ip(), iso(now()), iso(now())),
        )
        # /etc se resetea en cada arranque: reenviar la allowlist del grupo
        hosts, _ = stored_allowlist(conn, group_id)
        if hosts:
            try:
                enqueue_command(conn, group_id, machine_id, "set-allowlist", {"hosts": hosts})
            except (ValueError, RuntimeError):
                pass
    if first:
        publish("machine.first_seen", {"machine_id": machine_id, "group_id": group_id}, group_id)
    return h.json(200, {"bearer": bearer, "machine_id": machine_id, "group_id": group_id})


def status(h, group_id, machine_id):
    body = h.read_json()
    if not h.auth_machine(group_id, machine_id):
        return h.error(401, "enroll first / bad bearer")
    if not isinstance(body, dict):
        return h.error(400, "expected a JSON object")
    t = int(time.time())
    num = lambda k: (float(body[k]) if isinstance(body.get(k), (int, float)) else None)
    bound = None
    with DB_LOCK:
        conn = db()
        # Tiempo por editor abierto (no en foco), max 60s por reporte.
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
        # Sesiones por editor: se cierran cuando deja de aparecer.
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
    return h.json(200, {"ok": True})


def journal(h, group_id, machine_id):
    if not h.auth_machine(group_id, machine_id):
        return h.error(401, "enroll first / bad bearer")
    text = h.read_text()
    if not text.strip():
        return h.json(200, {"ok": True})
    with DB_LOCK:
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
    return h.json(200, {"ok": True})


def machine_event(h, group_id, machine_id):
    body = h.read_json()
    if not h.auth_machine(group_id, machine_id):
        return h.error(401, "enroll first / bad bearer")
    if not isinstance(body, dict) or not body.get("kind"):
        return h.error(400, "expected {kind, detail?}")
    kind = str(body["kind"])[:64]
    detail = str(body.get("detail", ""))[:256] or None
    with DB_LOCK:
        aid, new = raise_alert(db(), group_id, machine_id, kind, detail)
    if not new:
        return h.json(200, {"ok": True, "alert_id": aid, "duplicate": True})
    return h.json(200, {"ok": True, "alert_id": aid})


def machine_rows(scope):
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
            "home_age": home_meta_of(r["group_id"], (json.loads(r["binding_json"] or "{}").get("user_id"))
                                     or r["machine_id"])[0],
        })
    return out


def admin_machines(h):
    ok, scope = h.admin_scope()
    if not ok:
        return
    phases = {r["group_id"]: r["phase"] for r in db().execute(
        "SELECT group_id, phase FROM group_config")}
    return h.json(200, {"machines": machine_rows(scope), "now": iso(now()),
                            "scope": scope, "phases": phases})


def admin_machine_detail(h, group_id, machine_id):
    ok, scope = h.admin_scope()
    if not ok or not h.scope_ok(scope, group_id):
        return
    conn = db()
    m = conn.execute("SELECT * FROM machines WHERE machine_id=? AND group_id=?",
                     (machine_id, group_id)).fetchone()
    if not m:
        return h.error(404, "not found")
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
    home_age, home_size, home_team = home_meta_of(group_id, owner)
    return h.json(200, {
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


def admin_alerts(h):
    ok, scope = h.admin_scope()
    if not ok:
        return
    where = "WHERE dismissed_at IS NULL" + (" AND group_id=?" if scope else "")
    params = [scope] if scope else []
    rows = db().execute(
        f"SELECT * FROM alerts {where} ORDER BY id DESC", params).fetchall()
    return h.json(200, {"alerts": [dict(r) for r in rows]})


def admin_alert_dismiss(h, alert_id):
    ok, scope = h.admin_scope()
    if not ok:
        return
    who = scope or "admin"
    with DB_LOCK:
        conn = db()
        a = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not a:
            return h.error(404, "not found")
        if not h.scope_ok(scope, a["group_id"]):
            return
        conn.execute("UPDATE alerts SET dismissed_at=?, dismissed_by=? WHERE id=? AND dismissed_at IS NULL",
                     (iso(now()), who, alert_id))
    publish("alert.dismissed", {"id": int(alert_id), "by": who}, a["group_id"])
    return h.json(200, {"ok": True})


def admin_binding(h, group_id, machine_id):
    ok, scope = h.admin_scope()
    if not ok or not h.scope_ok(scope, group_id):
        return
    body = h.read_json() or {}
    with DB_LOCK:
        conn = db()
        m = conn.execute("SELECT 1 FROM machines WHERE machine_id=? AND group_id=?",
                         (machine_id, group_id)).fetchone()
        if not m:
            return h.error(404, "not found")
        uid = str(body.get("user_id", "")) if isinstance(body, dict) else ""
        if not uid:
            conn.execute("UPDATE machines SET binding_json=NULL WHERE machine_id=?", (machine_id,))
            publish("machine.unbound", {"machine_id": machine_id}, group_id)
            return h.json(200, {"ok": True})
        e = conn.execute("SELECT * FROM teams WHERE group_id=? AND user_id=?", (group_id, uid)).fetchone()
        if not e:
            return h.error(404, "unknown user_id in teams")
        binding = {"user_id": e["user_id"], "name": e["name"], "org": e["org"],
                   "seat": e["seat"], "country": e["country"]}
        conn.execute("UPDATE machines SET binding_json=? WHERE machine_id=?",
                     (json.dumps(binding), machine_id))
    publish("machine.bound", {"machine_id": machine_id, "user_id": uid}, group_id)
    return h.json(200, {"ok": True, "binding": binding})


def admin_location(h, group_id, machine_id):
    """Texto libre, ej. 'Sala 3, PC 12'."""
    ok, scope = h.admin_scope()
    if not ok or not h.scope_ok(scope, group_id):
        return
    body = h.read_json() or {}
    loc = str(body.get("location", "")).strip()[:200] if isinstance(body, dict) else ""
    with DB_LOCK:
        conn = db()
        m = conn.execute("SELECT 1 FROM machines WHERE machine_id=? AND group_id=?",
                         (machine_id, group_id)).fetchone()
        if not m:
            return h.error(404, "not found")
        conn.execute("UPDATE machines SET location=? WHERE machine_id=?",
                     (loc or None, machine_id))
    publish("machine.located", {"machine_id": machine_id, "location": loc}, group_id)
    return h.json(200, {"ok": True, "location": loc})
