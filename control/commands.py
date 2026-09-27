"""Comandos firmados: firma, cola, entrega y ack."""
import base64
import json
import secrets
import subprocess
import tempfile
import time
from datetime import timedelta

from control.db import CMD_COND, DB_LOCK, db, iso, now, stored_phase
from control.events import publish
from control.settings import (
    ACTIONS,
    COMMAND_TTL_SECONDS,
    FROZEN_ALLOWED,
    LONGPOLL_MAX,
    MAX_PAYLOAD_BYTES,
    SIGNING_KEY,
    SUPERADMIN_ONLY)


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


def _targets(conn, group_id, machine_id):
    if machine_id == "*":
        return [r["machine_id"] for r in conn.execute(
            "SELECT machine_id FROM machines WHERE group_id=?", (group_id,))]
    return [machine_id]


def apply_state(conn, group_id, machine_id, action):
    """Efecto en el servidor de lock/unlock/logout, ademas del comando."""
    mids = _targets(conn, group_id, machine_id)
    if not mids:
        return
    qmarks = ",".join("?" * len(mids))
    # lock_state va ya, asi una PC que reinicia se vuelve a bloquear. frozen se pone en el ack.
    if action in ("lock", "precontest"):
        conn.execute(f"UPDATE machines SET lock_state=1 WHERE machine_id IN ({qmarks})", mids)
        for m in mids:
            publish("machine.locked", {"machine_id": m}, group_id)
    elif action == "unlock":
        conn.execute(f"UPDATE machines SET lock_state=0 WHERE machine_id IN ({qmarks})", mids)
        for m in mids:
            publish("machine.unlocked", {"machine_id": m}, group_id)
    elif action == "logout":
        # se oculta hasta el proximo login
        conn.execute(f"UPDATE machines SET binding_json=NULL, hidden_at=? WHERE machine_id IN ({qmarks})",
                     [iso(now())] + mids)
        for m in mids:
            publish("machine.logged_out", {"machine_id": m}, group_id)


def enqueue_command(conn, group_id, machine_id, action, args, ttl=None):
    """Firma y guarda un comando. Llamar con DB_LOCK tomado."""
    issued = now()
    expires = issued + timedelta(seconds=max(60, ttl or COMMAND_TTL_SECONDS))
    payload_obj = {
        "action": action, "args": args, "expires_at": iso(expires),
        "group_id": group_id, "issued_at": iso(issued), "machine_id": machine_id,
        "nonce": new_nonce(),
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


def poll(h, group_id, machine_id, query):
    row = h.auth_machine(group_id, machine_id)
    if not row:
        return h.error(401, "enroll first / bad bearer")
    try:
        wait = max(0, min(LONGPOLL_MAX, int((query.get("wait") or ["0"])[0])))
    except ValueError:
        wait = 0
    deadline = time.monotonic() + wait
    while True:
        with DB_LOCK:
            conn = db()
            conn.execute("UPDATE machines SET last_seen=?, ip=? WHERE machine_id=?",
                         (iso(now()), h.client_ip(), machine_id))
            fresh = conn.execute("SELECT lock_state, frozen, binding_json FROM machines WHERE machine_id=?",
                                 (machine_id,)).fetchone()
            frozen = fresh["frozen"]
            meta = {"lock_state": fresh["lock_state"], "frozen": frozen,
                    "phase": stored_phase(conn, group_id),
                    "binding": json.loads(fresh["binding_json"]) if fresh["binding_json"] else None}
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
        if cmd:
            return h.json(200, {
                "nonce": cmd["nonce"], "action": cmd["action"],
                "payload_b64": base64.b64encode(cmd["payload"]).decode("ascii"),
                "signature": cmd["signature"], "command": json.loads(cmd["payload"]),
                "meta": meta,
            })
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return h.send(200, json.dumps({"meta": meta}), "application/json") \
                if wait else h.send(204, b"")
        with CMD_COND:
            CMD_COND.wait(timeout=min(remaining, 5))


def ack(h, group_id, machine_id):
    body = h.read_json()
    if not isinstance(body, dict) or "nonce" not in body:
        return h.error(400, "expected {nonce, status?, detail?}")
    with DB_LOCK:
        conn = db()
        if not h.auth_machine(group_id, machine_id):
            return h.error(401, "enroll first / bad bearer")
        nonce = str(body["nonce"])
        status = str(body.get("status", "ok"))[:32]
        detail = str(body.get("detail", ""))[:512] or None
        cmd = conn.execute("SELECT * FROM commands WHERE nonce=?", (nonce,)).fetchone()
        if not cmd or cmd["group_id"] != group_id:
            return h.error(404, "unknown nonce")
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
    return h.json(200, {"ok": True})


def admin_cmd(h):
    ok, scope = h.admin_scope()
    if not ok:
        return
    body = h.read_json()
    if not isinstance(body, dict):
        return h.error(400, "expected a JSON object")
    target = body.get("target") or {}
    action = str(body.get("action", ""))
    args = body.get("args") or {}
    try:
        ttl = int(body.get("ttl_seconds") or COMMAND_TTL_SECONDS)
    except (TypeError, ValueError):
        return h.error(400, "ttl_seconds must be a number")
    if action not in ACTIONS:
        return h.error(400, f"unknown action; allowed: {sorted(ACTIONS)}")
    if action in SUPERADMIN_ONLY and scope is not None:
        return h.error(403, f"'{action}' solo con el token superadmin")
    if not isinstance(args, dict):
        return h.error(400, "args must be an object")
    for key in ACTIONS[action]:
        if not args.get(key):
            return h.error(400, f"action '{action}' requires args.{key}")
    if action == "set-allowlist" and not isinstance(args.get("hosts"), list):
        return h.error(400, "args.hosts must be a list")

    if target.get("all"):
        # Todas las sedes: solo capturas, nada peligroso de un clic.
        if scope is not None or action != "screenshot":
            return h.error(403, "target 'all' solo con el token superadmin y solo para 'screenshot'")
        with DB_LOCK:
            conn = db()
            groups = [r["group_id"] for r in conn.execute("SELECT DISTINCT group_id FROM machines")]
            try:
                nonces = [enqueue_command(conn, g, "*", action, args, ttl)["nonce"] for g in groups]
            except (ValueError, RuntimeError) as exc:
                return h.error(500, str(exc))
        with CMD_COND:
            CMD_COND.notify_all()
        for g, n in zip(groups, nonces):
            publish("command.sent", {"nonce": n, "action": action, "machine_id": "*"}, g)
        return h.json(200, {"groups": groups, "nonces": nonces})

    machine_id = str(target.get("machine_id", "")) or "*"
    group_id = str(target.get("group_id", ""))
    with DB_LOCK:
        conn = db()
        if machine_id != "*":
            row = conn.execute("SELECT group_id FROM machines WHERE machine_id=?", (machine_id,)).fetchone()
            if not row:
                return h.error(404, "unknown machine_id")
            group_id = group_id or row["group_id"]
            if group_id != row["group_id"]:
                return h.error(400, "machine_id is not in that group")
        if not group_id:
            return h.error(400, "target needs group_id and/or a known machine_id")
        if not h.scope_ok(scope, group_id):
            return
        try:
            payload_obj = enqueue_command(conn, group_id, machine_id, action, args, ttl)
        except ValueError as exc:
            return h.error(400, str(exc))
        except RuntimeError as exc:
            return h.error(500, str(exc))
        apply_state(conn, group_id, machine_id, action)
    with CMD_COND:
        CMD_COND.notify_all()
    publish("command.sent", {"nonce": payload_obj["nonce"], "action": action,
                             "machine_id": machine_id}, group_id)
    return h.json(200, {"nonce": payload_obj["nonce"], "group_id": group_id,
                            "machine_id": machine_id, "expires_at": payload_obj["expires_at"]})


def admin_commands(h, query):
    ok, scope = h.admin_scope()
    if not ok:
        return
    try:
        limit = min(int((query.get("limit") or ["50"])[0]), 500)
    except ValueError:
        return h.error(400, "limit must be a number")
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
        # ocultar la password de unlock-root al coordinador
        for c in cmds:
            if c["action"] == "unlock-root":
                c["args_json"] = None
    return h.json(200, {"commands": cmds})
