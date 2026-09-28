"""Configuracion por sede: tokens, usuarios, fase, allowlist, homepage, logo y equipos."""
import json
import os
import threading
from urllib.parse import urlparse

from control.commands import enqueue_command
from control.db import CMD_COND, DB_LOCK, db, iso, now, since_seconds, stored_phase
from control.events import publish
from control.settings import DEFAULT_HOMEPAGE, GROUPS_FILE, MACHINE_ID_OK, PHASES, STATUS_EVERY, USERS_FILE


GROUPS_LOCK = threading.Lock()


def group_records():
    """{group_id: {"enroll_token": str, "admin_token": str|None, "label": str}}."""
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
        if isinstance(rec, dict):
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


def admin_group_put(h, group_id):
    """Registra un grupo; solo superadmin. El servidor conserva y escribe su propio archivo."""
    ok, scope = h.admin_scope()
    if not ok:
        return
    if scope is not None:
        return h.error(403, "groups: solo con el token superadmin")
    if not MACHINE_ID_OK(group_id) or group_id.startswith("_"):
        return h.error(400, "group_id inválido")
    body = h.read_json()
    if not isinstance(body, dict):
        return h.error(400, "expected {enroll_token, admin_token?, label?}")
    enroll_token = body.get("enroll_token")
    admin_token = body.get("admin_token")
    if not isinstance(enroll_token, str) or (admin_token is not None and not isinstance(admin_token, str)):
        return h.error(400, "tokens must be strings")
    if group_id != "lobby" and not admin_token:
        return h.error(400, "admin_token is required")
    if len(enroll_token) < 32 or (admin_token is not None and len(admin_token) < 32):
        return h.error(400, "tokens must have at least 32 characters")
    label = body.get("label", group_id)
    if not isinstance(label, str):
        return h.error(400, "label must be a string")
    label = label.strip()[:128] or group_id

    with GROUPS_LOCK:
        try:
            with open(GROUPS_FILE, encoding="utf-8") as fh:
                groups = json.load(fh)
        except FileNotFoundError:
            groups = {}
        except (OSError, ValueError) as exc:
            return h.error(500, f"cannot read groups file: {exc}")
        if not isinstance(groups, dict):
            return h.error(500, "groups file must be a JSON object")
        groups[group_id] = {
            "enroll_token": enroll_token,
            "admin_token": admin_token,
            "label": label,
        }
        os.makedirs(os.path.dirname(os.path.abspath(GROUPS_FILE)), exist_ok=True)
        temp = GROUPS_FILE + ".tmp"
        try:
            with open(temp, "w", encoding="utf-8") as fh:
                json.dump(groups, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            os.replace(temp, GROUPS_FILE)
        except OSError as exc:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass
            return h.error(500, f"cannot write groups file: {exc}")
    return h.json(200, {"ok": True, "group_id": group_id, "label": label})


def stored_allowlist(conn, group_id):
    row = conn.execute("SELECT allowlist_json, updated_at FROM group_config WHERE group_id=?",
                       (group_id,)).fetchone()
    return (json.loads(row["allowlist_json"]) if row else [],
            row["updated_at"] if row else None)


def stored_cfg(conn, group_id, col):
    """(propio, efectivo, updated_at); efectivo cae a '__global__'."""
    ts = "homepage_updated_at" if col == "homepage" else "logo_updated_at"
    row = conn.execute(f"SELECT {col}, {ts} FROM group_config WHERE group_id=?",
                       (group_id,)).fetchone()
    fallback = conn.execute(
        f"SELECT {col} FROM group_config WHERE group_id='__global__'").fetchone()
    own = (row[col] or "") if row else ""
    return own, own or ((fallback[col] or "") if fallback else ""), row[ts] if row else None


def valid_homepage(url):
    parsed = urlparse(url)
    return ((parsed.scheme in ("http", "https") and bool(parsed.netloc))
            or url.startswith("file:///usr/share/doc/contest/")
            or url == "about:blank")


def valid_logo_url(url):
    parsed = urlparse(url)
    return not url or (parsed.scheme in ("http", "https") and bool(parsed.netloc))


def admin_phase_get(h, query):
    ok, scope = h.admin_scope()
    if not ok:
        return
    group_id = (query.get("group") or [scope or ""])[0]
    if not group_id:
        return h.error(400, "group required")
    if not h.scope_ok(scope, group_id):
        return
    return h.json(200, {"group_id": group_id, "phase": stored_phase(db(), group_id)})


def admin_phase_put(h):
    ok, scope = h.admin_scope()
    if not ok:
        return
    body = h.read_json()
    if not isinstance(body, dict):
        return h.error(400, "expected {group_id, phase}")
    group_id = str(body.get("group_id", "")) or scope
    phase = str(body.get("phase", ""))
    if not group_id:
        return h.error(400, "group_id required")
    if phase not in PHASES:
        return h.error(400, "phase inválida: %s" % ", ".join(PHASES))
    if not h.scope_ok(scope, group_id):
        return
    with DB_LOCK:
        db().execute(
            """INSERT INTO group_config (group_id, phase, updated_at) VALUES (?,?,?)
               ON CONFLICT(group_id) DO UPDATE SET phase=excluded.phase, updated_at=excluded.updated_at""",
            (group_id, phase, iso(now())))
    with CMD_COND:
        CMD_COND.notify_all()   # despierta los long-poll para que reciban meta.phase
    publish("phase.changed", {"group_id": group_id, "phase": phase}, group_id)
    return h.json(200, {"ok": True, "group_id": group_id, "phase": phase})


def admin_teams_get(h):
    ok, scope = h.admin_scope()
    if not ok:
        return
    where = "WHERE group_id=?" if scope else ""
    params = [scope] if scope else []
    rows = db().execute(f"SELECT * FROM teams {where} ORDER BY group_id, seat, name", params).fetchall()
    return h.json(200, {"teams": [dict(r) for r in rows]})


def admin_teams_put(h):
    ok, scope = h.admin_scope()
    if not ok:
        return
    body = h.read_json()
    if not isinstance(body, dict) or not isinstance(body.get("entries"), list):
        return h.error(400, "expected {group_id, entries:[...]}")
    group_id = str(body.get("group_id", "")) or scope
    if not group_id:
        return h.error(400, "group_id required")
    if not h.scope_ok(scope, group_id):
        return
    with DB_LOCK:
        conn = db()
        conn.execute("DELETE FROM teams WHERE group_id=?", (group_id,))
        for e in body["entries"]:
            if not isinstance(e, dict) or not e.get("user_id") or not e.get("name"):
                continue
            conn.execute(
                "INSERT OR REPLACE INTO teams (group_id, user_id, name, org, seat, country) VALUES (?,?,?,?,?,?)",
                (group_id, str(e["user_id"])[:64], str(e["name"])[:128],
                 str(e.get("org", ""))[:128] or None, str(e.get("seat", ""))[:32] or None,
                 str(e.get("country", ""))[:8] or None))
    return h.json(200, {"ok": True})


def admin_allowlist_get(h, query):
    ok, scope = h.admin_scope()
    if not ok:
        return
    if scope is not None:
        return h.error(403, "allowlist persistente: solo con el token superadmin")
    group_id = (query.get("group") or [""])[0]
    if not group_id:
        return h.error(400, "group required")
    hosts, updated_at = stored_allowlist(db(), group_id)
    return h.json(200, {"group_id": group_id, "hosts": hosts, "updated_at": updated_at})


def admin_allowlist_put(h):
    ok, scope = h.admin_scope()
    if not ok:
        return
    if scope is not None:
        return h.error(403, "allowlist persistente: solo con el token superadmin")
    body = h.read_json()
    if not isinstance(body, dict) or not isinstance(body.get("hosts"), list):
        return h.error(400, "expected {group_id, hosts:[...]}")
    group_id = str(body.get("group_id", ""))
    if not group_id:
        return h.error(400, "group_id required")
    hosts, seen = [], set()
    for host in body["hosts"]:
        host = str(host).strip()
        if host and not host.startswith("#") and len(host) <= 253 and host not in seen:
            seen.add(host)
            hosts.append(host)
    if len(hosts) > 500:
        return h.error(400, "too many hosts (max 500)")
    with DB_LOCK:
        conn = db()
        conn.execute(
            """INSERT INTO group_config (group_id, allowlist_json, updated_at) VALUES (?,?,?)
               ON CONFLICT(group_id) DO UPDATE SET
                 allowlist_json=excluded.allowlist_json, updated_at=excluded.updated_at""",
            (group_id, json.dumps(hosts), iso(now())))
        try:
            payload_obj = enqueue_command(conn, group_id, "*", "set-allowlist", {"hosts": hosts})
        except ValueError as exc:
            return h.error(400, str(exc))
        except RuntimeError as exc:
            return h.error(500, str(exc))
    with CMD_COND:
        CMD_COND.notify_all()
    publish("command.sent", {"nonce": payload_obj["nonce"], "action": "set-allowlist",
                             "machine_id": "*"}, group_id)
    return h.json(200, {"ok": True, "group_id": group_id, "hosts": hosts,
                            "nonce": payload_obj["nonce"]})


# homepage y logo por sede, los entrega el login
def admin_cfg_get(h, query, col):
    ok, scope = h.admin_scope()
    if not ok:
        return
    group_id = (query.get("group") or [scope or "__global__"])[0]
    if not h.scope_ok(scope, group_id):
        return
    own, effective, updated_at = stored_cfg(db(), group_id, col)
    if col == "homepage":
        return h.json(200, {"group_id": group_id, "url": effective or DEFAULT_HOMEPAGE,
                                "updated_at": updated_at})
    return h.json(200, {"group_id": group_id, "url": own, "effective_url": effective,
                            "inherited": not own and bool(effective), "updated_at": updated_at})


def admin_cfg_put(h, col):
    ok, scope = h.admin_scope()
    if not ok:
        return
    body = h.read_json()
    if not isinstance(body, dict):
        return h.error(400, "expected {group_id, url}")
    group_id = str(body.get("group_id", "")) or scope or "__global__"
    url = str(body.get("url", "")).strip()
    if not h.scope_ok(scope, group_id):
        return
    if col == "homepage" and not valid_homepage(url):
        return h.error(400, "url must be http(s), about:blank or local contest documentation")
    if col == "logo_url" and not valid_logo_url(url):
        return h.error(400, "logo url must be http(s)")
    ts = "homepage_updated_at" if col == "homepage" else "logo_updated_at"
    updated_at = iso(now())
    with DB_LOCK:
        db().execute(
            f"""INSERT INTO group_config (group_id, {col}, {ts}) VALUES (?,?,?)
                ON CONFLICT(group_id) DO UPDATE SET {col}=excluded.{col}, {ts}=excluded.{ts}""",
            (group_id, url, updated_at))
    publish("homepage.changed" if col == "homepage" else "logo.changed",
            {"group_id": group_id, "url": url}, None if group_id == "__global__" else group_id)
    return h.json(200, {"ok": True, "group_id": group_id, "url": url,
                            "updated_at": updated_at})


def admin_quota(h):
    """Por sede: equipos esperados, conectados y faltantes (sin contrasenas)."""
    ok, scope = h.admin_scope()
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
    return h.json(200, {"quota": out})
