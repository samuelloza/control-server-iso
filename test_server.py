#!/usr/bin/env python3
"""Self-check for server.py. No framework. Run: python3 test_server.py

Starts a real server on an ephemeral port against a throwaway DB + key, then
exercises enroll -> admin command -> machine poll -> openssl signature verify ->
ack -> poll drains. Also checks the obvious rejections.
"""
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
import importlib.util

TMP = tempfile.mkdtemp(prefix="cc-test-")
KEY = os.path.join(TMP, "sign.key")
PUB = os.path.join(TMP, "sign.pub")
subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", KEY], check=True)
subprocess.run(["openssl", "pkey", "-in", KEY, "-pubout", "-out", PUB], check=True)

with open(os.path.join(TMP, "groups.json"), "w") as fh:
    json.dump({
        "_comment": "ignored",
        "lab-uno": "enroll-secret",
        "lab-dos": {"enroll_token": "enroll-dos", "admin_token": "coord-dos", "label": "Sede Dos"},
    }, fh)

with open(os.path.join(TMP, "users.json"), "w") as fh:
    json.dump({
        "_comment": "ignored",
        "t1": {"password": "hunter2", "team_id": "t1", "team_name": "Equipo Uno", "region": "lab-uno"},
        "t2": {"password": "swordfish", "team_id": "t2", "team_name": "Equipo Dos", "region": "lab-dos"},
        "staff1": {"password": "topsecret", "region": "lab-dos"},  # sin team_id: no es un equipo
    }, fh)

os.environ.update(
    CONTROL_DB=os.path.join(TMP, "db.sqlite"),
    CONTROL_SCREENSHOT_DIR=os.path.join(TMP, "shots"),
    CONTROL_HOME_DIR=os.path.join(TMP, "homes"),
    CONTROL_SIGNING_KEY=KEY,
    CONTROL_GROUP_TOKENS=os.path.join(TMP, "groups.json"),
    AUTH_USERS=os.path.join(TMP, "users.json"),
    CONTROL_ADMIN_TOKEN="admin-secret",
    CONTROL_SERVER_NAME="test-control",
    CONTROL_BIND="127.0.0.1:0",
    AUTH_DEFAULT_HOMEPAGE="https://default.example/inicio",
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402

def iso_ago(secs):
    return server.iso(server.now() - server.timedelta(seconds=secs))


httpd = server.ControlHTTPServer(("127.0.0.1", 0), server.Handler)
PORT = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as res:
            raw = res.read()
            return res.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, (json.loads(raw) if raw else None)


def verify(payload_bytes, signature_b64):
    sig = os.path.join(TMP, "sig.bin")
    msg = os.path.join(TMP, "msg.bin")
    with open(sig, "wb") as fh:
        fh.write(base64.b64decode(signature_b64))
    with open(msg, "wb") as fh:
        fh.write(payload_bytes)
    return subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-rawin",
         "-inkey", PUB, "-in", msg, "-sigfile", sig],
        capture_output=True,
    ).returncode == 0


def main():
    # Browser resets are harmless; unexpected handler failures must stay visible.
    errors = io.StringIO()
    try:
        raise ConnectionResetError
    except ConnectionResetError:
        with contextlib.redirect_stderr(errors):
            httpd.handle_error(None, ("127.0.0.1", 0))
    assert errors.getvalue() == ""
    try:
        raise RuntimeError("visible")
    except RuntimeError:
        with contextlib.redirect_stderr(errors):
            httpd.handle_error(None, ("127.0.0.1", 0))
    assert "RuntimeError: visible" in errors.getvalue()

    # bad enroll token -> 401
    status, _ = call("POST", "/enroll", {"machine_id": "m1", "group_id": "lab-uno", "enroll_token": "wrong"})
    assert status == 401, status

    # enroll -> bearer
    status, body = call("POST", "/enroll",
                        {"machine_id": "m1", "group_id": "lab-uno", "enroll_token": "enroll-secret",
                         "hostname": "pc-01"})
    assert status == 200, (status, body)
    bearer = body["bearer"]
    assert bearer

    # no command yet -> 204
    status, _ = call("GET", "/cmd/lab-uno/m1", token=bearer)
    assert status == 204, status

    # admin needs the admin token
    status, _ = call("POST", "/admin/cmd", {"target": {"machine_id": "m1"}, "action": "lock"}, token="nope")
    assert status == 401, status

    # unknown action -> 400
    status, _ = call("POST", "/admin/cmd",
                     {"target": {"machine_id": "m1"}, "action": "nuke"}, token="admin-secret")
    assert status == 400, status

    # message without text -> 400
    status, _ = call("POST", "/admin/cmd",
                     {"target": {"machine_id": "m1"}, "action": "message"}, token="admin-secret")
    assert status == 400, status

    # set-wallpaper without url -> 400; usb-block needs no args -> 200
    status, _ = call("POST", "/admin/cmd",
                     {"target": {"machine_id": "m1"}, "action": "set-wallpaper"}, token="admin-secret")
    assert status == 400, status
    status, body = call("POST", "/admin/cmd",
                        {"target": {"machine_id": "m1"}, "action": "usb-block"}, token="admin-secret")
    assert status == 200, (status, body)
    # drain it so the message-command assertions below still see their nonce first
    call("GET", "/cmd/lab-uno/m1", token=bearer)
    call("POST", "/cmd/lab-uno/m1/ack", {"nonce": body["nonce"], "status": "ok"}, token=bearer)

    # queue a real command
    status, body = call("POST", "/admin/cmd",
                        {"target": {"machine_id": "m1"}, "action": "message",
                         "args": {"text": "hola equipo"}}, token="admin-secret")
    assert status == 200, (status, body)
    nonce = body["nonce"]

    # machine polls, gets it, signature verifies against the exact bytes
    status, body = call("GET", "/cmd/lab-uno/m1", token=bearer)
    assert status == 200, status
    assert body["nonce"] == nonce
    payload_bytes = base64.b64decode(body["payload_b64"])
    assert verify(payload_bytes, body["signature"]), "openssl signature verify failed"
    parsed = json.loads(payload_bytes)
    assert parsed["action"] == "message"
    assert parsed["args"]["text"] == "hola equipo"
    assert parsed["machine_id"] == "m1"
    assert parsed["server"] == "test-control"
    assert payload_bytes.endswith(b"\n")
    # canonical: byte-for-byte reproducible
    assert server.canonical(parsed) == payload_bytes

    # redelivered until acked
    status, body = call("GET", "/cmd/lab-uno/m1", token=bearer)
    assert status == 200 and body["nonce"] == nonce, "should redeliver before ack"

    # ack -> drains
    status, _ = call("POST", "/cmd/lab-uno/m1/ack", {"nonce": nonce, "status": "ok"}, token=bearer)
    assert status == 200, status
    status, _ = call("GET", "/cmd/lab-uno/m1", token=bearer)
    assert status == 204, "acked command should not come back"

    # wrong bearer -> 401
    status, _ = call("GET", "/cmd/lab-uno/m1", token="garbage")
    assert status == 401, status

    # group-wide command reaches the machine
    status, body = call("POST", "/admin/cmd",
                        {"target": {"group_id": "lab-uno", "machine_id": "*"}, "action": "lock"},
                        token="admin-secret")
    assert status == 200, (status, body)
    status, body = call("GET", "/cmd/lab-uno/m1", token=bearer)
    assert status == 200 and body["command"]["machine_id"] == "*", (status, body)

    # admin listing sees the machine
    status, body = call("GET", "/admin/machines", token="admin-secret")
    assert status == 200 and any(m["machine_id"] == "m1" for m in body["machines"])

    # drain anything still queued from the checks above
    for _ in range(6):
        s, b = call("GET", "/cmd/lab-uno/m1", token=bearer)
        if s != 200:
            break
        call("POST", "/cmd/lab-uno/m1/ack", {"nonce": b["nonce"], "status": "ok"}, token=bearer)

    # -- phase 1: long-poll returns 200 + meta on timeout (not 204) ------------
    t0 = time.time()
    status, body = call("GET", "/cmd/lab-uno/m1?wait=1", token=bearer)
    assert status == 200 and "meta" in body and 0.8 < time.time() - t0 < 4, (status, body)

    # -- phase 1: precontest sets server-side lock_state ----------------------
    call("POST", "/admin/cmd", {"target": {"machine_id": "m1"}, "action": "precontest"}, token="admin-secret")
    status, body = call("GET", "/admin/machines", token="admin-secret")
    m1 = next(m for m in body["machines"] if m["machine_id"] == "m1")
    assert m1["lock_state"] == 1, m1
    # drain precontest + the earlier group lock so later asserts are clean
    for _ in range(4):
        s, b = call("GET", "/cmd/lab-uno/m1", token=bearer)
        if s != 200:
            break
        call("POST", "/cmd/lab-uno/m1/ack", {"nonce": b["nonce"], "status": "ok"}, token=bearer)

    # -- phase 1: donottouch freezes delivery except cantouch ---------------
    call("POST", "/admin/cmd", {"target": {"machine_id": "m1"}, "action": "donottouch"}, token="admin-secret")
    s, b = call("GET", "/cmd/lab-uno/m1", token=bearer)
    assert s == 200 and b["action"] == "donottouch"
    call("POST", "/cmd/lab-uno/m1/ack", {"nonce": b["nonce"], "status": "ok"}, token=bearer)
    call("POST", "/admin/cmd", {"target": {"machine_id": "m1"}, "action": "reboot"}, token="admin-secret")
    s, _ = call("GET", "/cmd/lab-uno/m1", token=bearer)
    assert s == 204, "frozen machine must not receive 'reboot'"
    call("POST", "/admin/cmd", {"target": {"machine_id": "m1"}, "action": "cantouch"}, token="admin-secret")
    s, b = call("GET", "/cmd/lab-uno/m1", token=bearer)
    assert s == 200 and b["action"] == "cantouch"
    call("POST", "/cmd/lab-uno/m1/ack", {"nonce": b["nonce"], "status": "ok"}, token=bearer)
    s, b = call("GET", "/cmd/lab-uno/m1", token=bearer)  # now reboot flows
    assert s == 200 and b["action"] == "reboot"
    call("POST", "/cmd/lab-uno/m1/ack", {"nonce": b["nonce"], "status": "ok"}, token=bearer)

    # net-open / net-lock are accepted actions
    s, nb = call("POST", "/admin/cmd", {"target": {"machine_id": "m1"}, "action": "net-open"}, token="admin-secret")
    assert s == 200, (s, nb)

    # -- phase 3: status ingest + machine detail + samples ------------------
    s, _ = call("POST", "/cmd/lab-uno/m1/status",
                {"mem": 41.0, "ld": 0.7, "sw": 0, "hd": 55.0, "virt": "kvm", "usb": "blocked", "locked": 1},
                token=bearer)
    assert s == 200
    s, det = call("GET", "/admin/machines/lab-uno/m1", token="admin-secret")
    assert s == 200 and det["status"]["mem"] == 41.0 and len(det["samples"]) >= 1, det

    # tiempo por programa: el 2do reporte con geany suma el intervalo transcurrido
    call("POST", "/cmd/lab-uno/m1/status", {"editors": {"geany": 1}}, token=bearer)
    time.sleep(2)
    call("POST", "/cmd/lab-uno/m1/status", {"editors": {"geany": 1}}, token=bearer)
    s, det = call("GET", "/admin/machines/lab-uno/m1", token="admin-secret")
    assert 1 <= det["app_usage"].get("geany", 0) <= 3, det["app_usage"]
    hist = [a for a in det["app_history"] if a["app"] == "geany"]
    assert len(hist) == 1 and hist[0]["open"] == 1 and hist[0]["last_at"] > hist[0]["started_at"], det["app_history"]
    call("POST", "/cmd/lab-uno/m1/status", {"editors": {}}, token=bearer)   # cierra la sesion
    s, det = call("GET", "/admin/machines/lab-uno/m1", token="admin-secret")
    assert [a["open"] for a in det["app_history"] if a["app"] == "geany"] == [0], det["app_history"]
    call("POST", "/cmd/lab-uno/m1/status", {"editors": {"geany": 1}}, token=bearer)   # sesion nueva
    # reinicio: otro machine_id, mismo equipo logueado -> continua, no vuelve a 0
    call("POST", "/cmd/lab-uno/m1/status", {"login": {"user_id": "u9"}, "editors": {"vim": 1}}, token=bearer)
    time.sleep(2)
    call("POST", "/cmd/lab-uno/m1/status", {"login": {"user_id": "u9"}, "editors": {"vim": 1}}, token=bearer)
    s, det = call("GET", "/admin/machines/lab-uno/m1", token="admin-secret")
    first = det["app_usage"].get("vim", 0)
    assert first >= 1, det["app_usage"]
    s, en9 = call("POST", "/enroll", {"machine_id": "m9", "group_id": "lab-uno", "enroll_token": "enroll-secret"})
    assert s == 200, (s, en9)
    b9 = en9["bearer"]
    call("POST", "/cmd/lab-uno/m9/status", {"login": {"user_id": "u9"}, "editors": {"vim": 1}}, token=b9)
    time.sleep(2)
    call("POST", "/cmd/lab-uno/m9/status", {"login": {"user_id": "u9"}, "editors": {"vim": 1}}, token=b9)
    s, det2 = call("GET", "/admin/machines/lab-uno/m9", token="admin-secret")
    assert det2["app_usage"].get("vim", 0) > first, (first, det2["app_usage"])

    # -- phase 3: alerts: raise, machine cannot dismiss, admin can ----------
    s, ev = call("POST", "/cmd/lab-uno/m1/events", {"kind": "usb.phone", "detail": "Pixel"}, token=bearer)
    assert s == 200 and "alert_id" in ev
    s, al = call("GET", "/admin/alerts", token="admin-secret")
    assert s == 200 and any(a["kind"] == "usb.phone" for a in al["alerts"])
    aid = ev["alert_id"]
    # no machine route to dismiss
    s, _ = call("POST", f"/cmd/lab-uno/m1/alerts/{aid}/dismiss", {}, token=bearer)
    assert s == 404
    s, _ = call("POST", f"/admin/alerts/{aid}/dismiss", {}, token="admin-secret")
    assert s == 200
    s, al = call("GET", "/admin/alerts", token="admin-secret")
    assert not any(a["id"] == aid for a in al["alerts"]), "dismissed alert must drop from open list"

    # -- phase 4: per-venue scoped admin token -----------------------------
    call("POST", "/enroll", {"machine_id": "d1", "group_id": "lab-dos", "enroll_token": "enroll-dos"})
    s, mine = call("GET", "/admin/machines", token="coord-dos")
    assert s == 200 and mine["scope"] == "lab-dos"
    assert all(m["group_id"] == "lab-dos" for m in mine["machines"]), "scoped token must only see its group"
    # scoped token cannot command another group's machine (404, not 403)
    s, _ = call("POST", "/admin/cmd", {"target": {"machine_id": "m1"}, "action": "lock"}, token="coord-dos")
    assert s == 404, s
    # superadmin-only actions are refused for a venue coordinator, even on their own machine
    for action, args in (("net-open", {}), ("usb-block", {}), ("usb-unblock", {}),
                         ("collect-home", {}), ("set-allowlist", {"hosts": ["x.example"]})):
        s, _ = call("POST", "/admin/cmd",
                    {"target": {"machine_id": "d1"}, "action": action, "args": args}, token="coord-dos")
        assert s == 403, (action, s)
    # bad token
    s, _ = call("GET", "/admin/machines", token="totally-wrong")
    assert s == 401

    # unlock-root password must not leak to the venue's own scoped token
    s, _ = call("POST", "/admin/cmd",
                {"target": {"machine_id": "d1"}, "action": "unlock-root", "args": {"password": "sekret"}},
                token="admin-secret")
    assert s == 200, s
    s, sup_cmds = call("GET", "/admin/commands", token="admin-secret")
    assert s == 200 and any(
        c["action"] == "unlock-root" and json.loads(c["args_json"])["password"] == "sekret"
        for c in sup_cmds["commands"]), "superadmin should still see the password"
    s, coord_cmds = call("GET", "/admin/commands", token="coord-dos")
    assert s == 200 and any(
        c["action"] == "unlock-root" and c["args_json"] is None
        for c in coord_cmds["commands"]), "scoped coordinator must not see the root password"

    # credentials: each coordinator only sees their own venue's plaintext passwords
    s, creds = call("GET", "/admin/credentials?format=json", token="coord-dos")
    assert s == 200 and creds["users"] == [
        {"username": "t2", "password": "swordfish", "team_name": "Equipo Dos"}], creds
    s, _ = call("GET", "/admin/credentials?format=json&group=lab-uno", token="coord-dos")
    assert s == 404, "scoped coordinator must not read another venue's credentials"
    s, all_creds = call("GET", "/admin/credentials?format=json&group=lab-uno", token="admin-secret")
    assert s == 200 and all_creds["users"][0]["password"] == "hunter2", "superadmin sees any venue"

    # -- phase 5: roster + binding -----------------------------------------
    s, _ = call("PUT", "/admin/roster",
                {"group_id": "lab-uno", "entries": [{"user_id": "t1", "name": "Equipo Uno", "seat": "A3"}]},
                token="admin-secret")
    assert s == 200
    s, b = call("PUT", "/admin/machines/lab-uno/m1/binding", {"user_id": "t1"}, token="admin-secret")
    assert s == 200 and b["binding"]["name"] == "Equipo Uno", b
    s, det = call("GET", "/admin/machines/lab-uno/m1", token="admin-secret")
    assert det["binding"]["seat"] == "A3"
    # poll meta carries the binding
    s, b = call("GET", "/cmd/lab-uno/m1?wait=0", token=bearer)
    assert b.get("meta", {}).get("binding", {}).get("name") == "Equipo Uno", b

    # -- phase 6: persistent group allowlist ------------------------------
    # only superadmin may read/save it; a venue coordinator loosening network
    # access on their own is exactly what this gate exists to prevent
    s, _ = call("PUT", "/admin/allowlist",
                {"group_id": "lab-dos", "hosts": ["cppreference.com"]}, token="coord-dos")
    assert s == 403, s
    s, _ = call("GET", "/admin/allowlist?group=lab-dos", token="coord-dos")
    assert s == 403, s
    # superadmin saves it; blanks / comments / dupes are dropped
    s, b = call("PUT", "/admin/allowlist",
                {"group_id": "lab-dos",
                 "hosts": ["login.codi.com.bo", " stats.codi.com.bo ", "", "# nota",
                           "cppreference.com", "cppreference.com"]},
                token="admin-secret")
    assert s == 200 and b["hosts"] == ["login.codi.com.bo", "stats.codi.com.bo", "cppreference.com"], b
    s, b = call("GET", "/admin/allowlist?group=lab-dos", token="admin-secret")
    assert s == 200 and b["hosts"][0] == "login.codi.com.bo" and b["updated_at"], b
    # the save pushed a signed set-allowlist to the whole group; a re-enroll also
    # re-pushes the stored list (a machine reverts /etc on every boot)
    s, en = call("POST", "/enroll", {"machine_id": "d1", "group_id": "lab-dos", "enroll_token": "enroll-dos"})
    d1b = en["bearer"]
    got = set()
    for _ in range(4):
        s, b = call("GET", "/cmd/lab-dos/d1", token=d1b)
        if s != 200:
            break
        if b["action"] == "set-allowlist":
            assert verify(base64.b64decode(b["payload_b64"]), b["signature"])
            assert b["command"]["args"]["hosts"] == ["login.codi.com.bo", "stats.codi.com.bo", "cppreference.com"]
            got.add("ok")
        call("POST", "/cmd/lab-dos/d1/ack", {"nonce": b["nonce"], "status": "ok"}, token=d1b)
    assert "ok" in got, "re-enroll / group push must deliver the stored allowlist"
    # cross-venue read is still 403 (superadmin-only trumps the 404-not-a-leak rule)
    s, _ = call("GET", "/admin/allowlist?group=lab-uno", token="coord-dos")
    assert s == 403, s

    # -- homepage persistente: se entrega en el login, no como comando masivo --
    s, b = call("GET", "/admin/homepage?group=lab-uno", token="admin-secret")
    assert s == 200 and b["url"] == "https://default.example/inicio" and not b["updated_at"], (s, b)
    global_homepage = "https://contest.example/global"
    s, b = call("PUT", "/admin/homepage",
                {"group_id": "__global__", "url": global_homepage}, token="admin-secret")
    assert s == 200 and b["url"] == global_homepage, (s, b)
    s, b = call("GET", "/admin/homepage?group=lab-uno", token="admin-secret")
    assert s == 200 and b["url"] == global_homepage, (s, b)
    s, _ = call("PUT", "/admin/homepage",
                {"group_id": "__global__", "url": global_homepage}, token="coord-dos")
    assert s == 404, s
    homepage = "https://contest.example/inicio"
    s, b = call("PUT", "/admin/homepage",
                {"group_id": "lab-dos", "url": homepage}, token="coord-dos")
    assert s == 200 and b["url"] == homepage, (s, b)
    s, b = call("GET", "/admin/homepage?group=lab-dos", token="coord-dos")
    assert s == 200 and b["url"] == homepage and b["updated_at"], (s, b)
    s, _ = call("PUT", "/admin/homepage",
                {"group_id": "lab-dos", "url": "javascript:alert(1)"}, token="coord-dos")
    assert s == 400, s
    s, _ = call("GET", "/admin/homepage?group=lab-uno", token="coord-dos")
    assert s == 404, s

    # -- logo por sede con fallback global; vacío elimina el override --
    global_logo = "https://contest.example/global.svg"
    site_logo = "https://contest.example/lab-dos.svg"
    s, b = call("PUT", "/admin/logo",
                {"group_id": "__global__", "url": global_logo}, token="admin-secret")
    assert s == 200 and b["url"] == global_logo, (s, b)
    s, b = call("GET", "/admin/logo?group=lab-dos", token="coord-dos")
    assert s == 200 and b["inherited"] and b["effective_url"] == global_logo, (s, b)
    s, _ = call("PUT", "/admin/logo",
                {"group_id": "__global__", "url": global_logo}, token="coord-dos")
    assert s == 404, s
    s, b = call("PUT", "/admin/logo",
                {"group_id": "lab-dos", "url": site_logo}, token="coord-dos")
    assert s == 200 and b["url"] == site_logo, (s, b)
    s, _ = call("PUT", "/admin/logo",
                {"group_id": "lab-dos", "url": "file:///etc/passwd"}, token="coord-dos")
    assert s == 400, s

    users = os.path.join(TMP, "users.json")
    with open(users, "w") as fh:
        json.dump({"team": {"password": "secret", "region": "lab-dos"}}, fh)
    spec = importlib.util.spec_from_file_location(
        "auth_server", os.path.join(os.path.dirname(__file__), "auth-server.py"))
    auth = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(auth)
    auth.USERS_FILE, auth.GROUPS_FILE, auth.DB_FILE = users, server.GROUPS_FILE, server.DB_PATH
    assert auth.homepage_for("lab-uno") == global_homepage
    auth_httpd = ThreadingHTTPServer(("127.0.0.1", 0), auth.Handler)
    threading.Thread(target=auth_httpd.serve_forever, daemon=True).start()
    auth_req = urllib.request.Request(
        f"http://127.0.0.1:{auth_httpd.server_address[1]}/login",
        data=json.dumps({"username": "team", "password": "secret"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(auth_req) as response:
        login = json.load(response)
        assert login["homepage"] == homepage
        assert login["logoUrl"] == site_logo
    auth_httpd.shutdown()

    # -- phase 5: sync HTML report ---------------------------------------
    req = urllib.request.Request(BASE + "/admin/report?group=lab-uno", method="GET")
    req.add_header("Authorization", "Bearer admin-secret")
    with urllib.request.urlopen(req) as r:
        html = r.read().decode()
    assert "<h1>Reporte" in html and "m1" in html

    # -- phase 6: collect-home upload / download / group zip ------------
    import gzip as _gz
    blob = _gz.compress(b"solucion int main(){}")
    r = urllib.request.Request(BASE + "/cmd/lab-uno/m1/home", data=blob, method="POST")
    r.add_header("Authorization", "Bearer " + bearer)
    r.add_header("Content-Type", "application/gzip")
    r.add_header("X-Team-Id", "equipo42")
    with urllib.request.urlopen(r) as res:
        assert res.status == 200, res.status

    r = urllib.request.Request(BASE + "/admin/machines/lab-uno/m1/home?token=admin-secret")
    with urllib.request.urlopen(r) as res:
        assert res.status == 200 and res.read() == blob
        assert "equipo42" in res.headers.get("Content-Disposition", "")

    r = urllib.request.Request(BASE + "/admin/homes/lab-uno?token=admin-secret")
    with urllib.request.urlopen(r) as res:
        import io as _io
        import zipfile as _zip
        names = _zip.ZipFile(_io.BytesIO(res.read())).namelist()
        assert names == ["equipo42__t1.tar.gz"], names   # por equipo (m1 ya esta ligada a t1), no por machine_id

    # non-gzip body is rejected
    r = urllib.request.Request(BASE + "/cmd/lab-uno/m1/home", data=b"not gzip", method="POST")
    r.add_header("Authorization", "Bearer " + bearer)
    try:
        urllib.request.urlopen(r)
        assert False, "expected 400"
    except urllib.error.HTTPError as exc:
        assert exc.code == 400, exc.code

    # -- phase 7: manual location per machine --------------------------
    s, b = call("PUT", "/admin/machines/lab-uno/m1/location",
                {"location": "Sala 3, PC 12"}, token="admin-secret")
    assert s == 200 and b["location"] == "Sala 3, PC 12", (s, b)
    s, b = call("GET", "/admin/machines/lab-uno/m1", token="admin-secret")
    assert b["location"] == "Sala 3, PC 12", b
    s, b = call("GET", "/admin/machines", token="admin-secret")
    assert any(m["machine_id"] == "m1" and m["location"] == "Sala 3, PC 12"
               for m in b["machines"]), b
    s, b = call("PUT", "/admin/machines/lab-uno/m1/location", {"location": ""}, token="admin-secret")
    assert s == 200 and b["location"] == "", (s, b)
    # scoped token can't touch another group's machine (404: no revela el grupo)
    s, _ = call("PUT", "/admin/machines/lab-uno/m1/location", {"location": "x"}, token="coord-dos")
    assert s == 404, s

    # -- phase 8: same user logged in on two machines + logout -------------
    s, en2 = call("POST", "/enroll", {"machine_id": "m2", "group_id": "lab-uno", "enroll_token": "enroll-secret"})
    assert s == 200, (s, en2)
    bearer2 = en2["bearer"]
    call("POST", "/cmd/lab-uno/m1/status", {"login": {"user_id": "t1", "team_name": "Equipo Uno"}}, token=bearer)
    call("POST", "/cmd/lab-uno/m2/status", {"login": {"user_id": "t1", "team_name": "Equipo Uno"}}, token=bearer2)
    s, b = call("GET", "/admin/machines", token="admin-secret")
    ids = {m["machine_id"] for m in b["machines"]}
    assert {"m1", "m2"} <= ids, "both machines with the same user_id must show up independently"
    assert sum(1 for m in b["machines"] if m["machine_id"] in ("m1", "m2")
               and m["binding"]["user_id"] == "t1") == 2

    s, _ = call("POST", "/admin/cmd", {"target": {"machine_id": "m2"}, "action": "logout"}, token="admin-secret")
    assert s == 200, s
    s, b = call("GET", "/admin/machines", token="admin-secret")
    ids = {m["machine_id"] for m in b["machines"]}
    assert "m2" not in ids, "logged-out machine must drop off the Home list"
    assert "m1" in ids, "logout on one machine must not affect the other"

    # logging back in un-hides it
    call("POST", "/cmd/lab-uno/m2/status", {"login": {"user_id": "t1", "team_name": "Equipo Uno"}}, token=bearer2)
    s, b = call("GET", "/admin/machines", token="admin-secret")
    assert any(m["machine_id"] == "m2" for m in b["machines"]), "a fresh login must bring it back"

    # -- alertas calculadas en el servidor ---------------------------------
    def enroll(mid):
        s, e = call("POST", "/enroll", {"machine_id": mid, "group_id": "lab-uno", "enroll_token": "enroll-secret"})
        assert s == 200, (s, e)
        return e["bearer"]

    def has_alert(mid, kind, open_only=True):
        _, al = call("GET", "/admin/alerts", token="admin-secret")
        return any(x["machine_id"] == mid and x["kind"] == kind and (not open_only or not x["dismissed_at"])
                   for x in al["alerts"])

    # disco casi lleno
    call("POST", "/cmd/lab-uno/m1/status", {"hd": 97.0}, token=bearer)
    assert has_alert("m1", "disk.full")

    # reinicio: mismo equipo + misma IP con machine_id nuevo
    bo = enroll("r1")
    call("POST", "/cmd/lab-uno/r1/status", {"login": {"user_id": "u_r"}}, token=bo)
    bn = enroll("r2")   # r1 sigue reportando: es otra PC del mismo equipo, no un reinicio
    call("POST", "/cmd/lab-uno/r2/status", {"login": {"user_id": "u_r"}}, token=bn)
    assert not has_alert("r2", "restart")
    with server._DB_LOCK:   # r1 se calla: ahora r3 del equipo aparece = reinicio
        server.db().execute("UPDATE machines SET last_seen=? WHERE machine_id='r1'", (iso_ago(120),))
    b3 = enroll("r2b")
    call("POST", "/cmd/lab-uno/r2b/status", {"login": {"user_id": "u_r"}}, token=b3)
    assert has_alert("r2b", "restart"), "reinicio inesperado debe alertar"
    # ... pero no si un admin ordeno el reboot
    bo = enroll("r3")
    call("POST", "/cmd/lab-uno/r3/status", {"login": {"user_id": "u_q"}}, token=bo)
    with server._DB_LOCK:
        server.db().execute("UPDATE machines SET last_seen=? WHERE machine_id='r3'", (iso_ago(120),))
    s, _ = call("POST", "/admin/cmd", {"target": {"machine_id": "r3"}, "action": "reboot"}, token="admin-secret")
    assert s == 200
    bn = enroll("r4")
    call("POST", "/cmd/lab-uno/r4/status", {"login": {"user_id": "u_q"}}, token=bn)
    assert not has_alert("r4", "restart"), "reboot ordenado no es un cuelgue"

    # offline: solo en fase de concurso; se cierra sola al volver a reportar
    b5 = enroll("r5")
    call("POST", "/cmd/lab-uno/r5/status", {"login": {"user_id": "u_off"}}, token=b5)
    old = iso_ago(300)
    with server._DB_LOCK:
        server.db().execute("UPDATE machines SET last_seen=?, status_at=? WHERE machine_id='r5'", (old, old))
    server.check_offline()
    assert not has_alert("r5", "offline"), "en fase idle no se vigila"
    s, _ = call("PUT", "/admin/phase", {"group_id": "lab-uno", "phase": "live"}, token="admin-secret")
    assert s == 200, s
    server.check_offline()
    assert has_alert("r5", "offline")
    call("POST", "/cmd/lab-uno/r5/status", {"login": {"user_id": "u_off"}}, token=b5)
    assert not has_alert("r5", "offline"), "al volver a reportar se cierra sola"

    # -- historial de capturas manuales: por equipo y sobrevive al reinicio
    b6 = enroll("s1")
    call("POST", "/cmd/lab-uno/s1/status", {"login": {"user_id": "u_shot"}}, token=b6)
    for i in range(3):   # la ISO sube el PNG; el historial queda por equipo y con tope
        req = urllib.request.Request(BASE + "/cmd/lab-uno/s1/screenshot", method="POST",
                                     data=b"\x89PNG\r\n\x1a\n" + bytes([i]) * 10)
        req.add_header("Authorization", "Bearer " + b6)
        urllib.request.urlopen(req).read()
        time.sleep(0.01)
    s, sh = call("GET", "/admin/machines/lab-uno/s1/shots", token="admin-secret")
    assert s == 200 and len(sh["shots"]) == 3, sh
    b7 = enroll("s2")   # reinicio: otro machine_id, mismo equipo -> ve el mismo historial
    call("POST", "/cmd/lab-uno/s2/status", {"login": {"user_id": "u_shot"}}, token=b7)
    s, sh2 = call("GET", "/admin/machines/lab-uno/s2/shots", token="admin-secret")
    assert sh2["shots"] == sh["shots"], (sh, sh2)
    with urllib.request.urlopen(BASE + f"/admin/machines/lab-uno/s2/shots/{sh['shots'][0]}?token=admin-secret") as r:
        assert r.read()[:8] == b"\x89PNG\r\n\x1a\n"

    # -- cupos por sede: esperados (users.json, solo cuentas con team_id), conectados y faltantes
    s, qd = call("GET", "/admin/quota", token="admin-secret")
    assert s == 200, (s, qd)
    q = {x["group_id"]: x for x in qd["quota"]}
    assert q["lab-uno"]["expected"] == 1 and q["lab-dos"]["expected"] == 1, q   # staff1 (sin team_id) no cuenta
    assert all(set(u) == {"username", "team_name"} for x in q.values() for u in x["missing"]), \
        "el cupo no debe exponer contrasenas"
    assert q["lab-dos"]["connected"] + len(q["lab-dos"]["missing"]) == 1
    s, qc = call("GET", "/admin/quota", token="coord-dos")
    assert [x["group_id"] for x in qc["quota"]] == ["lab-dos"], "un coordinador solo ve su sede"

    # -- captura de toda Bolivia: solo superadmin y solo 'screenshot'
    s, r = call("POST", "/admin/cmd", {"target": {"all": True}, "action": "screenshot"}, token="admin-secret")
    assert s == 200 and {"lab-uno", "lab-dos"} <= set(r["groups"]), (s, r)
    s, _ = call("POST", "/admin/cmd", {"target": {"all": True}, "action": "screenshot"}, token="coord-dos")
    assert s == 403, "un coordinador de sede no puede pedir toda Bolivia"
    s, _ = call("POST", "/admin/cmd", {"target": {"all": True}, "action": "lock"}, token="admin-secret")
    assert s == 403, "'all' solo vale para screenshot"
    s, _ = call("POST", "/admin/cmd", {"target": {"group_id": "lab-dos", "machine_id": "*"}, "action": "screenshot"},
                token="coord-dos")
    assert s == 200, "el coordinador si puede capturar su propio grupo"
    s, _ = call("POST", "/admin/cmd", {"target": {"group_id": "lab-uno", "machine_id": "*"}, "action": "screenshot"},
                token="coord-dos")
    assert s == 404, "...pero no otro grupo (404, como el resto de accesos cruzados)"

    print("ok")


if __name__ == "__main__":
    try:
        main()
    finally:
        httpd.shutdown()
