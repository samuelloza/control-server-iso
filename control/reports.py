"""Reportes HTML: estado de la sede y credenciales para imprimir."""
import html

from control.db import db, iso, now
from control.groups import users_for_group
from control.machines import machine_rows


def admin_report(h, query):
    # se abre en otra pestaña, por eso ?token=
    ok, scope = h.admin_scope(token=(query.get("token") or [None])[0])
    if not ok:
        return
    group_id = (query.get("group") or [scope or ""])[0]
    if scope and group_id != scope:
        return h.error(404, "not found")
    machines = machine_rows(group_id or None)
    conn = db()
    where = "WHERE group_id=?" if group_id else ""
    params = [group_id] if group_id else []
    alerts = [dict(r) for r in conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT 500", params)]
    data = {"generated_at": iso(now()), "group": group_id or "(all)",
            "machines": machines, "alerts": alerts}
    if (query.get("format") or ["html"])[0] == "json":
        return h.json(200, data)
    return h.send(200, report_html(data), "text/html; charset=utf-8")


def admin_credentials(h, query):
    # se abre en otra pestaña, por eso ?token=
    ok, scope = h.admin_scope(token=(query.get("token") or [None])[0])
    if not ok:
        return
    group_id = (query.get("group") or [scope or ""])[0]
    if not group_id:
        return h.error(400, "group required")
    if scope and group_id != scope:
        return h.error(404, "not found")
    users = users_for_group(group_id)
    if (query.get("format") or ["html"])[0] == "json":
        return h.json(200, {"group_id": group_id, "users": users})
    return h.send(200, credentials_html(group_id, users), "text/html; charset=utf-8")


def esc(x):
    return html.escape("" if x is None else str(x))


def report_html(d):
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


def credentials_html(group_id, users):
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
