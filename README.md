# control-server

Servidor de control remoto para las máquinas del concurso + UI mínima para el
coordinador. Vive fuera del build del ISO: **nada de esto entra al squashfs**.

Reusa los patrones que ya tiene el proyecto:

- Entrega de comandos firmados con **Ed25519**, verificados por `openssl`, igual
  que `overlay/usr/lib/contest/update.sh` verifica el manifiesto de updates.
- Las máquinas **consultan** (poll) por HTTPS — funcionan detrás de NAT, sin VPN.
- Identidad por `machine_id` (ya existe `stats-machine-id.sh`) + `group_id`
  horneado por build (una sede / coordinador = un ISO con su `GROUP_ID`).

Solo stdlib de Python 3 + el CLI de `openssl`. Sin dependencias.

## Puesta en marcha

```sh
./make-keys.sh                       # genera keys/command-signing.{key,pub}
cp groups.json.example groups.json   # define group_id -> enroll token
cp .env.example .env                 # define CONTROL_ADMIN_TOKEN, etc.
set -a; . ./.env; set +a
python3 server.py                    # http://127.0.0.1:8090
```

Poné un reverse proxy con TLS (nginx/caddy) delante; el servidor escucha en
localhost. `keys/`, `data/`, `groups.json` y `.env` están gitignored.

### Con Docker

`docker-compose.yml` levanta el control-server (`:8090` en loopback) + un
resolver DNS de caché (`:53`, ver `dns/`). Aparte del build del ISO.

```sh
./make-keys.sh
cp groups.json.example groups.json   # o el que ya tengas
cp .env.example .env                 # editá CONTROL_ADMIN_TOKEN
docker compose up -d
```

Si `NET_DNS_SERVERS` del ISO apunta directo a 1.1.1.1/8.8.8.8, el servicio `dns`
sobra: `docker compose up -d control-server`.

**Clave de firma:** lo más lazy es apuntar `CONTROL_SIGNING_KEY` a la MISMA clave
Ed25519 que las actualizaciones firmadas del ISO. Así la máquina ya tiene la
pública en `/usr/share/contest/keys/update-signing.pub` y no hay que hornear otra.
`make-keys.sh` genera una dedicada solo si preferís separarlas.

La UI del coordinador es `GET /` (la sirve el mismo servidor): **tarjetas por
máquina** con color de salud (verde/amarillo/rojo/gris según último visto,
alerta, mem/disco), filtros (con USB, bloqueadas, con alerta, sin equipo,
offline), banner de alertas con "dispensar", clic → detalle
(estado/alertas/comandos/journal), botones de acción, roster. Actualiza por
**SSE** + poll de respaldo. El token va en `sessionStorage`.

## Grupos y tokens (`groups.json`)

```json
{ "lab-uno": "enroll-token",                                    // forma corta
  "lab-dos": { "enroll_token": "...", "admin_token": "...", "label": "Sede Dos" } }
```

`CONTROL_ADMIN_TOKEN` = superadmin (ve/comanda todo). Un `admin_token` de grupo
**scopea** todo `/admin/*` a esa sede: solo ve sus máquinas, solo comanda las
suyas, y el acceso cruzado devuelve `404` (no `403`, para no filtrar nombres).

## Endpoints

| Método | Ruta | Auth | Uso |
|---|---|---|---|
| `POST` | `/enroll` | enroll token | `{machine_id, group_id, enroll_token, hostname?}` → `{bearer}` |
| `GET`  | `/cmd/<g>/<m>?wait=N` | `Bearer` máquina | Comando firmado o `204`. `wait` (≤30) = **long-poll**: se retiene la conexión hasta que haya comando o venza; en timeout devuelve `200 {meta}`. Respuesta incluye `meta:{lock_state,frozen,binding}` para reconciliar al arranque |
| `POST` | `/cmd/<g>/<m>/ack` | `Bearer` máquina | `{nonce, status?, detail?}` |
| `POST` | `/cmd/<g>/<m>/status` | `Bearer` máquina | Telemetría (`{mem,ld,sw,hd,virt,usb,locked,...}`); snapshot + serie `samples` (ring de 400) |
| `POST` | `/cmd/<g>/<m>/journal` | `Bearer` máquina | `text/plain` journal (cap 64 KiB/máquina) |
| `POST` | `/cmd/<g>/<m>/events` | `Bearer` máquina | `{kind, detail?}` → alerta (la máquina **no** puede descartarla) |
| `POST` | `/admin/cmd` | admin | `{target:{group_id?|machine_id?}, action, args?, ttl_seconds?}` |
| `GET`  | `/admin/machines` | admin | Máquinas + salud + alertas abiertas + binding + `scope` |
| `GET`  | `/admin/machines/<g>/<m>` | admin | Detalle: status, `samples`, journal, alertas, comandos |
| `GET`  | `/admin/commands?limit=` | admin | Comandos recientes |
| `GET`  | `/admin/alerts` | admin | Alertas abiertas |
| `POST` | `/admin/alerts/<id>/dismiss` | admin | Descartar (audita quién + cuándo) |
| `GET`/`PUT` | `/admin/roster` | admin | Roster de equipos del grupo |
| `GET`/`PUT` | `/admin/allowlist?group=` | admin | Allowlist de red **persistente** del grupo. `PUT {group_id, hosts:[...]}` la guarda y manda un `set-allowlist` firmado a `*`; además se re-empuja a cada máquina al (re-)enrolar |
| `GET`/`PUT` | `/admin/homepage?group=` | admin | Página de Firefox por sede. `__global__` es el predeterminado; el login la devuelve al equipo sin enviar comandos masivos |
| `GET`/`PUT` | `/admin/logo?group=` | admin | URL del logo SVG por sede. `__global__` es el predeterminado; una URL vacía hace que la sede lo herede |
| `PUT` | `/admin/machines/<g>/<m>/binding` | admin | `{user_id}` liga máquina↔equipo (vacío = desligar) |
| `GET`  | `/admin/events?token=` | admin | SSE (`command.sent/acked`, `machine.*`, `alert.*`) |
| `GET`  | `/admin/report?group=&format=` | admin | Reporte HTML (o `json`) por sede |
| `GET`  | `/healthz` | — | `{ok:true}` |

`?token=` sirve para SSE y reporte (se abren sin headers). Long-poll: proceso
único (estado en memoria); poné el server detrás de TLS, no lo escales.

## Acciones (whitelist)

| Acción | Args | Efecto |
|---|---|---|
| `lock` / `unlock` | — | Bloqueo best-effort (`contest-session.sh`). `lock` fija `lock_state` en el server → la máquina que reinicia se re-bloquea sola |
| `precontest` | — | Macro: `lock` + `usb-block` + `lock_state` |
| `donottouch` / `cantouch` | — | Congela / descongela la entrega de comandos a esa máquina (solo `cantouch` pasa mientras está congelada) |
| `message` | `text` | `zenity --info` |
| `net-lock` / `net-open` | — | Reinstala / levanta el bloqueo nftables completo (`contest-net.sh`) |
| `set-allowlist` | `hosts:[...]` | Reescribe allowlist + aplica nftables. Envío puntual; para una lista que sobreviva reinicios usá `PUT /admin/allowlist` |
| `usb-block` / `usb-unblock` | — | `contest-usb-storage.sh` |
| `set-wallpaper` | `url` | Descarga (host allowlisted) + fija en GNOME/XFCE |
| `reset-home` | — | Marca + reinicio; limpia `/home` antes del escritorio |
| `reboot` / `poweroff` | — | `systemctl` |

La máquina lo ejecuta con `overlay/usr/local/sbin/contest-control.sh --loop`
(`contest-control.service`, `Restart=always`, long-poll `?wait=25` + heartbeat de
telemetría). Enrola con `GROUP_ID`/`ENROLL_TOKEN` de `/etc/contestiso/identity.env`,
verifica con `/usr/share/contest/keys/update-signing.pub` (**misma clave Ed25519
que las actualizaciones**), deduplica por `nonce`, reconcilia lock/binding del
`meta`, y detecta VM (`ALLOW_VM=false` → alerta `vm.detected`).

## Contrato del comando firmado

JSON canónico UTF-8 (claves ordenadas, sin espacios, `\n` final), ≤ 8 KiB,
firmado con la privada Ed25519. Esquema en `command.schema.json`. Ejemplo de los
bytes que se firman:

```
{"action":"message","args":{"text":"hola equipo"},"expires_at":"2026-09-06T13:00:00Z","group_id":"lab-uno","issued_at":"2026-09-06T12:00:00Z","machine_id":"m1","nonce":"a5Yk..."}
```

El cliente en el ISO debe, con `keys/command-signing.pub` horneada:

```sh
printf '%s' "$payload" > /tmp/cmd.json          # bytes exactos, con el \n final
printf '%s' "$signature_b64" | openssl base64 -d -A > /tmp/cmd.sig
openssl pkeyutl -verify -pubin -rawin -inkey /path/command-signing.pub \
    -in /tmp/cmd.json -sigfile /tmp/cmd.sig     # == verificación de update.sh
```

y recién entonces parsear el JSON. Debe **deduplicar por `nonce`** (recordar los
ya aplicados), rechazar `expires_at` vencido, y confirmar que `machine_id` es el
suyo o `*`.

## Lado ISO (ya en el repo)

- `overlay/usr/local/sbin/contest-control.sh --loop` + `contest-control.service`
  (habilitado por `scripts/setup.d/common/27-contest-control.sh`),
  `identity.env`, `control.env`, `lock.env` (hash salado de `LOCKSCREEN_PASSWORD`),
  `bearer` en `/var/lib/contest-control/`.
- Acciones delegadas: `contest-session.sh`, `contest-lock-guard.sh` (aviso a
  pantalla completa + **desbloqueo local de emergencia** con la clave del staff
  si cae la red), `contest-set-wallpaper.sh`, `contest-usb-storage.sh`,
  `contest-net.sh`, `contest-alert.sh`, `contest-allowlist-apply.sh`,
  `contest-reset-home.sh`.
- Alertas por udev (`overlay/etc/udev/rules.d/99-contest-usb-alert.rules`):
  `usb.storage`, `usb.phone` (MTP/PTP), `usb.network` (tethering) → `contest-alert.sh`.
- `nftables` default-deny + allowlist: `overlay/etc/nftables.conf` +
  `scripts/setup.d/common/25-network-lockdown.sh`.

Pendiente: partición de config editable sin root para no rebuild-ear por sede;
kiosk real si `zenity` no alcanza; capas overlayfs rootless / seeders (grandes).

## Test

```sh
python3 test_server.py   # imprime "ok"
```
