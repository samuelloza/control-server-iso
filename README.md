# control-server

Servidor para controlar las máquinas del concurso (ISO de icpcbo-live) y panel
web para los coordinadores. Incluye también el servicio de login.

Solo usa Python 3 (stdlib) y `openssl`.

## Uso

```sh
./make-keys.sh                        # keys/command-signing.key y .pub
./make-groups.sh lapaz sucre cbba     # groups.json con tokens por sede
cp .env.example .env                  # poner CONTROL_ADMIN_TOKEN
# users.json: equipos con password, team_id, team_name y region
docker compose up -d
```

Levanta `control-server` (8090), `auth` (6666) y `ntp` (123/udp). Hay que
poner TLS delante (nginx o caddy).

Sin Docker:

```sh
set -a; . ./.env; set +a
python3 server.py
python3 auth-server.py
```

La llave pública (`keys/command-signing.pub`) va en la ISO para verificar los
comandos.

## Código

- `server.py`: arranca el servidor.
- `control/web.py`: HTTP, permisos y tabla de rutas.
- `control/commands.py`: comandos firmados (cola, entrega, ack).
- `control/machines.py`: registro, telemetría, alertas.
- `control/groups.py`: config por sede (fase, allowlist, homepage, logo, equipos).
- `control/files.py`: capturas y código recogido.
- `control/reports.py`: reporte y credenciales.
- `control/events.py`: SSE para el panel.
- `control/db.py`, `control/settings.py`: SQLite y configuración.
- `auth-server.py`: login de los equipos.

## Tokens

- `CONTROL_ADMIN_TOKEN`: superadmin, ve y controla todas las sedes.
- `admin_token` de cada sede en `groups.json`: el coordinador solo ve su sede.
  Algunas acciones (abrir red/USB, allowlist, recoger código, root) son solo
  para superadmin.
- `enroll_token`: lo usan las máquinas para registrarse. El login se lo pasa a
  cada equipo según su sede.

## Endpoints

Máquinas (`Bearer` que devuelve `/enroll`):

| | |
|---|---|
| `POST /enroll` | registro, devuelve el bearer |
| `GET /cmd/<g>/<m>?wait=N` | siguiente comando firmado (long-poll hasta 30s) |
| `POST /cmd/<g>/<m>/ack` | confirmar comando |
| `POST /cmd/<g>/<m>/status` | telemetría |
| `POST /cmd/<g>/<m>/journal` | logs |
| `POST /cmd/<g>/<m>/events` | alerta desde la máquina |
| `POST /cmd/<g>/<m>/screenshot` | captura PNG |
| `POST /cmd/<g>/<m>/home` | tar.gz del home del equipo |

Admin (`Bearer` admin, o `?token=` en SSE, reportes y descargas):

| | |
|---|---|
| `POST /admin/cmd` | mandar comando a una máquina o sede |
| `GET /admin/machines` | lista de máquinas |
| `GET /admin/machines/<g>/<m>` | detalle |
| `GET /admin/machines/<g>/<m>/screenshot` | última captura |
| `GET /admin/machines/<g>/<m>/shots[/<ts>]` | historial de capturas |
| `GET /admin/machines/<g>/<m>/home` | último código recogido |
| `GET /admin/homes/<g>` | zip con el código de toda la sede |
| `POST /admin/machines/<g>/<m>/binding` | asignar equipo a mano |
| `POST /admin/machines/<g>/<m>/location` | ubicación (ej. "Sala 3, PC 12") |
| `GET /admin/commands` | comandos recientes |
| `GET /admin/alerts`, `POST /admin/alerts/<id>/dismiss` | alertas |
| `GET/POST /admin/phase` | fase de la sede (idle, practice, live, frozen, ended) |
| `GET/POST /admin/teams` | equipos con asiento y universidad |
| `GET/POST /admin/allowlist` | dominios permitidos por sede |
| `GET/POST /admin/homepage` | página de inicio de Firefox |
| `GET/POST /admin/logo` | logo por sede |
| `GET /admin/quota` | equipos conectados vs esperados |
| `GET /admin/report` | reporte HTML o JSON |
| `GET /admin/credentials` | credenciales para imprimir |
| `GET /admin/events` | eventos en vivo (SSE) |

Las acciones permitidas están en `ACTIONS` en `server.py`.

## Comandos firmados

JSON con claves ordenadas y `\n` al final, firmado con Ed25519. Formato en
`command.schema.json`:

```
{"action":"message","args":{"text":"hola"},"expires_at":"...","group_id":"lapaz","issued_at":"...","machine_id":"m1","nonce":"..."}
```

La máquina verifica la firma, el grupo, la máquina y la expiración, y no
repite un `nonce` ya aplicado.

## Tests

```sh
python3 test_server.py
```
