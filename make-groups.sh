#!/bin/sh
# Genera groups.json para el modelo "1 ISO generico":
#   - grupo "lobby": token bootstrap, todas las maquinas arrancan aqui.
#   - un grupo por sede: enroll_token (lo entrega el login) + admin_token
#     (para el coordinador de esa sede).
#
#   ./make-groups.sh lapaz elalto sucre cbba scz ...      -> escribe groups.json
#
# Imprime tambien:
#   - la linea BOOTSTRAP para config/iso.local.conf del ISO generico
#   - la tabla region->enrollToken para el servidor de login
set -eu

cd "$(dirname "$0")"
[ "$#" -ge 1 ] || { echo "uso: $0 <sede-id> [sede-id ...]" >&2; exit 1; }
[ -e groups.json ] && { echo "groups.json ya existe; borralo si querES regenerar." >&2; exit 1; }

rnd() { openssl rand -hex 24; }

BOOTSTRAP="$(rnd)"

{
    printf '{\n'
    printf '  "_comment": "lobby=bootstrap del ISO generico; una sede por grupo (enroll_token lo da el login, admin_token es del coordinador de sede).",\n'
    printf '  "lobby": { "enroll_token": "%s", "admin_token": null, "label": "Sin asignar" }' "${BOOTSTRAP}"
    for id in "$@"; do
        printf ',\n  "%s": { "enroll_token": "%s", "admin_token": "%s", "label": "%s" }' \
            "${id}" "$(rnd)" "$(rnd)" "${id}"
    done
    printf '\n}\n'
} > groups.json
chmod 600 groups.json
echo "escrito groups.json ($# sedes + lobby)"
echo

echo "=== config/iso.local.conf del ISO generico ==="
echo "REGION_ID=\"\""
echo "GROUP_ID=\"lobby\""
echo "ENROLL_TOKEN=\"${BOOTSTRAP}\""
echo
echo "=== servidor de login: region -> enrollToken (lo devuelve en /login) ==="
python3 - <<'PY'
import json
g = json.load(open("groups.json"))
for gid, rec in g.items():
    if gid.startswith("_") or gid == "lobby":
        continue
    print(f'  {gid:12s} enrollToken={rec["enroll_token"]}   admin_token={rec["admin_token"]}')
PY
