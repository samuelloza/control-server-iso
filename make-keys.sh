#!/bin/sh
# Genera el par Ed25519 con el que el servidor firma los comandos.
# La clave privada NO sale de este host; la pública se hornea en el ISO.
set -eu

cd "$(dirname "$0")"
mkdir -p keys

if [ -f keys/command-signing.key ]; then
    echo "keys/command-signing.key ya existe; no se toca."
else
    openssl genpkey -algorithm ed25519 -out keys/command-signing.key
    chmod 600 keys/command-signing.key
    echo "escrito keys/command-signing.key (0600)"
fi

openssl pkey -in keys/command-signing.key -pubout -out keys/command-signing.pub
echo "escrito keys/command-signing.pub"
echo
echo "Siguiente paso: copiar keys/command-signing.pub al build del ISO"
echo "(igual que UPDATE_SIGNATURE_PUBKEY en config/iso.conf) para que el"
echo "cliente contest-control verifique la firma."
