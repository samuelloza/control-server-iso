FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Solo el código. keys/, data/, groups.json, users.json y .env se montan en
# runtime (secretos, gitignored) — ver docker-compose.yml. La misma imagen sirve
# para control-server y para auth-server (cambia el CMD en compose).
COPY server.py auth-server.py index.html icpc-bolivia-logo.svg icpc-bolivia-wallpaper.svg command.schema.json ./

EXPOSE 8090 6666

CMD ["python3", "server.py"]
