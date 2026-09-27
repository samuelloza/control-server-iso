FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# keys/, data/, groups.json y users.json se montan desde compose
COPY server.py auth-server.py index.html icpc-bolivia-logo.svg icpc-bolivia-wallpaper.svg command.schema.json ./

EXPOSE 8090 6666

CMD ["python3", "server.py"]
