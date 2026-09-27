FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    chrony \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 123/udp

COPY ntp/chrony.conf /etc/chrony/chrony.conf

# -n: primer plano.  -x: no tocar el reloj del host (sin CAP_SYS_TIME); chronyd
# igual rastrea el offset por software y lo sirve.
CMD ["chronyd", "-n", "-x", "-f", "/etc/chrony/chrony.conf"]
