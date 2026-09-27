FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    chrony \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 123/udp

COPY ntp/chrony.conf /etc/chrony/chrony.conf

# -x: no toca el reloj del host
CMD ["chronyd", "-n", "-x", "-f", "/etc/chrony/chrony.conf"]
