FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsmasq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 53/udp 53/tcp

COPY dns/dnsmasq.conf /etc/dnsmasq.conf

CMD ["dnsmasq", "--keep-in-foreground", "--conf-file=/etc/dnsmasq.conf"]
