FROM debian:12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    iptables \
    iputils-ping \
    kmod \
    conntrack \
    nftables \
    ppp \
    strongswan \
    strongswan-swanctl \
    xl2tpd \
    nodejs \
    npm \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy || true \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy || true \
    && update-alternatives --set arptables /usr/sbin/arptables-legacy || true \
    && update-alternatives --set ebtables /usr/sbin/ebtables-legacy || true \
    && rm -rf /var/lib/apt/lists/*

COPY apps/worker-runtime/package.json ./package.json
RUN npm install

COPY apps/worker-runtime/src ./src

EXPOSE 8080
CMD ["npm", "start"]
