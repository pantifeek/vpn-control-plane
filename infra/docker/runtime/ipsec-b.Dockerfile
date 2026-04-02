FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache \
    openrc \
    ca-certificates \
    curl \
    iproute2 \
    iptables \
    iputils \
    kmod \
    conntrack-tools \
    nftables \
    ppp \
    libreswan \
    xl2tpd \
    nodejs \
    npm \
    && mkdir -p /var/run/pluto \
    && mkdir -p /var/run/xl2tpd \
    && touch /var/run/xl2tpd/l2tp-control

COPY apps/worker-runtime/package.json ./package.json
RUN npm install --omit=dev

COPY apps/worker-runtime/src ./src

EXPOSE 8080
CMD ["npm", "start"]
