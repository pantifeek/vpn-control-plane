FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    strongswan \
    strongswan-swanctl \
    xl2tpd \
    ppp \
    kmod \
    iproute2 \
    iptables \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY apps/worker-runtime/package.json ./package.json
RUN npm install

COPY apps/worker-runtime/src ./src

EXPOSE 8080
CMD ["npm", "start"]
