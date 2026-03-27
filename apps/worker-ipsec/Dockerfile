FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    strongswan \
    strongswan-swanctl \
    iproute2 \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY apps/worker-ipsec/package.json ./package.json
RUN npm install

COPY apps/worker-ipsec/src ./src

EXPOSE 3102
CMD ["npm", "start"]
