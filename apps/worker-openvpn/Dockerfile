FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    openvpn \
    iproute2 \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY apps/worker-openvpn/package.json ./package.json
RUN npm install

COPY apps/worker-openvpn/src ./src

EXPOSE 3101
CMD ["npm", "start"]
