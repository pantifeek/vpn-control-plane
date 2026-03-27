FROM node:22-bookworm-slim

WORKDIR /app

COPY apps/manager-web/package.json ./package.json
RUN npm install

COPY apps/manager-web/src ./src

EXPOSE 3000
CMD ["npm", "start"]
