FROM node:22-bookworm-slim

WORKDIR /app

COPY apps/manager-api/package.json ./package.json
RUN npm install

COPY apps/manager-api/src ./src

EXPOSE 3001
CMD ["npm", "start"]
