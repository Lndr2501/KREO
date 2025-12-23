FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY server.js .

EXPOSE 6969

CMD ["node", "server.js"]
