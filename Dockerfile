FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN mkdir -p uploads/avatars uploads/files && chown -R node:node /app
USER node
EXPOSE 3000
CMD ["node", "server.js"]
