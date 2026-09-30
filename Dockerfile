FROM node:22-alpine
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile --prod
COPY server ./server
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "server/index.mjs"]
