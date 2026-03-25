# ── Build stage ─────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY prisma ./prisma/

RUN npm ci --omit=dev && \
    npx prisma generate


# ── Production stage ────────────────────
FROM node:20-alpine

RUN apk add --no-cache dumb-init openssl

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

# Create non-root user
RUN addgroup -S nodejs && adduser -S nodeuser

# Copy files
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma

COPY src ./src
COPY package*.json ./

USER nodeuser

EXPOSE 3000

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/server.js"]   