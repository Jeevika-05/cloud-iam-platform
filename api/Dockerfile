# ── Build stage ─────────────────────────
FROM node:20-alpine AS builder
RUN apk add --no-cache openssl   

WORKDIR /app

COPY package*.json ./
COPY prisma ./prisma/

RUN npm ci && \
    npx prisma generate


# ── Production stage ────────────────────
FROM node:20-alpine AS production

RUN apk add --no-cache dumb-init openssl

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

# Create non-root user
RUN addgroup -S nodejs && adduser -S nodeuser

# Pre-create secrets mount point to ensure Docker doesn't trip on ro rootfs issues
RUN mkdir -p /app/secrets && \
    touch /app/secrets/key1_private.pem /app/secrets/key1_public.pem \
          /app/secrets/key2_private.pem /app/secrets/key2_public.pem \
          /app/secrets/jwt_private.pem /app/secrets/jwt_public.pem \
          /app/secrets/encryption_v1.key /app/secrets/encryption_v2.key && \
    chown -R nodeuser:nodejs /app/secrets

# Copy files
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma

COPY src ./src
COPY workers ./workers
COPY scripts ./scripts
COPY package*.json ./

USER nodeuser

EXPOSE 3000

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/server.js"]   