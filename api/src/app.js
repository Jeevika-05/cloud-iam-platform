import express from 'express';
import helmet from 'helmet';

// PATCH 2: Validate Key Version at Application Startup
const version = Number(process.env.ACTIVE_KEY_VERSION);

if (!version) {
  throw new Error("ACTIVE_KEY_VERSION missing or invalid");
}

const key = process.env[`ENCRYPTION_KEY_V${version}`];

if (!key) {
  throw new Error(`ENCRYPTION_KEY_V${version} is missing`);
}

if (key.length !== 64 || !/^[0-9a-fA-F]+$/.test(key)) {
  throw new Error(`Invalid ENCRYPTION_KEY_V${version}`);
}
import cors from 'cors';
import morgan from 'morgan';
import { apiLimiter, internalLimiter } from './shared/middleware/rateLimiter.js';
import hpp from 'hpp';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { randomUUID } from 'crypto';

import authRoutes from './modules/auth/auth.routes.js';
import userRoutes, { internalRouter as internalUserRouter } from './modules/user/user.routes.js';
import analyticsRoutes from './modules/analytics/analytics.routes.js';
import mfaRoutes from './modules/auth/mfa.routes.js';

import { errorHandler, notFoundHandler } from './shared/middleware/errorHandler.js';
import { authenticate } from './shared/middleware/authenticate.js';
import logger from './shared/utils/logger.js';

const app = express();

// ─────────────────────────────────────────────
// TRUST PROXY
// ─────────────────────────────────────────────
// 🔒 SEC-05: Trust only 1 proxy hop (prevents X-Forwarded-For spoofing)
app.set('trust proxy', 1);

// ─────────────────────────────────────────────
// REQUEST ID (for tracing)
// ─────────────────────────────────────────────
app.use((req, res, next) => {
  req.id = randomUUID();
  next();
});

// ─────────────────────────────────────────────
// SECURITY HEADERS
// ─────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);

// ─────────────────────────────────────────────
// CORS — 🔐 SECURITY FIX: No unsafe wildcard fallback
// ─────────────────────────────────────────────
app.use(
  cors({
    origin: process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',')
      : ['http://localhost:3000'],
    credentials: true,
  })
);

// ─────────────────────────────────────────────
// BODY PARSING
// ─────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ─────────────────────────────────────────────
// COOKIE + COMPRESSION
// ─────────────────────────────────────────────
app.use(cookieParser());
app.use(compression());

// ─────────────────────────────────────────────
// SECURITY: HPP
// ─────────────────────────────────────────────
app.use(hpp());

// ─────────────────────────────────────────────
// LOGGING
// ─────────────────────────────────────────────
app.use(
  morgan('combined', {
    stream: { write: (msg) => logger.http(msg.trim()) },
    skip: () => process.env.NODE_ENV === 'test',
  })
);

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────
app.use(apiLimiter);

// ─────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/mfa', mfaRoutes);
app.use('/api/v1/users', authenticate, userRoutes);
app.use('/api/v1/analytics', authenticate, analyticsRoutes);

// ─────────────────────────────────────────────
// INTERNAL ROUTES — Zero Trust (service-to-service only)
// Chain: internalLimiter → internalAuth (inside router)
// Separate prefix prevents collision with /api/v1/users.
// ─────────────────────────────────────────────
app.use('/api/internal/users', internalLimiter, internalUserRouter);

// ─────────────────────────────────────────────
// ERROR HANDLING
// ─────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

export default app;