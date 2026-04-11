import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import { apiLimiter, internalLimiter } from './shared/middleware/rateLimiter.js';
import correlationId from './shared/middleware/correlationId.js';
import hpp from 'hpp';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { randomUUID } from 'crypto';

import config, { activeDefense as activeDefenseConfig } from './shared/config/index.js';

import authRoutes from './modules/auth/auth.routes.js';
import userRoutes, { internalRouter as internalUserRouter } from './modules/user/user.routes.js';
import analyticsRoutes from './modules/analytics/analytics.routes.js';
import mfaRoutes from './modules/auth/mfa.routes.js';
import auditRoutes from './modules/audit/audit.routes.js';
import rbacRoutes from './modules/rbac/rbac.routes.js';
import securityRoutes from './modules/security/security.routes.js';
import metricsRoutes from './modules/metrics/metrics.routes.js';
import graphRoutes from './modules/graph/graph.routes.js';
import { successResponse, errorResponse } from './shared/utils/response.js';

import { errorHandler, notFoundHandler } from './shared/middleware/errorHandler.js';
import { authenticate } from './shared/middleware/authenticate.js';
import logger from './shared/utils/logger.js';
import { register, requestCounter, httpResponseDuration, httpErrorRate } from './metrics/metrics.js';
import { activeDefenseMiddleware } from './shared/middleware/activeDefender.js';
import { internalAuth } from './shared/middleware/internalAuth.js';

const app = express();

// ─────────────────────────────────────────────
// TRUST PROXY
// ─────────────────────────────────────────────
// 🔒 SEC-05: Trust only 1 proxy hop (prevents X-Forwarded-For spoofing)
app.set('trust proxy', 1);

// ─────────────────────────────────────────────
// CORRELATION ID (for tracing and neo4j generation)
// ─────────────────────────────────────────────
app.use(correlationId);

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
    origin: config.app.corsOrigin,
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
    skip: () => config.app.nodeEnv === 'test',
  })
);

// ─────────────────────────────────────────────
// SAFE PATHS BYPASS (Health & Metrics)
// ─────────────────────────────────────────────
const safePaths = ['/metrics', '/health'];

app.use((req, res, next) => {
  if (safePaths.includes(req.path)) {
    if (req.method !== 'GET') {
      return errorResponse(res, 'Method Not Allowed', 405, 'METHOD_NOT_ALLOWED');
    }
  }
  next();
});

app.get('/health', (req, res) => {
  return successResponse(res, {
    status: 'ok',
    uptime: process.uptime()
  }, 'Service is healthy');
});

// 🔒 SEC-RBAC: Metrics endpoint restricted to internal service access only.
// Previously exposed without auth — attackers could read risk thresholds,
// ban counts, and system architecture from metric names and labels.
// Prometheus scraper must pass x-internal-token header.
app.get('/metrics', internalAuth, async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    res.send(await register.metrics());
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ─────────────────────────────────────────────
// ACTIVE DEFENSE — Ban enforcement layer (BEFORE rate limiter)
// When ON:  banned IPs rejected at edge → zero processing cost
// When OFF: system degrades to stateless per-request rejection
// ─────────────────────────────────────────────
if (activeDefenseConfig.enabled) {
  app.use(activeDefenseMiddleware);
  logger.info('ACTIVE_DEFENDER_ENABLED', { mode: 'adaptive_blocking' });
} else {
  logger.info('ACTIVE_DEFENDER_DISABLED', { mode: 'per_request_rejection_only' });
}

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────
app.use('/api/v1', apiLimiter);

// ─────────────────────────────────────────────
// GLOBAL REQUEST TRACKING (Prometheus)
// Tracks: request count, response time, error rate
// ─────────────────────────────────────────────
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const route = req.route ? (req.baseUrl + req.route.path) : 'unknown_route';
    const labels = { method: req.method, route, status: res.statusCode };

    // 1. Request count
    requestCounter.inc(labels);

    // 2. Response duration
    const durationNs = Number(process.hrtime.bigint() - start);
    httpResponseDuration.observe(labels, durationNs / 1e9);

    // 3. Error rate (4xx + 5xx)
    if (res.statusCode >= 400) {
      httpErrorRate.inc({
        ...labels,
        error_class: res.statusCode >= 500 ? 'server' : 'client',
      });
    }
  });
  next();
});


// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/mfa', mfaRoutes);
app.use('/api/v1/users', authenticate, userRoutes);
app.use('/api/v1/analytics', authenticate, analyticsRoutes);
app.use('/api/v1/audit', auditRoutes);
app.use('/api/v1/rbac', rbacRoutes);
app.use('/api/v1/security', securityRoutes);
app.use('/api/v1/metrics', metricsRoutes);
app.use('/api/v1/graph', graphRoutes);

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