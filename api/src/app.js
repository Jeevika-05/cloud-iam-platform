import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import hpp from 'hpp';
import xss from 'xss';

import authRoutes from './routes/auth.routes.js';
import userRoutes from './routes/user.routes.js';
import analyticsRoutes from './routes/analytics.routes.js';

import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import authenticate from './middleware/authenticate.js';
import logger from './utils/logger.js';

const app = express();

// ── Trust proxy (important for rate limit + real IPs) ──
app.set('trust proxy', 1);

// ── Security headers ──
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

// ── CORS (STRICT) ──
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(','),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// ── Body parsing (DoS protection) ──
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ── Prevent parameter pollution ──
app.use(hpp());

// ── Prevent XSS (CUSTOM SANITIZER) ──
const sanitize = (obj) => {
  if (!obj) return obj;

  for (let key in obj) {
    if (typeof obj[key] === 'string') {
      obj[key] = xss(obj[key]);
    } else if (typeof obj[key] === 'object') {
      sanitize(obj[key]); // recursive for nested objects
    }
  }
  return obj;
};

app.use((req, res, next) => {
  if (req.body) sanitize(req.body);
  if (req.query) sanitize(req.query);
  if (req.params) sanitize(req.params);
  next();
});

// ── Request logging ──
app.use(
  morgan('combined', {
    stream: { write: (msg) => logger.http(msg.trim()) },
    skip: () => process.env.NODE_ENV === 'test',
  })
);

// ── Global rate limiting ──
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 100 : 500,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { success: false, message: 'Too many requests, please try again later.' },
});
app.use(globalLimiter);

// ── Auth-specific limiter ──
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}-${req.body.email || ''}`,
  message: { success: false, message: 'Too many auth attempts, please try again later.' },
});

// ── Health check ──
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV,
  });
});

// ── Routes ──
app.use('/api/v1/auth', authLimiter, authRoutes);
app.use('/api/v1/users', authenticate, userRoutes);
app.use('/api/v1/analytics', authenticate, analyticsRoutes);

// ── 404 + Error handlers ──
app.use(notFoundHandler);
app.use(errorHandler);

export default app;