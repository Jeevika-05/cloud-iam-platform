import { extractClientInfo } from '../utils/clientInfo.js';
import logger from '../utils/logger.js';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import jwt from 'jsonwebtoken';
import redisClient from '../config/redis.js';

export const apiLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 100 : 50,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractClientInfo(req).ip,
});

export const authLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyGenerator: (req) => `${extractClientInfo(req).ip}-${req.body?.email || 'anonymous'}`,
});

// 🔐 SECURITY FIX: Strict MFA rate limiting to prevent TOTP brute-force
export const mfaLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    if (req.body?.tempToken) {
      try {
        const decoded = jwt.verify(req.body.tempToken, process.env.JWT_SECRET);
        if (decoded?.sub) return `mfa-${decoded.sub}`;
      } catch {
        // fall through to IP-based key
      }
    }
    return `mfa-${extractClientInfo(req).ip}`;
  },
  message: {
    success: false,
    code: 'MFA_RATE_LIMITED',
    message: 'Too many MFA attempts. Please try again later.',
  },
});

// ─────────────────────────────────────────────
// INTERNAL LIMITER — service-to-service routes only
// Applied to /api/internal/* BEFORE internalAuth.
// 50 requests per 15 minutes, keyed by IP.
// ─────────────────────────────────────────────
export const internalLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractClientInfo(req).ip,
  handler: (req, res, next, options) => {
    // 🔒 SEC-16: Use structured logger instead of console.log
    logger.warn('INTERNAL_RATE_LIMITED', { ip: extractClientInfo(req).ip, path: req.originalUrl });
    res.status(options.statusCode).send(options.message);
  },
  message: {
    success: false,
    code: 'INTERNAL_RATE_LIMITED',
    message: 'Too many internal requests. Please try again later.',
  },
});

