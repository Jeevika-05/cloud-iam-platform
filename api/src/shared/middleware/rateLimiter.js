import { extractClientInfo, getClientIp } from '../utils/clientInfo.js';
import logger from '../utils/logger.js';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import redisClient from '../config/redis.js';
import { verifyTempToken } from '../utils/jwt.js';
import { rateLimitCounter } from '../../metrics/metrics.js';
import { app as appConfig } from '../config/index.js';

function getRateLimitKey(req) {
  return (
    req.headers['x-attack-id']?.toString() ||
    req.user?.id ||
    req.body?.email ||
    extractClientInfo(req).ip
  );
}

export const apiLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: appConfig.isProduction ? 100 : 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests' },
  keyGenerator: (req) => getRateLimitKey(req),
  handler: (req, res, next, options) => {
    rateLimitCounter.inc({ type: 'api' });
    res.setHeader('X-RateLimit-Error', 'Too many requests');
    res.status(options.statusCode).json(options.message);
  },
});

export const authLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests' },
  keyGenerator: (req) => getRateLimitKey(req),
  handler: (req, res, next, options) => {
    rateLimitCounter.inc({ type: 'auth' });
    res.setHeader('X-RateLimit-Error', 'Too many requests');
    res.status(options.statusCode).json(options.message);
  },
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
    const defaultKey = getRateLimitKey(req);

    try {
      const tempToken = req.body?.tempToken;
      if (!tempToken) return `mfa-ip:${defaultKey}`;

      const decoded = verifyTempToken(tempToken);

      // per-user limiter (prevents distributed MFA attacks)
      // Allow attack-id to override even here to isolate separate simulated attacks
      return `mfa:${req.headers['x-attack-id'] || decoded.sub}`;
    } catch {
      return `mfa-ip:${defaultKey}`;
    }
  },
  message: {
    success: false,
    code: 'MFA_RATE_LIMITED',
    message: 'Too many MFA attempts. Please try again later.',
  },
  handler: (req, res, next, options) => {
    let type = 'mfa_ip';
    try {
      const tempToken = req.body?.tempToken;
      if (tempToken) {
        verifyTempToken(tempToken);
        type = 'mfa_user';
      }
    } catch {
      // ignore and leave as mfa_ip
    }
    rateLimitCounter.inc({ type });
    res.setHeader('X-RateLimit-Error', 'Too many requests');
    res.status(options.statusCode).json(options.message);
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
    rateLimitCounter.inc({ type: 'internal' });
    // 🔒 SEC-16: Use structured logger instead of console.log
    logger.warn('INTERNAL_RATE_LIMITED', { ip: extractClientInfo(req).ip, path: req.originalUrl });
    res.setHeader('X-RateLimit-Error', 'Too many requests');
    res.status(options.statusCode).json(options.message);
  },
  message: {
    success: false,
    code: 'INTERNAL_RATE_LIMITED',
    message: 'Too many internal requests. Please try again later.',
  },
});

