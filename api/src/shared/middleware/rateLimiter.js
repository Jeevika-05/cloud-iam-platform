import { extractClientInfo } from '../utils/clientInfo.js';
import logger from '../utils/logger.js';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import redisClient from '../config/redis.js';
import { verifyTempToken } from '../utils/jwt.js';
import { rateLimitCounter } from '../../metrics/metrics.js';
import { app as appConfig } from '../config/index.js';

function getRateLimitKey(req) {
  const ip = extractClientInfo(req).ip;
  if (req.user?.id) return req.user.id;

  // For login routes: combine IP + email so per-user limits apply
  // even when requests come from different IPs
  const email = req.body?.email?.toString().toLowerCase().trim();
  if (email) return `${ip}::${email}`;  // IP+email composite
  return ip;
}
export const perUserLoginLimiter = rateLimit({
  store: makeStore(),
  windowMs: 15 * 60 * 1000,
  max: 10,  // 10 failed attempts per user across all IPs
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const email = req.body?.email?.toString().toLowerCase().trim();
    return email ? `user_login:${email}` : `ip_login:${extractClientInfo(req).ip}`;
  },
  message: { success: false, code: 'RATE_LIMITED', message: 'Too many login attempts for this account.' },
  handler: (req, res, _next, options) => {
    rateLimitCounter.inc({ type: 'per_user_login' });
    res.status(options.statusCode).json(options.message);
  },
});

function makeStore() {
  return new RedisStore({ sendCommand: (...args) => redisClient.call(...args) });
}

// ─── Global API limiter — generous, catches only true abuse ───────────────────
// Applied at app level to ALL /api/v1/* routes.
// Per-route limiters below enforce tighter limits where it matters.
export const apiLimiter = rateLimit({
  store: makeStore(),
  windowMs: 15 * 60 * 1000,
  max: 300,                        // FIX: was 50 (dev) / 100 (prod) — too tight
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests' },
  keyGenerator: getRateLimitKey,
  skip: (req) => req.path === '/auth/csrf', // FIX: CSRF fetch must never be rate-blocked
  handler: (req, res, _next, options) => {
    rateLimitCounter.inc({ type: 'api' });
    res.setHeader('X-RateLimit-Error', 'Too many requests');
    res.status(options.statusCode).json(options.message);
  },
});

// ─── Auth limiter — applied only to login / register / refresh ────────────────
export const authLimiter = rateLimit({
  store: makeStore(),
  windowMs: 15 * 60 * 1000,
  max: 20,                         // FIX: was 100 — brute-force protection needs to be strict
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests' },
  keyGenerator: getRateLimitKey,
  handler: (req, res, _next, options) => {
    rateLimitCounter.inc({ type: 'auth' });
    res.setHeader('X-RateLimit-Error', 'Too many requests');
    res.status(options.statusCode).json(options.message);
  },
});

// ─── CSRF limiter — very generous, must never block normal traffic ─────────────
// FIX: dedicated limiter prevents CSRF fetch from being blocked by apiLimiter
export const csrfLimiter = rateLimit({
  store: makeStore(),
  windowMs: 60 * 1000,             // 1 minute window
  max: 30,                         // 30 CSRF fetches/min is more than enough
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractClientInfo(req).ip,
  handler: (req, res, _next, options) => {
    rateLimitCounter.inc({ type: 'csrf' });
    res.status(options.statusCode).json({ success: false, message: 'Too many requests' });
  },
});

// ─── MFA limiter — strict TOTP brute-force protection ────────────────────────
export const mfaLimiter = rateLimit({
  store: makeStore(),
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
      return `mfa:${decoded.sub}`;
    } catch {
      return `mfa-ip:${defaultKey}`;
    }
  },
  message: {
    success: false,
    code: 'MFA_RATE_LIMITED',
    message: 'Too many MFA attempts. Please try again later.',
  },
  handler: (req, res, _next, options) => {
    let type = 'mfa_ip';
    try {
      if (req.body?.tempToken) { verifyTempToken(req.body.tempToken); type = 'mfa_user'; }
    } catch { /* leave as mfa_ip */ }
    rateLimitCounter.inc({ type });
    res.setHeader('X-RateLimit-Error', 'Too many requests');
    res.status(options.statusCode).json(options.message);
  },
});

// ─── Internal service limiter ──────────────────────────────────────────────────
export const internalLimiter = rateLimit({
  store: makeStore(),
  windowMs: 15 * 60 * 1000,
  max: 50,                         // FIX: was 5 (comment said 50 — code was wrong)
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractClientInfo(req).ip,
  handler: (req, res, _next, options) => {
    rateLimitCounter.inc({ type: 'internal' });
    logger.warn('INTERNAL_RATE_LIMITED', { ip: extractClientInfo(req).ip, path: req.originalUrl });
    res.setHeader('X-RateLimit-Error', 'Too many requests');
    res.status(options.statusCode).json(options.message);
  },
  message: {
    success: false,
    code: 'INTERNAL_RATE_LIMITED',
    message: 'Too many internal requests.',
  },
});