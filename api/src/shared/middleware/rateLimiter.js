import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';

export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 100 : 500,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyGenerator: (req) => `${req.ip}-${req.body?.email || 'anonymous'}`,
});

// 🔐 SECURITY FIX: Strict MFA rate limiting to prevent TOTP brute-force
export const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    try {
      const decoded = jwt.decode(req.body?.tempToken);
      if (decoded?.sub) return `mfa-${decoded.sub}`;
    } catch {
      // fall through to IP-based key
    }
    return `mfa-${req.ip}`;
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
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res, next, options) => {
    console.log('INTERNAL RATE LIMIT CHECK');
    res.status(options.statusCode).send(options.message);
  },
  message: {
    success: false,
    code: 'INTERNAL_RATE_LIMITED',
    message: 'Too many internal requests. Please try again later.',
  },
});

