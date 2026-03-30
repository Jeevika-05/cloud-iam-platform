/**
 * internalAuth.js
 * ───────────────────────────────────────────────────────────
 * Zero Trust — internal service-to-service authentication.
 *
 * Validates the `x-internal-token` header against the
 * INTERNAL_SERVICE_TOKEN environment variable.
 *
 * ⚠️  Apply ONLY to internal routes. Do NOT use globally.
 * ───────────────────────────────────────────────────────────
 */
import crypto from 'crypto';
import logger from '../utils/logger.js';
import { extractClientInfo } from '../utils/clientInfo.js';

const INTERNAL_TOKEN = process.env.INTERNAL_SERVICE_TOKEN;

if (!INTERNAL_TOKEN) {
  logger.warn('INTERNAL_SERVICE_TOKEN_MISSING', {
    message:
      'INTERNAL_SERVICE_TOKEN is not set. ' +
      'Internal routes will reject all requests until it is configured.',
  });
}

/**
 * Middleware — validates internal service token.
 *
 * Logs INTERNAL_AUTH_FAILED with:
 *   - ip        caller IP
 *   - path      request path
 *   - reason    'missing_token' | 'invalid_token' | 'token_not_configured'
 *
 * ⚠️  The actual token value is NEVER logged.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export const internalAuth = (req, res, next) => {
  const provided = req.headers['x-internal-token'];

  // Reject if the env var itself is missing — fail secure
  if (!INTERNAL_TOKEN) {
    logger.warn('INTERNAL_AUTH_FAILED', {
      reason: 'token_not_configured',
      ip:     extractClientInfo(req).ip,
      path:   req.originalUrl,
    });
    return res.status(403).json({
      success: false,
      message: 'Forbidden: internal access only',
    });
  }

  // No token supplied in the request
  if (!provided) {
    logger.warn('INTERNAL_AUTH_FAILED', {
      reason: 'missing_token',
      ip:     extractClientInfo(req).ip,
      path:   req.originalUrl,
    });
    return res.status(403).json({
      success: false,
      message: 'Forbidden: internal access only',
    });
  }

  // 🔒 SEC-03: Timing-safe token comparison (prevents byte-by-byte brute force)
  const providedBuf = Buffer.from(provided);
  const expectedBuf = Buffer.from(INTERNAL_TOKEN);
  const isValid = providedBuf.length === expectedBuf.length &&
    crypto.timingSafeEqual(providedBuf, expectedBuf);

  if (!isValid) {
    logger.warn('INTERNAL_AUTH_FAILED', {
      reason: 'invalid_token',
      ip:     extractClientInfo(req).ip,
      path:   req.originalUrl,
    });
    return res.status(403).json({
      success: false,
      message: 'Forbidden: internal access only',
    });
  }

  next();
};
