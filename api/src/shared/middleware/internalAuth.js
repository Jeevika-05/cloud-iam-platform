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
import logger from '../utils/logger.js';

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
      ip:     req.ip,
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
      ip:     req.ip,
      path:   req.originalUrl,
    });
    return res.status(403).json({
      success: false,
      message: 'Forbidden: internal access only',
    });
  }

  // Token supplied but does not match
  if (provided !== INTERNAL_TOKEN) {
    logger.warn('INTERNAL_AUTH_FAILED', {
      reason: 'invalid_token',
      ip:     req.ip,
      path:   req.originalUrl,
    });
    return res.status(403).json({
      success: false,
      message: 'Forbidden: internal access only',
    });
  }

  next();
};
