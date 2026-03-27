/**
 * authorizeRoles.js
 * -----------------
 * Factory middleware for Role-Based Access Control (RBAC).
 *
 * Usage:
 *   import authorizeRoles from '../middleware/authorizeRoles.js';
 *
 *   router.get('/admin-only',  authenticate, authorizeRoles('ADMIN'),                   handler);
 *   router.get('/analysts',    authenticate, authorizeRoles('ADMIN','SECURITY_ANALYST'), handler);
 *
 * Contract:
 *   - Must run AFTER authenticate (req.user must be populated).
 *   - Returns 401 if req.user is missing (belt-and-suspenders guard).
 *   - Returns 403 with a structured JSON body for any role mismatch.
 *   - Logs every denial as a WARN so it surfaces in your SIEM/log pipeline.
 *   - Throws 500 if called with zero roles (configuration error, caught
 *     early in development rather than silently denying everyone).
 */

import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';

// ─────────────────────────────────────────────
// Allowed role universe — single source of truth.
// Keep in sync with the Prisma Role enum.
// ─────────────────────────────────────────────
export const ROLES = Object.freeze({
  USER:             'USER',
  ADMIN:            'ADMIN',
  SECURITY_ANALYST: 'SECURITY_ANALYST',
});

/**
 * @param  {...string} allowedRoles  One or more values from ROLES.
 * @returns Express middleware function.
 */
export const authorizeRoles = (...allowedRoles) => {
  // ── Fail-fast: catch misconfigured routes at startup / first request ──
  if (!allowedRoles.length) {
    throw new Error(
      '[authorizeRoles] No roles supplied. ' +
      'You must pass at least one role, e.g. authorizeRoles("ADMIN").'
    );
  }

  const unknownRoles = allowedRoles.filter(
    (r) => !Object.values(ROLES).includes(r)
  );
  if (unknownRoles.length) {
    throw new Error(
      `[authorizeRoles] Unknown role(s): ${unknownRoles.join(', ')}. ` +
      `Valid roles are: ${Object.values(ROLES).join(', ')}.`
    );
  }

  // ── Return the actual middleware ──
  return (req, res, next) => {
    try {
      // 1. Ensure authenticate() ran before this middleware
      if (!req.user) {
        throw new AppError(
          'Authentication required before authorization',
          401,
          'AUTH_REQUIRED'
        );
      }

      const userRole = req.user.role;

      // 2. Defensive: role field must be present on the user object
      if (!userRole) {
        throw new AppError(
          'User account has no role assigned',
          403,
          'ROLE_MISSING'
        );
      }

      // 3. Default-deny: check membership
      if (!allowedRoles.includes(userRole)) {
        logger.warn('RBAC_DENIED', {
          userId:       req.user.id,
          userRole,
          allowedRoles,
          method:       req.method,
          path:         req.originalUrl,
          ip:           req.ip,
          requestId:    req.id,           // set by app.js request-id middleware
        });

        throw new AppError(
          `Access denied. Required role(s): ${allowedRoles.join(' | ')}. ` +
          `Your role: ${userRole}.`,
          403,
          'FORBIDDEN'
        );
      }

      // 4. Access granted — pass control to the next handler
      next();

    } catch (err) {
      next(err);
    }
  };
};

