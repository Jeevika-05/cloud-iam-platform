import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';

/**
 * Authorize middleware factory
 * Usage: authorize('ADMIN') or authorize('ADMIN', 'ANALYST')
 */
const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    try {
      // ─────────────────────────────────────────────
      // 1. Ensure authentication ran before
      // ─────────────────────────────────────────────
      if (!req.user) {
        throw new AppError('Authentication required', 401, 'AUTH_REQUIRED');
      }

      // ─────────────────────────────────────────────
      // 2. Validate role presence
      // ─────────────────────────────────────────────
      const userRole = req.user.role;

      if (!userRole) {
        throw new AppError('User role missing', 403, 'ROLE_MISSING');
      }

      // ─────────────────────────────────────────────
      // 3. Default deny (CRITICAL SECURITY PRINCIPLE)
      // ─────────────────────────────────────────────
      if (!allowedRoles.length) {
        throw new AppError('Access configuration error', 500, 'NO_ROLES_DEFINED');
      }

      if (!allowedRoles.includes(userRole)) {
        // 🔐 Log unauthorized access attempt
        logger.warn('AUTHZ_DENIED', {
          userId: req.user.id,
          role: userRole,
          allowedRoles,
          path: req.originalUrl,
          method: req.method,
          ip: req.ip,
        });

        throw new AppError(
          `Role '${userRole}' is not authorized for this resource`,
          403,
          'FORBIDDEN'
        );
      }

      // ─────────────────────────────────────────────
      // 4. Access granted
      // ─────────────────────────────────────────────
      next();

    } catch (err) {
      next(err);
    }
  };
};

export default authorize;