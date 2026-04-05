/**
 * requirePermission.js
 * ─────────────────────────────────────────────────────────────
 * Factory middleware for Permission-Based Access Control.
 *
 * Usage:
 *   import { requirePermission } from '../middleware/requirePermission.js';
 *
 *   // Single permission
 *   router.get('/users', authenticate, requirePermission('users:list'), handler);
 *
 *   // Multiple permissions (ALL required — AND logic)
 *   router.delete('/user/:id', authenticate, requirePermission('users:delete', 'sensitive:delete'), handler);
 *
 * Contract:
 *   - Must run AFTER authenticate (req.user must be populated with DB role).
 *   - Returns 401 if req.user is missing (belt-and-suspenders guard).
 *   - Returns 403 with structured JSON for any permission mismatch.
 *   - Logs every denial for SIEM pipeline + increments Prometheus counter.
 *   - Throws at import time if called with zero or unknown permissions.
 *
 * Integration with existing middleware:
 *   authenticate → requirePermission() → authorizePolicy() → handler
 *
 *   requirePermission checks role-based permissions.
 *   authorizePolicy checks ABAC conditions (ownership, MFA, network).
 *   Both can coexist in the same middleware chain.
 * ─────────────────────────────────────────────────────────────
 */

import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import { extractClientInfo } from '../utils/clientInfo.js';
import { logSecurityEvent } from '../../modules/auth/audit.service.js';
import { authorizationFailures } from '../../metrics/metrics.js';
import { ROLE_PERMISSIONS } from '../rbac/rolePermissions.js';
import { PERMISSIONS } from '../rbac/permissions.js';

// Pre-compute the valid permission set once at module load
const VALID_PERMISSIONS = new Set(Object.values(PERMISSIONS));

/**
 * @param  {...string} requiredPermissions  One or more permission strings.
 *         If multiple are passed, ALL must be satisfied (AND logic).
 * @returns Express middleware function.
 */
export const requirePermission = (...requiredPermissions) => {
  // ── Fail-fast: catch misconfigured routes at startup / first import ──
  if (!requiredPermissions.length) {
    throw new Error(
      '[requirePermission] No permissions supplied. ' +
      'You must pass at least one permission, e.g. requirePermission("users:list").'
    );
  }

  const unknowns = requiredPermissions.filter(p => !VALID_PERMISSIONS.has(p));
  if (unknowns.length) {
    throw new Error(
      `[requirePermission] Unknown permission(s): ${unknowns.join(', ')}. ` +
      `Valid permissions are defined in src/shared/rbac/permissions.js.`
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

      // 2. Resolve the user's role and its permission set
      const userRole = req.user.role?.toUpperCase();

      if (!userRole) {
        throw new AppError(
          'User account has no role assigned',
          403,
          'ROLE_MISSING'
        );
      }

      const rolePerms = ROLE_PERMISSIONS[userRole];

      if (!rolePerms) {
        logger.warn('UNKNOWN_ROLE_IN_PERMISSION_CHECK', {
          userId: req.user.id,
          role: userRole,
          path: req.originalUrl,
        });
        throw new AppError(
          `Unknown role: ${userRole}`,
          403,
          'ROLE_UNKNOWN'
        );
      }

      // 3. Check ALL required permissions (AND logic)
      const missingPerms = requiredPermissions.filter(p => !rolePerms.has(p));

      if (missingPerms.length > 0) {
        const clientInfo = extractClientInfo(req);

        logger.warn('PERMISSION_DENIED', {
          userId:       req.user.id,
          role:         userRole,
          required:     requiredPermissions,
          missing:      missingPerms,
          method:       req.method,
          path:         req.originalUrl,
          ip:           clientInfo.ip,
          correlationId: req.correlationId,
        });

        // 📋 AUDIT: Persist permission denial for forensic analysis
        logSecurityEvent({
          userId: req.user.id,
          action: 'PERMISSION_DENIED',
          status: 'FAILURE',
          ip: clientInfo.ip,
          userAgent: clientInfo.userAgent,
          metadata: {
            role: userRole,
            requiredPermissions,
            missingPermissions: missingPerms,
            method: req.method,
            path: req.originalUrl,
          },
        });

        authorizationFailures.inc({ type: 'permission' });

        throw new AppError(
          `Access denied. Missing permission(s): ${missingPerms.join(', ')}. ` +
          `Your role (${userRole}) does not grant this access.`,
          403,
          'FORBIDDEN'
        );
      }

      // 4. All permissions satisfied — pass control
      next();

    } catch (err) {
      next(err);
    }
  };
};
