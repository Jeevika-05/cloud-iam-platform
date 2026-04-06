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
 *   - Logs every denial for SIEM pipeline.
 *   - Increments Prometheus RBAC counters on ALLOW and DENY:
 *       iam_rbac_allowed_total { role, permission, route }
 *       iam_rbac_denied_total  { role, permission, route }
 *   - Throws at import time if called with zero or unknown permissions.
 *
 * Label cardinality note:
 *   - role:       3 values  (ADMIN | SECURITY_ANALYST | USER)
 *   - permission: bounded by PERMISSIONS constant (currently ~20)
 *   - route:      normalised Express path pattern (not raw URL — no userId bleed)
 *
 * Integration with existing middleware:
 *   authenticate → authorizeRoles → requirePermission() → authorizePolicy() → handler
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
import { authorizationFailures, rbacAllowedTotal, rbacDeniedTotal } from '../../metrics/metrics.js';
import { ROLE_PERMISSIONS } from '../rbac/rolePermissions.js';
import { PERMISSIONS } from '../rbac/permissions.js';

// Pre-compute the valid permission set once at module load
const VALID_PERMISSIONS = new Set(Object.values(PERMISSIONS));

/**
 * Normalise a route path for use as a Prometheus label.
 * Uses the Express matched route pattern (req.route.path) so that
 * /users/123 and /users/456 both collapse to /users/:id.
 * Falls back to req.path (without query string) if route not yet resolved.
 *
 * @param {import('express').Request} req
 * @returns {string}
 */
const normaliseRoute = (req) => {
  if (req.route && req.route.path) {
    // Prefix with baseUrl so /api/v1/users/:id is readable
    return (req.baseUrl || '') + req.route.path;
  }
  // Fallback: strip query string, keep path only
  return req.path || 'unknown';
};

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
      const route = normaliseRoute(req);

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

        // 📊 RBAC OBSERVABILITY: increment denied counter per missing permission
        // One increment per missing permission to keep label values low-cardinality.
        // role: ADMIN|SECURITY_ANALYST|USER (3 values)
        // permission: bounded set (~20 values)
        // route: Express pattern — no userId/IP bleed
        missingPerms.forEach((permission) => {
          rbacDeniedTotal.inc({ role: userRole, permission, route });
        });

        authorizationFailures.inc({ type: 'permission' });

        throw new AppError(
          `Access denied. Missing permission(s): ${missingPerms.join(', ')}. ` +
          `Your role (${userRole}) does not grant this access.`,
          403,
          'FORBIDDEN'
        );
      }

      // 4. All permissions satisfied — increment allowed counter and pass control
      // One increment per required permission so per-permission grant rates are observable.
      requiredPermissions.forEach((permission) => {
        rbacAllowedTotal.inc({ role: userRole, permission, route });
      });

      next();

    } catch (err) {
      next(err);
    }
  };
};
