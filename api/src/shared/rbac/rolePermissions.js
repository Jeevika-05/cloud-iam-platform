/**
 * rolePermissions.js
 * ─────────────────────────────────────────────────────────────
 * Maps each role to its set of granted permissions.
 *
 * Design decisions:
 *   - Uses Set for O(1) lookups during request processing.
 *   - Frozen objects prevent runtime mutation.
 *   - No role hierarchy here — permissions are explicit per role.
 *     ADMIN gets all permissions listed, not inherited via chain.
 *     This is intentional: explicit > implicit for security systems.
 *
 * To add a new role (e.g., AUDITOR):
 *   1. Add the role to the Prisma Role enum in schema.prisma
 *   2. Add the role entry below with its permission Set
 *   3. No route files need to change — routes check permissions,
 *      not roles.
 * ─────────────────────────────────────────────────────────────
 */

import { PERMISSIONS as P } from './permissions.js';

export const ROLE_PERMISSIONS = Object.freeze({
  // ─────────────────────────────────────────────
  // ADMIN — Full platform access
  // ─────────────────────────────────────────────
  ADMIN: new Set([
    // User management
    P.USERS_LIST,
    P.USERS_READ,
    P.USERS_UPDATE_ROLE,
    P.USERS_DELETE,

    // Self-service (admins are also users)
    P.PROFILE_READ,
    P.PROFILE_UPDATE,
    P.SESSIONS_LIST_OWN,
    P.SESSIONS_REVOKE_OWN,

    // Analytics
    P.ANALYTICS_VIEW,
    P.ANALYTICS_INTERNAL,

    // Audit
    P.AUDIT_VIEW_EVENTS,
    P.AUDIT_VIEW_DEFENSE,
    P.AUDIT_DEBUG,

    // Security operations
    P.DEFENSE_MANAGE,
    P.METRICS_VIEW,

    // Sensitive (still requires MFA via ABAC)
    P.SENSITIVE_MODIFY,
    P.SENSITIVE_DELETE,
  ]),

  // ─────────────────────────────────────────────
  // SECURITY_ANALYST — Read-only security operations
  // ─────────────────────────────────────────────
  SECURITY_ANALYST: new Set([
    // Can read all users (not modify)
    P.USERS_READ,

    // Self-service
    P.PROFILE_READ,
    P.PROFILE_UPDATE,
    P.SESSIONS_LIST_OWN,
    P.SESSIONS_REVOKE_OWN,

    // Analytics — core analyst function
    P.ANALYTICS_VIEW,

    // Audit — read events for investigation
    P.AUDIT_VIEW_EVENTS,

    // Metrics — view Prometheus dashboards
    P.METRICS_VIEW,
  ]),

  // ─────────────────────────────────────────────
  // USER — Self-service only
  // ─────────────────────────────────────────────
  USER: new Set([
    P.PROFILE_READ,
    P.PROFILE_UPDATE,
    P.SESSIONS_LIST_OWN,
    P.SESSIONS_REVOKE_OWN,
  ]),
});

/**
 * Helper: check if a role has a specific permission.
 *
 * @param {string} role       — User role (e.g., 'ADMIN')
 * @param {string} permission — Permission key (e.g., 'users:list')
 * @returns {boolean}
 */
export const roleHasPermission = (role, permission) => {
  const perms = ROLE_PERMISSIONS[role?.toUpperCase()];
  return perms ? perms.has(permission) : false;
};
