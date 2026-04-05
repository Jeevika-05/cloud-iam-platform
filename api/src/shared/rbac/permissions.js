/**
 * permissions.js
 * ─────────────────────────────────────────────────────────────
 * Centralized permission constants for the IAM Security Platform.
 *
 * Naming convention:  resource:action
 *   resource = users, profile, sessions, analytics, audit, defense, metrics, sensitive
 *   action   = list, read, update, delete, manage, view, etc.
 *
 * These are the atomic capabilities that roles map to.
 * Routes consume these via requirePermission() middleware.
 *
 * To add a new permission:
 *   1. Add it here
 *   2. Map it to the appropriate role(s) in rolePermissions.js
 *   3. Apply it to the route via requirePermission()
 * ─────────────────────────────────────────────────────────────
 */

export const PERMISSIONS = Object.freeze({
  // ─────────────────────────────────────────────
  // User Management (ADMIN operations)
  // ─────────────────────────────────────────────
  USERS_LIST:          'users:list',
  USERS_READ:          'users:read',
  USERS_UPDATE_ROLE:   'users:update_role',
  USERS_DELETE:        'users:delete',

  // ─────────────────────────────────────────────
  // Own Profile & Sessions (self-service)
  // ─────────────────────────────────────────────
  PROFILE_READ:        'profile:read',
  PROFILE_UPDATE:      'profile:update',
  SESSIONS_LIST_OWN:   'sessions:list_own',
  SESSIONS_REVOKE_OWN: 'sessions:revoke_own',

  // ─────────────────────────────────────────────
  // Analytics
  // ─────────────────────────────────────────────
  ANALYTICS_VIEW:      'analytics:view',
  ANALYTICS_INTERNAL:  'analytics:internal_demo',

  // ─────────────────────────────────────────────
  // Audit Events
  // ─────────────────────────────────────────────
  AUDIT_VIEW_EVENTS:   'audit:view_events',
  AUDIT_VIEW_DEFENSE:  'audit:view_defense',
  AUDIT_DEBUG:         'audit:debug',

  // ─────────────────────────────────────────────
  // Security Operations & Defense
  // ─────────────────────────────────────────────
  DEFENSE_MANAGE:      'defense:manage',
  METRICS_VIEW:        'metrics:view',

  // ─────────────────────────────────────────────
  // Sensitive Operations (MFA-gated via ABAC)
  // ─────────────────────────────────────────────
  SENSITIVE_MODIFY:    'sensitive:modify',
  SENSITIVE_DELETE:    'sensitive:delete',
});
