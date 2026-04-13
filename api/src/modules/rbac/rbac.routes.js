/**
 * ─────────────────────────────────────────────────────────────
 * RBAC API ROUTES — Exposes role/permission data for frontend
 * ─────────────────────────────────────────────────────────────
 *
 * Designed so the frontend can:
 *   1. Know which permissions the current user has (GET /me)
 *   2. Display role-appropriate UI elements without hardcoding
 *   3. Query available roles and their permissions (admin only)
 *
 * All routes require authentication (JWT).
 * ─────────────────────────────────────────────────────────────
 */

import { Router } from 'express';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { authorizePolicy } from '../../shared/middleware/authorizePolicy.js';
import { ROLE_PERMISSIONS, roleHasPermission } from '../../shared/rbac/rolePermissions.js';
import { PERMISSIONS } from '../../shared/rbac/permissions.js';
import { ROLES } from '../../shared/middleware/authorizeRoles.js';
import { successResponse, errorResponse } from '../../shared/utils/response.js';

const router = Router();

// All RBAC routes require authentication
router.use(authenticate);

// ─────────────────────────────────────────────
// GET /api/v1/rbac/me
// Returns the current user's role and permissions.
// Frontend uses this to conditionally render UI elements.
// ─────────────────────────────────────────────
router.get('/me', (req, res) => {
  const role = req.user.role?.toUpperCase();
  const permissions = ROLE_PERMISSIONS[role];

  return successResponse(res, {
    userId: req.user.id,
    role,
    permissions: permissions ? [...permissions] : [],
  }, 'Current user permissions retrieved');
});

// ─────────────────────────────────────────────
// GET /api/v1/rbac/check?permission=users:list
// Quick permission check for a specific permission.
// Returns { allowed: true/false } without throwing 403.
// ─────────────────────────────────────────────
router.get('/check', (req, res) => {
  const { permission } = req.query;

  if (!permission) {
    return errorResponse(res, 'Query parameter "permission" is required', 400, 'MISSING_PARAM');
  }

  const role = req.user.role?.toUpperCase();
  const allowed = roleHasPermission(role, permission);

  return successResponse(res, {
    permission,
    role,
    allowed,
  }, 'Permission check completed');
});

// ─────────────────────────────────────────────
// GET /api/v1/rbac/roles
// Returns all roles and their permissions (ADMIN only).
// ─────────────────────────────────────────────
router.get(
  '/roles',
  requirePermission('users:list'),
  authorizePolicy({ action: 'read', resource: 'rbac' }),
  (req, res) => {
    const roles = {};
    for (const [roleName, permSet] of Object.entries(ROLE_PERMISSIONS)) {
      roles[roleName] = [...permSet];
    }

    return successResponse(res, {
      roles,
      availableRoles: Object.values(ROLES),
      allPermissions: Object.values(PERMISSIONS),
    }, 'Roles and permissions retrieved');
  }
);

export default router;
