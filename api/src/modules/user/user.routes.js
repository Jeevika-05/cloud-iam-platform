import { Router } from 'express';
import * as userController from './user.controller.js';
import * as userService from './user.service.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { authorizeRoles } from '../../shared/middleware/authorizeRoles.js';
import { authorizePolicy } from '../../shared/middleware/authorizePolicy.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { internalAuth } from '../../shared/middleware/internalAuth.js';
import { internalLimiter } from '../../shared/middleware/rateLimiter.js';
import {
  userIdParamRule,
  updateRoleRules,
  validate
} from '../../shared/middleware/validate.js';

const router = Router();

// ─────────────────────────────────────────────
// Global middlewares
// ─────────────────────────────────────────────
router.use(authenticate);


// ─────────────────────────────────────────────
// ADMIN only — list all users
// Chain: authenticate → authorizeRoles → requirePermission → authorizePolicy → handler
// ─────────────────────────────────────────────
router.get(
  '/',
  authorizeRoles('ADMIN'),
  requirePermission('users:list'),
  authorizePolicy({ action: 'read', resource: 'user' }),
  userController.getAllUsers
);

// ─────────────────────────────────────────────
// ADMIN + SECURITY_ANALYST — read a single user
// Chain: authenticate → authorizeRoles → requirePermission → authorizePolicy → validate → handler
//
// FIX: authorizeRoles('ADMIN', 'SECURITY_ANALYST') added.
// Previously only requirePermission guarded this route; the role guard
// was missing, breaking the canonical middleware chain pattern and
// bypassing the first defence-in-depth layer.
// ─────────────────────────────────────────────
router.get(
  '/:id',
  authorizeRoles('ADMIN', 'SECURITY_ANALYST'),
  requirePermission('users:read'),
  authorizePolicy({
    action: 'read',
    resource: 'user',
    getResource: async (req) => ({
      id: req.params.id
    })
  }),
  userIdParamRule,
  validate,
  userController.getUserById
);

// ─────────────────────────────────────────────
// ADMIN only — update a user's role
// Chain: authenticate → authorizeRoles → requirePermission → authorizePolicy → validate → handler
// ─────────────────────────────────────────────
router.patch(
  '/:id/role',
  authorizeRoles('ADMIN'),
  requirePermission('users:update_role'),
  authorizePolicy({ action: 'update', resource: 'user' }),
  userIdParamRule,
  updateRoleRules,
  validate,
  userController.updateUserRole
);

// ─────────────────────────────────────────────
// ADMIN only — delete a user
// Chain: authenticate → authorizeRoles → requirePermission → authorizePolicy → validate → handler
// ─────────────────────────────────────────────
router.delete(
  '/:id',
  authorizeRoles('ADMIN'),
  requirePermission('users:delete'),
  authorizePolicy({ action: 'delete', resource: 'user' }),
  userIdParamRule,
  validate,
  userController.deleteUser
);

export default router;

// ─────────────────────────────────────────────────────────────
// ⚠️  INTERNAL ROUTES — Zero Trust simulation
//     Protected by x-internal-token, NOT by authenticate.
//     These endpoints are for service-to-service calls only.
// ─────────────────────────────────────────────────────────────

// Internal-only router — separate from the authenticated router above
// so internalAuth is NEVER applied to existing public/authed routes.
const internalRouter = Router();

/**
 * GET /internal/users/:id
 *
 * Service-to-service only. Requires x-internal-token header.
 * Reuses getUserById from user service; only returns safe fields.
 */
internalRouter.get('/:id', internalLimiter, internalAuth, async (req, res, next) => {
  try {
    const user = await userService.getUserById(req.params.id);

    // Intentionally strip fields that should never leave the service boundary.
    // user.service.js already limits the select, but be explicit here.
    const safeUser = {
      id:        user.id,
      name:      user.name,
      email:     user.email,
      role:      user.role,
      createdAt: user.createdAt,
    };

    return res.status(200).json({
      success: true,
      data:    { user: safeUser },
    });
  } catch (err) {
    next(err);
  }
});

export { internalRouter };
