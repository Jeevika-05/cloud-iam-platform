import { Router } from 'express';
import * as userController from '../controllers/user.controller.js';
import { authenticate } from '../middleware/authenticate.js';
import { authorizeRoles } from '../middleware/authorizeRoles.js';   // ← NEW
import {
  userIdParamRule,
  updateRoleRules,
  validate
} from '../middleware/validate.js';

const router = Router();

// ─────────────────────────────────────────────
// Global middlewares
// ─────────────────────────────────────────────
router.use(authenticate);


// ─────────────────────────────────────────────
// ADMIN only — full user management
// ─────────────────────────────────────────────
router.get(
  '/',
  authorizeRoles('ADMIN'),
  userController.getAllUsers
);

router.get(
  '/:id',
  authorizeRoles('ADMIN', 'SECURITY_ANALYST'),  // analysts can read individual users
  userIdParamRule,
  validate,
  userController.getUserById
);

router.patch(
  '/:id/role',
  authorizeRoles('ADMIN'),
  userIdParamRule,
  updateRoleRules,
  validate,
  userController.updateUserRole
);

router.delete(
  '/:id',
  authorizeRoles('ADMIN'),
  userIdParamRule,
  validate,
  userController.deleteUser
);

export default router;
