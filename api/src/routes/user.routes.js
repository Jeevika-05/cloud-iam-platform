import { Router } from 'express';
import * as userController from '../controllers/user.controller.js';
import authenticate from '../middleware/authenticate.js';
import authorize from '../middleware/authorize.js';
import {
  userIdParamRule,
  updateRoleRules,
  validate
} from '../middleware/validate.js';
import { apiLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// ─────────────────────────────────────────────
// Global middlewares
// ─────────────────────────────────────────────
router.use(authenticate);
router.use(apiLimiter);

// ─────────────────────────────────────────────
// ADMIN: full user management
// ─────────────────────────────────────────────
router.get(
  '/',
  authorize('ADMIN'),
  userController.getAllUsers
);

router.get(
  '/:id',
  authorize('ADMIN', 'ANALYST'),
  userIdParamRule,
  validate,
  userController.getUserById
);

router.patch(
  '/:id/role',
  authorize('ADMIN'),
  userIdParamRule,
  updateRoleRules,
  validate,
  userController.updateUserRole
);

router.delete(
  '/:id',
  authorize('ADMIN'),
  userIdParamRule,
  validate,
  userController.deleteUser
);

export default router;