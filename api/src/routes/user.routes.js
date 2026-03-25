import { Router } from 'express';
import * as userController from '../controllers/user.controller.js';
import authenticate from '../middleware/authenticate.js';
import authorize from '../middleware/authorize.js';
import { userIdParamRule, validate } from '../middleware/validate.js';

const router = Router();

// ─────────────────────────────────────────────
// All routes require authentication
// ─────────────────────────────────────────────
router.use(authenticate);

// ─────────────────────────────────────────────
// ADMIN: full user management
// ─────────────────────────────────────────────
router.get('/', authorize('ADMIN'), userController.getAllUsers);

router.get('/:id',
  userIdParamRule,
  validate,
  authorize('ADMIN', 'ANALYST'),
  userController.getUserById
);

router.patch('/:id/role',
  userIdParamRule,
  validate,
  authorize('ADMIN'),
  userController.updateUserRole
);

router.delete('/:id',
  userIdParamRule,
  validate,
  authorize('ADMIN'),
  userController.deleteUser
);

export default router;