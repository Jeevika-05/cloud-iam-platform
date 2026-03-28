import { Router } from 'express';
import * as userController from '../controllers/user.controller.js';
import { authenticate } from '../middleware/authenticate.js';
import { authorizeRoles } from '../middleware/authorizeRoles.js';
import { authorizePolicy } from '../middleware/authorizePolicy.js';
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
  authorizePolicy({ action: 'read', resource: 'user' }),
  userController.getAllUsers
);

router.get(
  '/:id',
  authenticate,
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

router.patch(
  '/:id/role',
  authorizeRoles('ADMIN'),
  authorizePolicy({ action: 'update', resource: 'user' }),
  userIdParamRule,
  updateRoleRules,
  validate,
  userController.updateUserRole
);

router.delete(
  '/:id',
  authorizeRoles('ADMIN'),
  authorizePolicy({ action: 'delete', resource: 'user' }),
  userIdParamRule,
  validate,
  userController.deleteUser
);

export default router;
