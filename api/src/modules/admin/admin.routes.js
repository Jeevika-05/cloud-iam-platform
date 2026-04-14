import { Router } from 'express';
import * as adminController from './admin.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { authorizeRoles } from '../../shared/middleware/authorizeRoles.js';

const router = Router();

router.use(authenticate);

router.get(
  '/pending-users',
  authorizeRoles('ADMIN'),
  adminController.getPendingUsers
);

router.get(
  '/pending-count',
  authorizeRoles('ADMIN'),
  adminController.getPendingCount
);

// Only ADMIN can approve/reject users
router.post(
  '/approve-user',
  authorizeRoles('ADMIN'),
  adminController.approveUser
);

router.post(
  '/reject-user',
  authorizeRoles('ADMIN'),
  adminController.rejectUser
);

export default router;
