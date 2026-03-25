import { Router } from 'express';
import * as authController from '../controllers/auth.controller.js';
import authenticate from '../middleware/authenticate.js';
import {
  validate,
  registerRules,
  loginRules,
  refreshRules,
} from '../middleware/validate.js';

const router = Router();

// ─────────────────────────────────────────────
// Public routes
// ─────────────────────────────────────────────
router.post('/register', registerRules, validate, authController.register);

router.post('/login', loginRules, validate, authController.login);

router.post('/refresh', refreshRules, validate, authController.refresh);

// ─────────────────────────────────────────────
// Protected routes
// ─────────────────────────────────────────────
router.post('/logout', authenticate, authController.logout);

router.get('/profile', authenticate, authController.getProfile);

export default router;