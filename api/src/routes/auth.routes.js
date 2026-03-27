import { Router } from 'express';
import * as authController from '../controllers/auth.controller.js';
import { authenticate } from '../middleware/authenticate.js';
import { authLimiter } from '../middleware/rateLimiter.js';
import { validate, registerRules, loginRules, sessionIdParamRule } from '../middleware/validate.js';

const router = Router();

// ─────────────────────────────────────────────
// Public routes
// ─────────────────────────────────────────────
router.post('/register', authLimiter, registerRules, validate, authController.register);

router.post('/login', authLimiter, loginRules, validate, authController.login);

// Cookie-based refresh
router.post('/refresh', authController.refresh);

// ─────────────────────────────────────────────
// Protected routes
// ─────────────────────────────────────────────
router.post('/logout', authenticate, authController.logout);

router.get('/profile', authenticate, authController.getProfile);

// ─────────────────────────────────────────────
// Session management (IAM)
// ─────────────────────────────────────────────
router.get('/sessions', authenticate, authController.getSessions);

router.get('/sessions/current', authenticate, authController.getCurrentSession);

// Revoke single session
router.delete(
  '/sessions/:id',
  authenticate,
  sessionIdParamRule,
  validate,
  authController.revokeSession
);

// Revoke all sessions (🔥 important)
router.delete(
  '/sessions',
  authenticate,
  authController.revokeAllSessions
);

export default router;