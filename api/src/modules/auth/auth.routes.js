import { Router } from 'express';
import * as authController from './auth.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { authLimiter, mfaLimiter, apiLimiter } from '../../shared/middleware/rateLimiter.js';
import { validate, registerRules, loginRules, sessionIdParamRule } from '../../shared/middleware/validate.js';

const router = Router();

// ─────────────────────────────────────────────
// Public routes — no authentication required
// ─────────────────────────────────────────────
router.post('/register', authLimiter, registerRules, validate, authController.register);

router.get('/google', authController.googleAuth);
router.get('/google/callback', authController.googleCallback);

router.post('/login', authLimiter, loginRules, validate, authController.login);

// 🔐 SECURITY FIX: mfaLimiter (5 attempts/15min) replaces authLimiter to prevent TOTP brute-force
router.post('/mfa/validate-login', mfaLimiter, authController.validateMfaLogin);

// 🔒 SEC-12: Rate-limit refresh endpoint (prevents token rotation abuse)
router.post('/refresh', authLimiter, authController.refresh);

// ─────────────────────────────────────────────
// Protected routes
// Chain: authenticate → requirePermission → handler
// ─────────────────────────────────────────────

// Logout — revokes the current session
router.post(
  '/logout',
  authenticate,
  requirePermission('sessions:revoke_own'),
  authController.logout
);

// Own profile read
router.get(
  '/profile',
  authenticate,
  apiLimiter,
  requirePermission('profile:read'),
  authController.getProfile
);

// ─────────────────────────────────────────────
// Session management (IAM)
// Chain: authenticate → requirePermission → [validate] → handler
// ─────────────────────────────────────────────

// List all own sessions
router.get(
  '/sessions',
  authenticate,
  requirePermission('sessions:list_own'),
  authController.getSessions
);

// Get current session info
router.get(
  '/sessions/current',
  authenticate,
  requirePermission('sessions:list_own'),
  authController.getCurrentSession
);

// Revoke a single session by ID
router.delete(
  '/sessions/:id',
  authenticate,
  requirePermission('sessions:revoke_own'),
  sessionIdParamRule,
  validate,
  authController.revokeSession
);

// Revoke all own sessions
router.delete(
  '/sessions',
  authenticate,
  requirePermission('sessions:revoke_own'),
  authController.revokeAllSessions
);

export default router;
