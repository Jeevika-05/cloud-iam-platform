import { Router } from 'express';
import * as authController from './auth.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { authorizePolicy } from '../../shared/middleware/authorizePolicy.js';
import * as authService from './auth.service.js';
import { authLimiter, mfaLimiter, apiLimiter } from '../../shared/middleware/rateLimiter.js';
import { validate, registerRules, loginRules, sessionIdParamRule } from '../../shared/middleware/validate.js';
import { requireCsrf } from '../../shared/middleware/requireCsrf.js';

const router = Router();

// ─────────────────────────────────────────────
// ─────────────────────────────────────────────
// Public routes — no authentication required
// ─────────────────────────────────────────────
router.get('/csrf', apiLimiter, authController.getCsrfToken);

router.post('/register', authLimiter, registerRules, validate, authController.register);

router.get('/google', authController.googleAuth);
router.get('/google/callback', authController.googleCallback);

router.post('/login', authLimiter, loginRules, validate, authController.login);

// SECURITY FIX: mfaLimiter (5 attempts/15min) replaces authLimiter to prevent TOTP brute-force
router.post('/mfa/validate-login', mfaLimiter, authController.validateMfaLogin);

// SEC-12: Rate-limit refresh endpoint (prevents token rotation abuse)
router.post('/refresh', authLimiter,  authController.refresh);

// ─────────────────────────────────────────────
// Protected routes
// Chain: authenticate → requirePermission → handler
// ─────────────────────────────────────────────

// Logout — revokes the current session
router.post(
  '/logout',
  authenticate,
  requirePermission('sessions:revoke_own'),
  requireCsrf,
  authController.logout
);

// Own profile read
router.get(
  '/profile',
  authenticate,
  apiLimiter,
  requirePermission('profile:read'),
  authorizePolicy({ action: 'read', resource: 'user', getResource: req => ({ id: req.user.id }) }),
  authController.getProfile
);

// Own profile update
router.patch(
  '/profile',
  authenticate,
  apiLimiter,
  requirePermission('profile:update'),
  requireCsrf,
  authorizePolicy({ action: 'update', resource: 'user', getResource: req => ({ id: req.user.id }) }),
  authController.updateProfile
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
  authorizePolicy({ action: 'read', resource: 'session', getResource: req => ({ userId: req.user.id }) }),
  authController.getSessions
);

// Get current session info
router.get(
  '/sessions/current',
  authenticate,
  requirePermission('sessions:list_own'),
  authorizePolicy({ action: 'read', resource: 'session', getResource: req => ({ userId: req.user.id }) }),
  authController.getCurrentSession
);

// Revoke a single session by ID
router.delete(
  '/sessions/:id',
  authenticate,
  requirePermission('sessions:revoke_own'),
  authorizePolicy({ 
    action: 'delete', 
    resource: 'session', 
    getResource: async (req) => {
      try {
        return await authService.getCurrentSession(req.params.id);
      } catch {
        return null;
      }
    }
  }),
  sessionIdParamRule,
  validate,
  authController.revokeSession
);

// Revoke all own sessions
router.delete(
  '/sessions',
  authenticate,
  requirePermission('sessions:revoke_own'),
  authorizePolicy({ action: 'delete', resource: 'session', getResource: req => ({ userId: req.user.id }) }),
  authController.revokeAllSessions
);

export default router;
