import { Router } from 'express';
import * as mfaController from './mfa.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';

const router = Router();

// All MFA routes require authentication first
router.use(authenticate);

// ─────────────────────────────────────────────
// MFA self-service routes
// Chain: authenticate (router.use) → requirePermission → handler
// All three roles (ADMIN, SECURITY_ANALYST, USER) have mfa:setup / mfa:verify.
// ─────────────────────────────────────────────

// Initiate MFA setup — generates TOTP secret and QR code
router.post('/setup', requirePermission('mfa:setup'), mfaController.setupMfa);

// Verify TOTP token — completes MFA setup or validates during login
router.post('/verify', requirePermission('mfa:verify'), mfaController.verifyMfa);

export default router;
