import { Router } from 'express';
import * as mfaController from './mfa.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { apiLimiter, mfaLimiter } from '../../shared/middleware/rateLimiter.js';

const router = Router();

router.use(authenticate);

// Initiate MFA setup — generates TOTP secret and QR code
router.post('/setup', requirePermission('mfa:setup'), mfaController.setupMfa);

// Verify TOTP token — completes MFA setup or validates during login
router.post('/verify', mfaLimiter, requirePermission('mfa:verify'), mfaController.verifyMfa);

// Disable TOTP MFA — requires re-authentication (TOTP code or password in body)
// mfaLimiter guards against brute-forcing the re-auth credentials
router.delete('/', mfaLimiter, requirePermission('mfa:setup'), mfaController.disableMfa);

export default router;
