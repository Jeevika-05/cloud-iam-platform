/**
 * ─────────────────────────────────────────────────────────────
 * SECURITY ROUTES — Attack Simulation API
 * ─────────────────────────────────────────────────────────────
 *
 * Base: /api/v1/security  (mounted in app.js)
 *
 * Routes:
 *   GET  /attacks   → list of supported attack types (no mutation)
 *   POST /simulate  → trigger a named simulation (mutates event stream)
 *
 * Security chain:
 *   authenticate → requirePermission('security:simulate') → handler
 *
 * Access: ADMIN only (security:simulate is not granted to other roles).
 *
 * Rate limiting: inherits the global apiLimiter applied in app.js.
 * Consider adding a simulation-specific limiter (e.g. 5/hour) before
 * deploying to production to prevent simulation flooding.
 * ─────────────────────────────────────────────────────────────
 */

import { Router } from 'express';
import * as securityController from './security.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { authorizePolicy } from '../../shared/middleware/authorizePolicy.js';

const router = Router();

// Apply auth + RBAC to every route in this module
router.use(authenticate);
router.use(requirePermission('security:simulate'));
router.use(authorizePolicy({ action: 'simulate', resource: 'security' }));

// ─────────────────────────────────────────────
// GET /attacks
// Returns list of registered attack types.
// Frontend uses this to render buttons dynamically.
// ─────────────────────────────────────────────
router.get('/attacks', securityController.getAttackTypes);

// ─────────────────────────────────────────────
// POST /simulate
// Triggers a named attack simulation.
// Body: { type: "BRUTE_FORCE" }
// ─────────────────────────────────────────────
router.post('/simulate', securityController.simulate);

export default router;
