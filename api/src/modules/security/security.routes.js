/**
 * ─────────────────────────────────────────────────────────────
 * SECURITY ROUTES — Attack Simulation API
 * ─────────────────────────────────────────────────────────────
 */

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import redisClient from '../../shared/config/redis.js';

import * as securityController from './security.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { authorizePolicy } from '../../shared/middleware/authorizePolicy.js';

const router = Router();

// ─────────────────────────────────────────────
// 🔒 Simulation-specific rate limiter (Redis)
// ─────────────────────────────────────────────
const simulationLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),

  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // max 10 simulations per hour per user

  keyGenerator: (req) => {
    // Fallback to IP if user is somehow missing
    if (req.user?.id) {
      const attackType = req.body?.type || 'unknown';
      return `sim:user:${req.user.id}:${attackType}`;
    }
    return `sim:ip:${req.ip}`;
  },

  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: 'Simulation rate limit exceeded. Max 10/hour.',
  },
});

// ─────────────────────────────────────────────
// 🔐 Global security middleware (applies to all)
// ─────────────────────────────────────────────
router.use(authenticate);
router.use(requirePermission('security:simulate'));
router.use(authorizePolicy({ action: 'simulate', resource: 'security' }));

// ─────────────────────────────────────────────
// GET /attacks
// List available attack types
// ─────────────────────────────────────────────
router.get('/attacks', securityController.getAttackTypes);

// ─────────────────────────────────────────────
// POST /simulate
// Trigger attack simulation (rate limited)
// ─────────────────────────────────────────────
router.post(
  '/simulate',
  simulationLimiter, // ✅ critical: apply limiter here
  securityController.simulate
);

export default router;