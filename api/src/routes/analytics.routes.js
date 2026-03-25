import { Router } from 'express';
import authenticate from '../middleware/authenticate.js';
import authorize from '../middleware/authorize.js';
import prisma from '../config/database.js';
import { successResponse } from '../utils/response.js';
import logger from '../utils/logger.js';

const router = Router();

// ─────────────────────────────────────────────
// Apply security middleware
// ─────────────────────────────────────────────
router.use(authenticate);
router.use(authorize('ADMIN', 'ANALYST'));

// ─────────────────────────────────────────────
// GET /summary
// ─────────────────────────────────────────────
router.get('/summary', async (req, res, next) => {
  try {
    const [totalUsers, roleBreakdown] = await Promise.all([
      prisma.user.count(),

      prisma.user.groupBy({
        by: ['role'],
        _count: { role: true },
      }),
    ]);

    // Transform role data
    const roles = roleBreakdown.reduce((acc, item) => {
      acc[item.role] = item._count.role;
      return acc;
    }, {});

    // 🔐 Audit log (important for your project)
    logger.info('ANALYTICS_ACCESSED', {
      userId: req.user.id,
      role: req.user.role,
      ip: req.ip,
      path: req.originalUrl,
    });

    return successResponse(
      res,
      { totalUsers, roles },
      'Analytics summary retrieved'
    );

  } catch (err) {
    next(err);
  }
});

export default router;