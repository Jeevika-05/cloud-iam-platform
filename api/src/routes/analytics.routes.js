import { Router } from 'express';
import { authenticate } from '../middleware/authenticate.js';
import { authorizeRoles } from '../middleware/authorizeRoles.js';
import { authorizePolicy } from '../middleware/authorizePolicy.js';
import prisma from '../config/database.js';
import { successResponse } from '../utils/response.js';
import logger from '../utils/logger.js';

const router = Router();

// ─────────────────────────────────────────────
// Apply security middleware to every analytics route
// ─────────────────────────────────────────────
router.use(authenticate);
router.use(authorizeRoles('ADMIN', 'SECURITY_ANALYST'));

// ─────────────────────────────────────────────
// GET /summary
// ─────────────────────────────────────────────
router.get('/summary', authorizePolicy({ action: 'read', resource: 'analytics' }), async (req, res, next) => {
  try {
    const [totalUsers, roleBreakdown] = await Promise.all([
      prisma.user.count(),

      prisma.user.groupBy({
        by: ['role'],
        _count: { role: true },
      }),
    ]);

    const roles = roleBreakdown.reduce((acc, item) => {
      acc[item.role] = item._count.role;
      return acc;
    }, {});

    logger.info('ANALYTICS_ACCESSED', {
      userId: req.user.id,
      role:   req.user.role,
      ip:     req.ip,
      path:   req.originalUrl,
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
