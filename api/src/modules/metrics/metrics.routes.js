import { Router } from 'express';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { successResponse, errorResponse } from '../../shared/utils/response.js';
import { register } from '../../metrics/metrics.js';

const router = Router();

router.get(
  '/summary',
  authenticate,
  requirePermission('metrics:view'),
  async (req, res) => {
    try {
      // Get JSON structured metrics
      const metricsJSON = await register.getMetricsAsJSON();

      // Helper to sum all values for a given metric across all labels
      const extractMetric = (name) => {
        const metric = metricsJSON.find((m) => m.name === name);
        if (!metric || !metric.values) return 0;
        return metric.values.reduce((sum, v) => sum + (v.value || 0), 0);
      };

      const totalRequests = extractMetric('iam_requests_total');
      const failedLogins = extractMetric('login_failures_total');
      // Fallback 0 for activeSessions if not found
      const activeSessions = extractMetric('iam_active_sessions_current'); 
      const blockedIPs = extractMetric('iam_active_bans_current') || extractMetric('iam_ip_bans_total');

      return successResponse(
        res,
        {
          totalRequests,
          failedLogins,
          activeSessions,
          blockedIPs
        },
        'Metrics retrieved successfully',
        200,
        'METRICS_SUMMARY'
      );
    } catch (error) {
      return errorResponse(res, 'Failed to retrieve metrics summary', 500, 'METRICS_ERROR');
    }
  }
);

export default router;
