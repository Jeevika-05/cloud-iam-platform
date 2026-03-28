import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import { evaluatePolicy } from '../auth/policyEngine.js';

export const authorizePolicy = ({ action, resource, getResource }) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError(
          'Authentication required before authorization',
          401,
          'AUTH_REQUIRED'
        );
      }

      // Build context object
      const context = {
        ip: req.ip,
        userAgent: req.headers['user-agent']
      };

      // Fetch resource data dynamically if a fetcher is provided
      let resourceData = null;
      if (typeof getResource === 'function') {
        resourceData = await getResource(req);
      }

      // Call policy engine
      const isAllowed = evaluatePolicy({
        user: req.user,
        action,
        resource,
        resourceData,
        context
      });

      if (!isAllowed) {
        logger.warn('ABAC_DENIED', {
          userId: req.user.id,
          action,
          resource,
          path: req.originalUrl,
          ip: req.ip
        });

        throw new AppError('Access denied by policy constraint', 403, 'FORBIDDEN');
      }

      next();
    } catch (err) {
      next(err);
    }
  };
};
