import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import prisma from '../config/database.js';
import { evaluatePolicy } from '../../modules/auth/policyEngine.js';

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

      // Hydrate Session for Advanced Zero Trust Checks
      let currentSession = null;
      if (req.auth?.jti) {
        currentSession = await prisma.session.findUnique({
          where: { id: req.auth.jti }
        });
        
        // Active Session Context Enforcement (ABAC Hard Deny)
        if (currentSession) {
          if (
            (currentSession.ipAddress && currentSession.ipAddress !== context.ip) ||
            (currentSession.userAgent && currentSession.userAgent !== context.userAgent)
          ) {
             logger.warn('ABAC_SESSION_HIJACK_DETECTED', { userId: req.user.id, ip: context.ip });
             throw new AppError('Anomalous contextual access blocked', 403, 'SESSION_COMPROMISED');
          }
        }
      }
      

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
