import prisma from '../config/database.js';
import logger from '../utils/logger.js';

export const logSecurityEvent = async ({ userId, action, status, ip, userAgent, metadata }) => {
  try {
    const metaJson = metadata ? JSON.parse(JSON.stringify(metadata)) : null;
    await prisma.auditLog.create({
      data: {
        userId,
        action,
        status,
        ip,
        userAgent,
        metadata: metaJson,
      },
    });
  } catch (error) {
    logger.error('Failed to write audit log', { error: error.message });
  }
};
