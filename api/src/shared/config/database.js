import { PrismaClient } from '@prisma/client';
import logger from '../utils/logger.js';

// ─────────────────────────────────────────────
// Prisma Singleton (IMPORTANT for serverless & dev)
// ─────────────────────────────────────────────
let prisma;

if (!global.prisma) {
  prisma = new PrismaClient({
    log: [
      { emit: 'event', level: 'error' },
      { emit: 'event', level: 'warn' },
      ...(process.env.NODE_ENV !== 'production'
        ? [{ emit: 'event', level: 'query' }]
        : []),
    ],
  });

  // ─────────────────────────────────────────────
  // Query logging (DEV ONLY)
  // ─────────────────────────────────────────────
  if (process.env.NODE_ENV !== 'production') {
    prisma.$on('query', (e) => {
      logger.debug('PRISMA_QUERY', {
        query: e.query,
        duration: `${e.duration}ms`,
      });
    });
  }

  // ─────────────────────────────────────────────
  // Error logging
  // ─────────────────────────────────────────────
  prisma.$on('error', (e) => {
    logger.error('PRISMA_ERROR', {
      message: e.message,
    });
  });

  // ─────────────────────────────────────────────
  // Warn logging
  // ─────────────────────────────────────────────
  prisma.$on('warn', (e) => {
    logger.warn('PRISMA_WARN', {
      message: e.message,
    });
  });

  // Store globally (prevents multiple instances)
  if (process.env.NODE_ENV !== 'production') {
    global.prisma = prisma;
  }
} else {
  prisma = global.prisma;
}

export default prisma;