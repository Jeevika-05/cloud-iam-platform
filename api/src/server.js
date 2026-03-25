import 'dotenv/config';
import app from './app.js';
import prisma from './config/database.js';
import logger from './utils/logger.js';

const PORT = process.env.PORT || 3000;

// Validate env
if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
  throw new Error('Missing required environment variables');
}

const shutdown = async (signal, server) => {
  logger.info(`${signal} received. Shutting down gracefully...`);

  server.close(async () => {
    logger.info('HTTP server closed.');

    try {
      await prisma.$disconnect();
      logger.info('Database disconnected.');
    } catch (err) {
      logger.error('Error during DB disconnect', {
        message: err.message,
        stack: err.stack,
      });
    }

    process.exit(0);
  });

  setTimeout(() => {
    logger.error('Forced shutdown after timeout.');
    process.exit(1);
  }, 10000);
};

const startServer = async () => {
  try {
    await prisma.$connect();
    logger.info('✅ Database connected');

    const server = app.listen(PORT, () => {
      logger.info(`🚀 Server running on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
    });

    process.on('SIGTERM', () => shutdown('SIGTERM', server));
    process.on('SIGINT', () => shutdown('SIGINT', server));

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled Rejection:', reason);
      shutdown('unhandledRejection', server);
    });

    process.on('uncaughtException', (err) => {
      logger.error('Uncaught Exception:', {
        message: err.message,
        stack: err.stack,
      });
      process.exit(1);
    });

  } catch (err) {
    logger.error('❌ Database connection failed', {
      message: err.message,
      stack: err.stack,
    });
    process.exit(1);
  }
};

startServer();