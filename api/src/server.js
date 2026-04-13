import config from './shared/config/index.js';
import app from './app.js';
import prisma, { initPrisma } from './shared/config/database.js';
import logger from './shared/utils/logger.js';
import { initNeo4jDriver } from './shared/db/neo4j.js';
import { getSecretProvider } from './shared/providers/SecretProvider.js';

// ─── Initialize Prisma with secret-loaded DATABASE_URL ──────────────────────
// config/index.js resolves DATABASE_URL from Docker secrets at the top level.
// Prisma's schema.prisma env("DATABASE_URL") would fail in Docker where secrets
// are file-mounted, not env vars — so we inject via datasourceUrl override.
initPrisma(config.database.url);

const PORT = config.app.port;

// Warn (not throw) — internal routes will fail-secure but main service stays up
if (!config.internal.serviceToken) {
  logger.warn(
    '⚠️  INTERNAL_SERVICE_TOKEN is not set. ' +
    'Internal service-to-service routes will reject all requests.'
  );
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

    // Initialize Neo4j driver with password from SecretProvider
    const secretProvider = getSecretProvider();
    await initNeo4jDriver(secretProvider);
    logger.info('✅ Neo4j driver initialized');

    const server = app.listen(PORT, '0.0.0.0', () => {
      logger.info(`🚀 Server running on port ${PORT} [${config.app.nodeEnv}]`);
      logger.info(`🔐 JWT Algorithm: ${config.jwt.algorithm}`);
      logger.info(`🔑 Password Hashing: Argon2id`);
      logger.info(`🔒 AES Encryption: ${config.encryption.algorithm} (key v${config.encryption.activeKeyVersion})`);
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