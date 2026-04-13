import { PrismaClient } from '@prisma/client';
import logger from '../utils/logger.js';

// ─────────────────────────────────────────────
// Prisma Singleton — Lazy Initialization
// ─────────────────────────────────────────────
// PrismaClient reads `env("DATABASE_URL")` from the process environment at
// construction time. In Docker, DATABASE_URL lives in /run/secrets (file mount)
// and is resolved by config/index.js via the SecretProvider — which deliberately
// does NOT pollute process.env.
//
// To bridge this gap we expose `initPrisma(url)` which must be called once
// (after config is loaded) before any query. Every other module just
// `import prisma from './database.js'` and uses the proxy — the first access
// transparently delegates to the real client.
// ─────────────────────────────────────────────

let _client = null;

/**
 * Initialize the PrismaClient singleton with a datasource URL.
 * MUST be called exactly once, before any Prisma query.
 *
 * @param {string} databaseUrl - Full PostgreSQL connection string
 * @returns {PrismaClient}
 */
export function initPrisma(databaseUrl) {
  if (_client) return _client;

  _client = new PrismaClient({
    datasourceUrl: databaseUrl,
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
    _client.$on('query', (e) => {
      logger.debug('PRISMA_QUERY', {
        query: e.query,
        duration: `${e.duration}ms`,
      });
    });
  }

  // ─────────────────────────────────────────────
  // Error logging
  // ─────────────────────────────────────────────
  _client.$on('error', (e) => {
    logger.error('PRISMA_ERROR', {
      message: e.message,
    });
  });

  // ─────────────────────────────────────────────
  // Warn logging
  // ─────────────────────────────────────────────
  _client.$on('warn', (e) => {
    logger.warn('PRISMA_WARN', {
      message: e.message,
    });
  });

  // Store globally (prevents multiple instances in dev)
  if (process.env.NODE_ENV !== 'production') {
    global.__prisma = _client;
  }

  return _client;
}

/**
 * Returns the initialized PrismaClient.
 * Throws if called before initPrisma().
 */
export function getPrisma() {
  if (!_client) {
    throw new Error(
      'Prisma has not been initialized. Call initPrisma(databaseUrl) first.'
    );
  }
  return _client;
}

// ─────────────────────────────────────────────
// Default export: Proxy that defers to the real
// client — keeps `import prisma from '...'` working
// everywhere without changing call sites.
// ─────────────────────────────────────────────
const prisma = new Proxy(
  {},
  {
    get(_target, prop) {
      // Restore dev-global if available (HMR scenario)
      if (!_client && global.__prisma) {
        _client = global.__prisma;
      }
      if (!_client) {
        throw new Error(
          `Prisma not initialized — attempted to access prisma.${String(prop)} before initPrisma() was called.`
        );
      }
      return Reflect.get(_client, prop, _client);
    },
  }
);

export default prisma;