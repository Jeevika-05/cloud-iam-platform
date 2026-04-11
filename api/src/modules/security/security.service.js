/**
 * ─────────────────────────────────────────────────────────────
 * SECURITY SERVICE — Attack Simulation Engine
 * ─────────────────────────────────────────────────────────────
 *
 * Provides a registry of attack simulation types.
 * Each attack implements an execute() method that simulates the
 * corresponding threat by emitting realistic security events
 * into the existing audit + Redis stream pipeline.
 *
 * Attack types are data-driven: adding a new attack only requires
 * a new entry in ATTACK_REGISTRY — no frontend changes needed.
 *
 * Groups mirror the frontend SecuritySimulation.jsx GROUP_RULES:
 *   Authentication | Token | API | Authorization | Other
 *
 * DO NOT trigger real destructive operations here.
 * These are simulation events only — they exercise the detection
 * and defense pipeline without modifying production user data.
 * ─────────────────────────────────────────────────────────────
 */

import crypto from 'crypto';
import AppError from '../../shared/utils/AppError.js';
import logger from '../../shared/utils/logger.js';
import { logSecurityEvent } from '../auth/audit.service.js';
import { attackSimulationCounter } from '../../metrics/metrics.js';

// ─────────────────────────────────────────────
// SIMULATION HELPERS
// ─────────────────────────────────────────────

/**
 * Builds a base simulation event payload for logSecurityEvent.
 *
 * @param {object} opts
 * @param {string} opts.action       - Event action name
 * @param {string} opts.userId       - Triggering admin user ID
 * @param {string} opts.severity     - LOW | MEDIUM | HIGH | CRITICAL
 * @param {string} [opts.targetPath] - Simulated target endpoint
 */
const buildSimEvent = ({ action, userId, severity, targetPath = '/api/v1/auth/login' }) => ({
  userId,
  action,
  status: 'FAILURE',
  ip: `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
  userAgent: 'attack-engine/1.0 (simulation)',
  severity,
  event_type: 'ATTACK',
  metadata: {
    event_type: 'ATTACK',
    simulated: true,
    target_endpoint: targetPath,
    agent_type: 'SIMULATED',
  },
});

// ─────────────────────────────────────────────
// ATTACK REGISTRY
// Each entry: { label, group, execute(userId) }
// ─────────────────────────────────────────────
const ATTACK_REGISTRY = {
  // ── Authentication ────────────────────────────────────────────
  BRUTE_FORCE: {
    label: 'Brute Force Attack',
    group: 'Authentication',
    async execute(userId) {
      // Emit multiple rapid login failures from the same simulated IP
      for (let i = 0; i < 6; i++) {
        await logSecurityEvent(buildSimEvent({
          action: 'LOGIN_FAILED',
          userId,
          severity: 'HIGH',
          targetPath: '/api/v1/auth/login',
        }));
      }
    },
  },

  CREDENTIAL_STUFFING: {
    label: 'Credential Stuffing',
    group: 'Authentication',
    async execute(userId) {
      for (let i = 0; i < 5; i++) {
        await logSecurityEvent(buildSimEvent({
          action: 'LOGIN_FAILED',
          userId,
          severity: 'HIGH',
          targetPath: '/api/v1/auth/login',
        }));
      }
    },
  },

  PASSWORD_SPRAY: {
    label: 'Password Spray Attack',
    group: 'Authentication',
    async execute(userId) {
      await logSecurityEvent(buildSimEvent({
        action: 'LOGIN_FAILED',
        userId,
        severity: 'MEDIUM',
        targetPath: '/api/v1/auth/login',
      }));
    },
  },

  MFA_BRUTE_FORCE: {
    label: 'MFA Brute Force',
    group: 'Authentication',
    async execute(userId) {
      for (let i = 0; i < 4; i++) {
        await logSecurityEvent(buildSimEvent({
          action: 'MFA_FAILED',
          userId,
          severity: 'HIGH',
          targetPath: '/api/v1/mfa/validate-login',
        }));
      }
    },
  },

  // ── Token ─────────────────────────────────────────────────────
  TOKEN_REPLAY: {
    label: 'Token Replay Attack',
    group: 'Token',
    async execute(userId) {
      await logSecurityEvent(buildSimEvent({
        action: 'TOKEN_REUSE_DETECTED',
        userId,
        severity: 'CRITICAL',
        targetPath: '/api/v1/auth/refresh',
      }));
    },
  },

  JWT_TAMPERING: {
    label: 'JWT Tampering',
    group: 'Token',
    async execute(userId) {
      await logSecurityEvent(buildSimEvent({
        action: 'TOKEN_REUSE_DETECTED',
        userId,
        severity: 'CRITICAL',
        targetPath: '/api/v1/auth/refresh',
      }));
    },
  },

  SESSION_HIJACK: {
    label: 'Session Hijacking',
    group: 'Token',
    async execute(userId) {
      await logSecurityEvent(buildSimEvent({
        action: 'SUSPICIOUS_SESSION_DETECTED',
        userId,
        severity: 'CRITICAL',
        targetPath: '/api/v1/auth/refresh',
      }));
    },
  },

  // ── API ───────────────────────────────────────────────────────
  API_ABUSE: {
    label: 'API Abuse',
    group: 'API',
    async execute(userId) {
      for (let i = 0; i < 8; i++) {
        await logSecurityEvent(buildSimEvent({
          action: 'LOGIN_FAILED',
          userId,
          severity: 'MEDIUM',
          targetPath: '/api/v1/users',
        }));
      }
    },
  },

  RATE_LIMIT_BYPASS: {
    label: 'Rate Limit Bypass Attempt',
    group: 'API',
    async execute(userId) {
      for (let i = 0; i < 5; i++) {
        await logSecurityEvent(buildSimEvent({
          action: 'LOGIN_FAILED',
          userId,
          severity: 'MEDIUM',
          targetPath: '/api/v1/auth/login',
        }));
      }
    },
  },

  // ── Authorization ─────────────────────────────────────────────
  PRIVILEGE_ESCALATION: {
    label: 'Privilege Escalation',
    group: 'Authorization',
    async execute(userId) {
      await logSecurityEvent(buildSimEvent({
        action: 'RBAC_ACCESS_DENIED',
        userId,
        severity: 'HIGH',
        targetPath: '/api/v1/users',
      }));
    },
  },

  IDOR: {
    label: 'Insecure Direct Object Reference',
    group: 'Authorization',
    async execute(userId) {
      await logSecurityEvent(buildSimEvent({
        action: 'ABAC_ACCESS_DENIED',
        userId,
        severity: 'HIGH',
        targetPath: `/api/v1/users/${crypto.randomUUID()}`,
      }));
    },
  },

  // ── Other ─────────────────────────────────────────────────────
  SQL_INJECTION: {
    label: 'SQL Injection Attempt',
    group: 'Other',
    async execute(userId) {
      await logSecurityEvent(buildSimEvent({
        action: 'LOGIN_FAILED',
        userId,
        severity: 'CRITICAL',
        targetPath: '/api/v1/auth/login',
      }));
    },
  },

  OAUTH_ABUSE: {
    label: 'OAuth Token Abuse',
    group: 'Other',
    async execute(userId) {
      await logSecurityEvent(buildSimEvent({
        action: 'TOKEN_REUSE_DETECTED',
        userId,
        severity: 'HIGH',
        targetPath: '/api/v1/auth/google/callback',
      }));
    },
  },
};

// ─────────────────────────────────────────────
// EXPORTED: List available attack types
// Returns the metadata array the frontend renders dynamically.
// ─────────────────────────────────────────────
export const getAttackTypes = () => {
  return Object.entries(ATTACK_REGISTRY).map(([type, { label, group }]) => ({
    type,
    label,
    group,
  }));
};

// ─────────────────────────────────────────────
// EXPORTED: Execute a simulation
// ─────────────────────────────────────────────
export const runSimulation = async ({ type, userId, correlationId }) => {
  const normalizedType = (type || '').toString().toUpperCase().trim();
  const attack = ATTACK_REGISTRY[normalizedType];

  if (!attack) {
    throw new AppError("Invalid attack type", 400, "INVALID_ATTACK");
  }

  logger.info('ATTACK_SIMULATION_STARTED', {
    type: normalizedType,
    label: attack.label,
    userId,
    correlationId,
  });

  try {
    await attack.execute(userId);

    // Audit the simulation trigger itself
    await logSecurityEvent({
      userId,
      action: 'ATTACK_SIMULATION',
      status: 'SUCCESS',
      ip: null,
      userAgent: null,
      severity: 'LOW',
      correlationId,
      metadata: {
        event_type: 'SECURITY',
        simulated: true,
        attackType: normalizedType,
        attackLabel: attack.label,
        attackGroup: attack.group,
      },
    });

    attackSimulationCounter.inc({ type: normalizedType, status: 'success' });

    logger.info('ATTACK_SIMULATION_COMPLETE', { type: normalizedType, userId, correlationId });

    return {
      message: 'Simulation triggered successfully',
      attack: normalizedType,
      label: attack.label,
      group: attack.group,
    };
  } catch (err) {
    attackSimulationCounter.inc({ type: normalizedType, status: 'failure' });
    logger.error('ATTACK_SIMULATION_FAILED', { type: normalizedType, userId, error: err.message, correlationId });
    throw err;
  }
};
