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
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const rand = (max) => Math.floor(Math.random() * max);

const ATTACK_REGISTRY = {
  BRUTE_FORCE: {
    label: 'Brute Force Attack',
    group: 'Authentication',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;
      
      for (let i = 0; i < 5; i++) {
        await logSecurityEvent({
          userId,
          action: 'LOGIN_FAILED',
          status: 'FAILURE',
          ip: attackerIp,
          correlationId,
          severity: i >= 3 ? 'HIGH' : 'MEDIUM',
          event_type: 'ATTACK',
          metadata: {
            event_type: 'ATTACK',
            simulated: true,
            target_endpoint: '/api/v1/auth/login',
            agent_type: 'SIMULATED',
            step: i + 1,
            scenario: 'BRUTE_FORCE',
          },
        });
        await sleep(100);
      }
      return { correlationId, steps: 5, attackerIp };
    },
  },

  SESSION_HIJACK_CHAIN: {
    label: 'Session Hijack + Lateral Movement',
    group: 'Token',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;
      
      // Step 1: Token reuse detected
      await logSecurityEvent({
        userId, action: 'TOKEN_REUSE_DETECTED', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'CRITICAL',
        event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 1,
                    target_endpoint: '/api/v1/auth/refresh', agent_type: 'SIMULATED' },
      });
      await sleep(150);
      
      // Step 2-4: MFA brute force attempt from same IP
      for (let i = 0; i < 3; i++) {
        await logSecurityEvent({
          userId, action: 'MFA_FAILED', status: 'FAILURE',
          ip: attackerIp, correlationId, severity: 'HIGH',
          event_type: 'ATTACK',
          metadata: { event_type: 'ATTACK', simulated: true, step: 2 + i,
                      target_endpoint: '/api/v1/mfa/validate-login', agent_type: 'SIMULATED' },
        });
        await sleep(100);
      }
      
      // Step 5: Privilege escalation attempt
      await logSecurityEvent({
        userId, action: 'RBAC_ACCESS_DENIED', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'HIGH',
        event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 5,
                    target_endpoint: '/api/v1/users', agent_type: 'SIMULATED' },
      });
      
      return { correlationId, steps: 5, attackerIp };
    },
  },

  CREDENTIAL_STUFFING: {
    label: 'Credential Stuffing',
    group: 'Authentication',
    async execute(userId, correlationId) {
       const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;
       for (let i = 0; i < 4; i++) {
        await logSecurityEvent({
          userId, action: 'LOGIN_FAILED', status: 'FAILURE',
          ip: attackerIp, correlationId, severity: 'HIGH', event_type: 'ATTACK',
          metadata: { event_type: 'ATTACK', simulated: true, target_endpoint: '/api/v1/auth/login', agent_type: 'SIMULATED', step: i + 1, scenario: 'CREDENTIAL_STUFFING' }
        });
        await sleep(100);
      }
      return { correlationId, steps: 4, attackerIp };
    }
  },

  API_ABUSE: {
    label: 'API Abuse',
    group: 'API',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;
      for (let i = 0; i < 8; i++) {
        await logSecurityEvent({
          userId, action: 'ABAC_ACCESS_DENIED', status: 'FAILURE',
          ip: attackerIp, correlationId, severity: 'MEDIUM', event_type: 'ATTACK',
          metadata: { event_type: 'ATTACK', simulated: true, target_endpoint: '/api/v1/users', agent_type: 'SIMULATED', step: i + 1, scenario: 'API_ABUSE' }
        });
        await sleep(100);
      }
      return { correlationId, steps: 8, attackerIp };
    }
  },

  // ─── NEW ATTACK TYPES (5–12) ──────────────────────────────────────────────

  TOKEN_FORGERY: {
    label: 'JWT Token Forgery',
    group: 'Token',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;

      // Step 1: Forged token detected
      await logSecurityEvent({
        userId, action: 'TOKEN_INVALID_SIGNATURE', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'CRITICAL', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 1,
                    target_endpoint: '/api/v1/auth/profile', agent_type: 'SIMULATED', scenario: 'TOKEN_FORGERY' },
      });
      await sleep(120);

      // Step 2: Algorithm confusion attempt
      await logSecurityEvent({
        userId, action: 'TOKEN_ALGORITHM_MISMATCH', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'CRITICAL', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 2,
                    target_endpoint: '/api/v1/auth/refresh', agent_type: 'SIMULATED', scenario: 'TOKEN_FORGERY' },
      });
      await sleep(120);

      // Step 3: Expired token replay
      await logSecurityEvent({
        userId, action: 'TOKEN_EXPIRED_REUSE', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'HIGH', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 3,
                    target_endpoint: '/api/v1/users', agent_type: 'SIMULATED', scenario: 'TOKEN_FORGERY' },
      });

      return { correlationId, steps: 3, attackerIp };
    },
  },

  PASSWORD_SPRAY: {
    label: 'Password Spray',
    group: 'Authentication',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;

      // Spray common passwords across multiple "user" targets
      const targets = ['admin@test.com', 'user@test.com', 'analyst@test.com', 'dev@test.com'];
      for (let i = 0; i < targets.length; i++) {
        await logSecurityEvent({
          userId, action: 'LOGIN_FAILED', status: 'FAILURE',
          ip: attackerIp, correlationId, severity: 'HIGH', event_type: 'ATTACK',
          metadata: { event_type: 'ATTACK', simulated: true, step: i + 1,
                      target_endpoint: '/api/v1/auth/login', agent_type: 'SIMULATED',
                      scenario: 'PASSWORD_SPRAY', target_email: targets[i] },
        });
        await sleep(150);
      }

      return { correlationId, steps: targets.length, attackerIp };
    },
  },

  RATE_LIMIT_BYPASS: {
    label: 'Rate Limit Bypass',
    group: 'API',
    async execute(userId, correlationId) {
      // Simulate rapid requests from rotating IPs to bypass rate limiting
      for (let i = 0; i < 5; i++) {
        const rotatedIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;
        await logSecurityEvent({
          userId, action: 'RATE_LIMIT_EXCEEDED', status: 'FAILURE',
          ip: rotatedIp, correlationId, severity: 'MEDIUM', event_type: 'ATTACK',
          metadata: { event_type: 'ATTACK', simulated: true, step: i + 1,
                      target_endpoint: '/api/v1/auth/login', agent_type: 'SIMULATED',
                      scenario: 'RATE_LIMIT_BYPASS', technique: 'ip_rotation' },
        });
        await sleep(80);
      }

      return { correlationId, steps: 5, attackerIp: 'multiple (rotating)' };
    },
  },

  PRIVILEGE_ESCALATION: {
    label: 'Privilege Escalation',
    group: 'Authorization',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;

      // Step 1: Attempt to access admin endpoint as USER
      await logSecurityEvent({
        userId, action: 'RBAC_ACCESS_DENIED', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'HIGH', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 1,
                    target_endpoint: '/api/v1/users', agent_type: 'SIMULATED', scenario: 'PRIVILEGE_ESCALATION' },
      });
      await sleep(100);

      // Step 2: Attempt to modify own role
      await logSecurityEvent({
        userId, action: 'ROLE_MODIFICATION_DENIED', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'CRITICAL', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 2,
                    target_endpoint: '/api/v1/users/self/role', agent_type: 'SIMULATED',
                    scenario: 'PRIVILEGE_ESCALATION', attempted_role: 'ADMIN' },
      });
      await sleep(100);

      // Step 3: Attempt to access security simulation
      await logSecurityEvent({
        userId, action: 'PERMISSION_DENIED', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'HIGH', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 3,
                    target_endpoint: '/api/v1/security/simulate', agent_type: 'SIMULATED',
                    scenario: 'PRIVILEGE_ESCALATION' },
      });

      return { correlationId, steps: 3, attackerIp };
    },
  },

  INJECTION_ATTACK: {
    label: 'Injection Attack',
    group: 'API',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;
      const payloads = [
        { target: '/api/v1/auth/login', type: 'SQL_INJECTION' },
        { target: '/api/v1/users?search=<script>', type: 'XSS' },
        { target: '/api/v1/auth/login', type: 'NOSQL_INJECTION' },
        { target: '/api/v1/audit/events?since=;DROP TABLE', type: 'SQL_INJECTION' },
      ];

      for (let i = 0; i < payloads.length; i++) {
        await logSecurityEvent({
          userId, action: 'INJECTION_DETECTED', status: 'FAILURE',
          ip: attackerIp, correlationId, severity: 'CRITICAL', event_type: 'ATTACK',
          metadata: { event_type: 'ATTACK', simulated: true, step: i + 1,
                      target_endpoint: payloads[i].target, agent_type: 'SIMULATED',
                      scenario: 'INJECTION_ATTACK', injection_type: payloads[i].type },
        });
        await sleep(100);
      }

      return { correlationId, steps: payloads.length, attackerIp };
    },
  },

  SESSION_FIXATION: {
    label: 'Session Fixation',
    group: 'Token',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;

      // Step 1: Pre-authenticated session injection
      await logSecurityEvent({
        userId, action: 'SESSION_FIXATION_DETECTED', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'HIGH', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 1,
                    target_endpoint: '/api/v1/auth/login', agent_type: 'SIMULATED',
                    scenario: 'SESSION_FIXATION' },
      });
      await sleep(120);

      // Step 2: Cookie injection attempt
      await logSecurityEvent({
        userId, action: 'COOKIE_TAMPERING_DETECTED', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'HIGH', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 2,
                    target_endpoint: '/api/v1/auth/refresh', agent_type: 'SIMULATED',
                    scenario: 'SESSION_FIXATION' },
      });
      await sleep(120);

      // Step 3: Session ID reuse after rotation
      await logSecurityEvent({
        userId, action: 'SESSION_REUSE_AFTER_ROTATION', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'CRITICAL', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 3,
                    target_endpoint: '/api/v1/auth/refresh', agent_type: 'SIMULATED',
                    scenario: 'SESSION_FIXATION' },
      });

      return { correlationId, steps: 3, attackerIp };
    },
  },

  RBAC_BYPASS: {
    label: 'RBAC Bypass',
    group: 'Authorization',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;
      const targets = [
        { endpoint: '/api/v1/rbac/roles', perm: 'users:list' },
        { endpoint: '/api/v1/security/simulate', perm: 'security:simulate' },
        { endpoint: '/api/v1/metrics/summary', perm: 'metrics:view' },
        { endpoint: '/api/v1/users', perm: 'users:delete' },
      ];

      for (let i = 0; i < targets.length; i++) {
        await logSecurityEvent({
          userId, action: 'RBAC_ACCESS_DENIED', status: 'FAILURE',
          ip: attackerIp, correlationId, severity: i >= 2 ? 'CRITICAL' : 'HIGH', event_type: 'ATTACK',
          metadata: { event_type: 'ATTACK', simulated: true, step: i + 1,
                      target_endpoint: targets[i].endpoint, agent_type: 'SIMULATED',
                      scenario: 'RBAC_BYPASS', required_permission: targets[i].perm },
        });
        await sleep(100);
      }

      return { correlationId, steps: targets.length, attackerIp };
    },
  },

  MFA_BYPASS: {
    label: 'MFA Bypass Attempt',
    group: 'Authentication',
    async execute(userId, correlationId) {
      const attackerIp = `10.${rand(255)}.${rand(255)}.${rand(255)}`;

      // Step 1: Brute force TOTP codes
      for (let i = 0; i < 3; i++) {
        await logSecurityEvent({
          userId, action: 'MFA_FAILED', status: 'FAILURE',
          ip: attackerIp, correlationId, severity: 'HIGH', event_type: 'ATTACK',
          metadata: { event_type: 'ATTACK', simulated: true, step: i + 1,
                      target_endpoint: '/api/v1/auth/mfa/validate-login', agent_type: 'SIMULATED',
                      scenario: 'MFA_BYPASS', technique: 'totp_bruteforce' },
        });
        await sleep(80);
      }

      // Step 4: Attempt to use tempToken directly without MFA
      await logSecurityEvent({
        userId, action: 'MFA_SKIP_ATTEMPT', status: 'FAILURE',
        ip: attackerIp, correlationId, severity: 'CRITICAL', event_type: 'ATTACK',
        metadata: { event_type: 'ATTACK', simulated: true, step: 4,
                    target_endpoint: '/api/v1/auth/profile', agent_type: 'SIMULATED',
                    scenario: 'MFA_BYPASS', technique: 'token_without_mfa' },
      });

      return { correlationId, steps: 4, attackerIp };
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
    const attackResult = await attack.execute(userId, correlationId);

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
        steps: attackResult?.steps,
        attackIp: attackResult?.attackerIp
      },
    });

    attackSimulationCounter.inc({ type: normalizedType, status: 'success' });

    logger.info('ATTACK_SIMULATION_COMPLETE', { type: normalizedType, userId, correlationId });

    return {
      message: 'Simulation triggered successfully',
      attack: normalizedType,
      label: attack.label,
      group: attack.group,
      correlationId: correlationId,
      steps: attackResult?.steps,
      attackerIp: attackResult?.attackerIp
    };
  } catch (err) {
    attackSimulationCounter.inc({ type: normalizedType, status: 'failure' });
    logger.error('ATTACK_SIMULATION_FAILED', { type: normalizedType, userId, error: err.message, correlationId });
    throw err;
  }
};
