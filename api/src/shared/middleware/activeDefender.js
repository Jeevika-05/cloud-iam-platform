// ─────────────────────────────────────────────────────────────
// ACTIVE DEFENDER — Adaptive IP Defense Layer
// ─────────────────────────────────────────────────────────────
// Features:
//   • Sliding-window trust reset (strikes auto-decay via Redis TTL)
//   • Progressive ban escalation (10m → 1h → 24h)
//   • Safe IP allowlist (localhost, Docker internal, simulation)
//   • Prometheus iam_ip_bans_total counter
//   • Graceful Redis failure handling (never crashes API)
//   • Simulation-mode bypass (controlled by SIMULATION_MODE env)
// ─────────────────────────────────────────────────────────────

import crypto from 'crypto';
import redisClient from '../config/redis.js';
import logger from '../utils/logger.js';
import { getClientIp } from '../utils/clientInfo.js';
import { classifyIp } from '../utils/ipClassifier.js';
import { ipBanCounter } from '../../metrics/metrics.js';
import { activeDefense as activeDefenseConfig } from '../config/index.js';

// ─────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────
const STRIKE_THRESHOLD = 5;          // Strikes before ban triggers
const STRIKE_WINDOW_TTL = 300;       // 5 minutes (sliding window)
const BAN_DURATIONS = [600, 3600, 86400]; // 10m, 1h, 24h (seconds)

// Redis key prefixes
const STRIKE_KEY    = (ip) => `strike:ip:${ip}`;
const BAN_KEY       = (ip) => `ban:ip:${ip}`;
const BAN_META_KEY  = (ip) => `ban:meta:${ip}`;

// ─────────────────────────────────────────────
// SAFE IP ALLOWLIST
// ─────────────────────────────────────────────
const ALLOWLIST = new Set([
  '127.0.0.1',
  '::1',
  '::ffff:127.0.0.1',
  'localhost',
]);

// Docker internal IP ranges (172.16-31.x.x)
const INTERNAL_CIDRS = [
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
  /^::ffff:172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
];

// Simulation IP ranges — only active when SIMULATION_MODE=true
// Prevents simulation traffic from polluting real defense state
const SIMULATION_MODE = (process.env.SIMULATION_MODE || '').toLowerCase() === 'true';
const SIMULATION_CIDRS = [
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
];

/**
 * Check if an IP is in the safe allowlist.
 * Includes localhost, Docker internals, and (in simulation mode) test IPs.
 */
const isAllowlisted = (ip) => {
  if (!ip) return false;
  if (ALLOWLIST.has(ip)) return true;
  if (INTERNAL_CIDRS.some((cidr) => cidr.test(ip))) return true;
  // In simulation mode, skip strikes/bans for test IPs
  if (SIMULATION_MODE && SIMULATION_CIDRS.some((cidr) => cidr.test(ip))) return true;
  return false;
};

// ─────────────────────────────────────────────
// RECORD STRIKE (called by logSecurityEvent)
// ─────────────────────────────────────────────
/**
 * Records a security strike against an IP.
 * Uses Redis INCR + EXPIRE for sliding-window decay.
 * When strikes exceed threshold → triggers progressive ban.
 *
 * @param {string} ip                  - Client IP address
 * @param {string} severity            - Event severity (LOW, MEDIUM, HIGH, CRITICAL)
 * @param {string} reason              - Human-readable reason for the strike
 * @param {string} [triggeringEventId] - event_id of the event that caused this strike (for correlation)
 */
export const recordStrike = async (ip, severity = 'MEDIUM', reason = 'security_event', triggeringEventId = null) => {
  try {
    if (!activeDefenseConfig.enabled) return; // Toggle OFF → no behavioral memory
    if (!ip || isAllowlisted(ip)) return;

    const strikeKey = STRIKE_KEY(ip);

    // Sliding window: INCR strike count, reset TTL on each new strike
    const strikes = await redisClient.incr(strikeKey);
    await redisClient.expire(strikeKey, STRIKE_WINDOW_TTL);

    logger.debug('STRIKE_RECORDED', { ip, strikes, threshold: STRIKE_THRESHOLD, severity, reason });

    // Unified DEFENSE event — queued to Redis stream for async processing
    try {
      const event = {
        event_id: crypto.randomUUID(),
        correlation_id: triggeringEventId || crypto.randomUUID(),
        event_type: "DEFENSE",
        action: "STRIKE_RECORDED",
        source_ip: ip,
        ip_type: classifyIp(ip),
        user_agent: "active-defender",
        agent_type: "SYSTEM",
        target_type: "SYSTEM",
        target_endpoint: "strike-engine",
        result: "BLOCKED",
        reason: reason,
        strike_count: strikes,
        severity: "MEDIUM",
        timestamp: new Date().toISOString(),
        mode: activeDefenseConfig.enabled ? "AFTER_ACTIVE_DEFENDER" : "BEFORE_ACTIVE_DEFENDER"
      };
      
      await redisClient.xadd(
        'security_events',
        'MAXLEN', '~', '10000',
        '*',
        'data',
        JSON.stringify(event)
      );
    } catch (dbErr) {
      logger.error('Failed to pipe DEFENSE event to Redis stream', { error: dbErr.message });
    }

    if (strikes >= STRIKE_THRESHOLD) {
      await banIp(ip, severity, reason);
      // Reset strikes after ban is applied
      await redisClient.del(strikeKey);
    }
  } catch (err) {
    // 🛡️ Redis failures MUST NOT crash the API
    logger.error('STRIKE_RECORD_FAILED', { ip, error: err.message });
  }
};

// ─────────────────────────────────────────────
// PROGRESSIVE BAN ENGINE
// ─────────────────────────────────────────────
/**
 * Bans an IP with escalating duration based on ban history.
 * 1st ban → 10 minutes
 * 2nd ban → 1 hour
 * 3rd+ ban → 24 hours
 */
const banIp = async (ip, severity, reason) => {
  try {
    const banMetaKey = BAN_META_KEY(ip);
    const banKey = BAN_KEY(ip);

    // Get current ban count (persists across ban windows for escalation)
    const rawMeta = await redisClient.get(banMetaKey);
    let meta = rawMeta ? JSON.parse(rawMeta) : { count: 0, history: [] };

    const banIndex = Math.min(meta.count, BAN_DURATIONS.length - 1);
    const duration = BAN_DURATIONS[banIndex];

    // Update ban metadata
    meta.count += 1;
    meta.history.push({
      reason,
      severity,
      bannedAt: new Date().toISOString(),
      durationSeconds: duration,
    });

    // Store ban flag with TTL
    await redisClient.set(banKey, JSON.stringify({
      reason,
      severity,
      bannedAt: new Date().toISOString(),
      banNumber: meta.count,
      expiresIn: duration,
    }), 'EX', duration);

    // Store ban metadata (persist for 48h to track escalation across bans)
    await redisClient.set(banMetaKey, JSON.stringify(meta), 'EX', 172800);

    // 📊 Prometheus: Increment ban counter
    ipBanCounter.inc({ reason, severity });

    // Unified DEFENSE event — queued to Redis stream for async processing
    try {
      const event = {
        event_id: crypto.randomUUID(),
        correlation_id: crypto.randomUUID(),
        event_type: "DEFENSE",
        action: "IP_BANNED",
        source_ip: ip,
        ip_type: classifyIp(ip),
        user_agent: "active-defender",
        agent_type: "SYSTEM",
        target_type: "SYSTEM",
        target_endpoint: "ban-engine",
        result: "BANNED",
        total_strikes: meta.count * STRIKE_THRESHOLD,
        ban_duration: duration,
        ban_number: meta.count,
        severity: "HIGH",
        timestamp: new Date().toISOString(),
        mode: activeDefenseConfig.enabled ? "AFTER_ACTIVE_DEFENDER" : "BEFORE_ACTIVE_DEFENDER"
      };

      await redisClient.xadd(
        'security_events',
        'MAXLEN', '~', '10000',
        '*',
        'data',
        JSON.stringify(event)
      );
    } catch (dbErr) {
      logger.error('Failed to pipe IP_BANNED event to Redis stream', { error: dbErr.message });
    }

    const durationLabel = duration < 3600
      ? `${duration / 60}m`
      : `${duration / 3600}h`;

    logger.warn('IP_BANNED', {
      ip,
      reason,
      severity,
      banNumber: meta.count,
      duration: durationLabel,
      durationSeconds: duration,
    });
  } catch (err) {
    logger.error('BAN_IP_FAILED', { ip, error: err.message });
  }
};

// ─────────────────────────────────────────────
// CHECK BAN STATUS (middleware)
// ─────────────────────────────────────────────
/**
 * Express middleware: blocks requests from banned IPs.
 * Skips allowlisted IPs. Gracefully handles Redis failures.
 */
export const activeDefenseMiddleware = async (req, res, next) => {
  try {
    const ip = getClientIp(req);

    // Never block allowlisted IPs
    if (isAllowlisted(ip)) {
      return next();
    }

    const banKey = BAN_KEY(ip);
    const banData = await redisClient.get(banKey);

    if (banData) {
      let ban;
      try {
        ban = JSON.parse(banData);
      } catch (parseErr) {
        logger.error('BAN_DATA_PARSE_FAILED', { ip, error: parseErr.message });
        return next(); // fail-open on corrupted ban data
      }

      logger.warn('BLOCKED_BANNED_IP', {
        ip,
        reason: ban.reason,
        severity: ban.severity,
        banNumber: ban.banNumber,
      });

      try {
        const correlation_id = req.headers['x-correlation-id'] || crypto.randomUUID();
        const timestamp = new Date().toISOString();
        const mode = activeDefenseConfig.enabled ? "AFTER_ACTIVE_DEFENDER" : "BEFORE_ACTIVE_DEFENDER";
        const ip_type = classifyIp(ip, req.headers['user-agent']);
        const user_agent = req.headers['user-agent'] || "active-defender";

        // 1. Emit DEFENSE Event
        const defenseEvent = {
          event_id: crypto.randomUUID(),
          correlation_id,
          event_type: "DEFENSE",
          action: "BLOCKED_BANNED_IP",
          source_ip: ip,
          ip_type,
          user_agent,
          agent_type: "SYSTEM",
          target_type: "SYSTEM",
          target_endpoint: req.originalUrl || "ban-engine",
          result: "BLOCKED",
          reason: ban.reason,
          strike_count: ban.banNumber * STRIKE_THRESHOLD,
          severity: "HIGH",
          timestamp,
          mode
        };
        await redisClient.xadd('security_events', 'MAXLEN', '~', '10000', '*', 'data', JSON.stringify(defenseEvent));

        // 2. Emit ATTACK Event
        const attackEvent = {
          event_id: crypto.randomUUID(),
          correlation_id,
          event_type: "ATTACK",
          action: "BLOCKED_REQUEST",
          source_ip: ip,
          ip_type,
          user_agent,
          agent_type: "EXTERNAL",
          target_type: "API",
          target_endpoint: req.originalUrl,
          result: "BLOCKED",
          severity: "MEDIUM",
          timestamp,
          mode,
          metadata: {
            route: req.originalUrl,
            method: req.method,
            reason: ban.reason
          }
        };
        await redisClient.xadd('security_events', 'MAXLEN', '~', '10000', '*', 'data', JSON.stringify(attackEvent));
        
      } catch (err) {
        logger.error('Failed to pipe events to Redis stream', { error: err.message });
      }

      return res.status(403).json({
        success: false,
        code: 'IP_BANNED',
        message: 'Your IP has been temporarily blocked due to suspicious activity.',
      });
    }

    next();
  } catch (err) {
    // 🛡️ Redis failure → fail open (never block legitimate traffic)
    logger.error('ACTIVE_DEFENSE_CHECK_FAILED', { error: err.message });
    next();
  }
};

// ─────────────────────────────────────────────
// UTILITY EXPORTS (for testing / admin)
// ─────────────────────────────────────────────

/**
 * Manually unban an IP (admin use).
 */
export const unbanIp = async (ip) => {
  try {
    await redisClient.del(BAN_KEY(ip));
    logger.info('IP_UNBANNED', { ip });
  } catch (err) {
    logger.error('UNBAN_FAILED', { ip, error: err.message });
  }
};

/**
 * Get ban metadata for an IP.
 */
export const getBanMeta = async (ip) => {
  try {
    const raw = await redisClient.get(BAN_META_KEY(ip));
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    logger.error('BAN_META_FETCH_FAILED', { ip, error: err.message });
    return null;
  }
};

/**
 * Get current strike count for an IP.
 */
export const getStrikeCount = async (ip) => {
  try {
    const count = await redisClient.get(STRIKE_KEY(ip));
    return parseInt(count, 10) || 0;
  } catch (err) {
    logger.error('STRIKE_COUNT_FETCH_FAILED', { ip, error: err.message });
    return 0;
  }
};

export { isAllowlisted, STRIKE_THRESHOLD, STRIKE_WINDOW_TTL, BAN_DURATIONS };
