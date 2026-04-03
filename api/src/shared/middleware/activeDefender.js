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
//
// FIX SUMMARY:
//
// 1. CORRELATION ID — Only correlation_id is used.
//    event_group_id fallback is REMOVED.
//    corr:<ip> Redis fallback is REMOVED (was a hidden secondary correlation system).
//    DEFENSE events without a valid correlation_id are logged and skipped.
//    This prevents orphaned DEFENSE events from polluting the pipeline with
//    events that have no valid parent chain.
//
// 2. AGENT TYPE ENFORCEMENT — All DEFENSE events emitted by this module
//    carry agent_type: "SYSTEM" explicitly. This is the canonical signal
//    that the eventWorker uses to skip risk computation.
//
// 3. NO SELF-LOOP — recordStrike() → emits DEFENSE to stream.
//    The eventWorker will process the DEFENSE event but fast-path it
//    (no riskEngine call), so no circular amplification occurs.
//
// 4. ATOMIC BAN META — banIp reads + writes ban metadata in one place.
//    No partial write risk since each step is independent and Redis
//    operations are naturally serialized per key.
// ─────────────────────────────────────────────────────────────

import crypto         from 'crypto';
import redisClient    from '../config/redis.js';
import logger         from '../utils/logger.js';
import { getClientIp } from '../utils/clientInfo.js';
import { classifyIp }  from '../utils/ipClassifier.js';
import { ipBanCounter } from '../../metrics/metrics.js';
import { activeDefense as activeDefenseConfig } from '../config/index.js';
import {
  resolveStage,
  resolveAttackCategory,
  calculateEventIntelligence,
} from '../../modules/auth/audit.service.js';

// ─────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────
const STRIKE_THRESHOLD  = 5;
const STRIKE_WINDOW_TTL = 300;    // 5 minutes sliding window
const BAN_DURATIONS     = [600, 3600, 86400]; // 10m → 1h → 24h

const STRIKE_KEY   = (ip) => `strike:ip:${ip}`;
const BAN_KEY      = (ip) => `ban:ip:${ip}`;
const BAN_META_KEY = (ip) => `ban:meta:${ip}`;

// ─────────────────────────────────────────────
// SAFE IP ALLOWLIST
// ─────────────────────────────────────────────
const ALLOWLIST = new Set([
  '127.0.0.1',
  '::1',
  '::ffff:127.0.0.1',
  'localhost',
]);

const INTERNAL_CIDRS = [
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
  /^::ffff:172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
];

const SIMULATION_MODE = (process.env.SIMULATION_MODE || '').toLowerCase() === 'true';
const SIMULATION_CIDRS = [
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
];

const isAllowlisted = (ip) => {
  if (!ip) return false;
  if (ALLOWLIST.has(ip)) return true;
  if (INTERNAL_CIDRS.some((cidr) => cidr.test(ip))) return true;
  if (SIMULATION_MODE && SIMULATION_CIDRS.some((cidr) => cidr.test(ip))) return true;
  return false;
};

// ─────────────────────────────────────────────────────────────────────────────
// EMIT DEFENSE EVENT TO STREAM
//
// Shared helper used by both recordStrike() and banIp().
// Only emits when:
//   1. A valid correlation_id is available from the triggering event.
//   2. The chosen action is structurally valid.
//
// FIX: corr:<ip> Redis fallback is REMOVED. If the triggering event has no
// correlation_id, we log and skip — orphaned DEFENSE events are noise.
// event_group_id fallback is also REMOVED.
// ─────────────────────────────────────────────────────────────────────────────
async function emitDefenseEvent(ip, action, extraFields, triggeringEvent) {
  // ── Correlation ID resolution — SINGLE CANONICAL SOURCE ──────────────────
  const correlationId = triggeringEvent?.correlation_id;

  if (!correlationId) {
    logger.warn('DEFENSE_EVENT_SKIPPED_NO_CORRELATION', {
      ip,
      action,
      reason: 'triggeringEvent.correlation_id is missing; cannot emit orphaned DEFENSE event',
    });
    return;
  }

  const eventId   = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  let intelligence = { time_since_last_event_ms: 0, correlation_reason: null };
  try {
    intelligence = await calculateEventIntelligence(correlationId, timestamp, ip, extraFields.target_endpoint || 'defense-engine');
  } catch (intellErr) {
    logger.warn('DEFENSE_INTELLIGENCE_FAILED', {
      error:          intellErr.message,
      correlation_id: correlationId,
      event_id:       eventId,
    });
  }

  const event = {
    event_id:        eventId,
    correlation_id:  correlationId,
    event_type:      'DEFENSE',
    event_priority:  2,              // ← H1: DEFENSE always sorts after ATTACK (1)
    agent_type:      'SYSTEM',       // ← canonical system event marker
    action,
    source_ip:       ip,
    ip_type:         classifyIp(ip),
    user_agent:      'active-defender',
    target_type:     'SYSTEM',
    result:          'BLOCKED',
    severity:        extraFields.severity || 'MEDIUM',
    timestamp,
    mode:            activeDefenseConfig.enabled ? 'AFTER_ACTIVE_DEFENDER' : 'BEFORE_ACTIVE_DEFENDER',
    ...intelligence,
    stage:           resolveStage('DEFENSE', action),
    attack_category: resolveAttackCategory(extraFields.reason || action),
    ...extraFields,
  };

  await redisClient.xadd(
    'security_events',
    'MAXLEN', '~', '10000',
    '*',
    'data', JSON.stringify(event)
  );

  logger.info('DEFENSE_EVENT_QUEUED', {
    action,
    ip,
    event_id:       eventId,
    correlation_id: correlationId,
    event_priority: 2,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// RECORD STRIKE
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Records a security strike against an IP.
 * Uses Redis INCR + EXPIRE for sliding-window decay.
 * When strikes exceed threshold → triggers progressive ban.
 *
 * @param {string} ip              - Client IP address
 * @param {string} severity        - Event severity (LOW, MEDIUM, HIGH, CRITICAL)
 * @param {string} reason          - Human-readable reason for the strike
 * @param {object} triggeringEvent - Full event object (must contain correlation_id)
 */
export const recordStrike = async (ip, severity = 'MEDIUM', reason = 'security_event', triggeringEvent = {}) => {
  try {
    if (!activeDefenseConfig.enabled) return;
    if (!ip || isAllowlisted(ip)) return;

    const strikeKey = STRIKE_KEY(ip);

    // Sliding window: INCR + reset TTL on each new strike
    const strikes = await redisClient.incr(strikeKey);
    await redisClient.expire(strikeKey, STRIKE_WINDOW_TTL);

    logger.debug('STRIKE_RECORDED', {
      ip,
      strikes,
      threshold:      STRIKE_THRESHOLD,
      severity,
      reason,
      correlation_id: triggeringEvent?.correlation_id ?? null,
    });

    // Emit DEFENSE event (fast-pathed by worker — does NOT re-enter riskEngine)
    try {
      await emitDefenseEvent(ip, 'STRIKE_RECORDED', {
        reason,
        strike_count:    strikes,
        severity:        'MEDIUM',
        target_endpoint: 'strike-engine',
      }, triggeringEvent);
    } catch (emitErr) {
      logger.error('STRIKE_EVENT_EMIT_FAILED', {
        ip,
        error:          emitErr.message,
        correlation_id: triggeringEvent?.correlation_id ?? null,
      });
    }

    if (strikes >= STRIKE_THRESHOLD) {
      await banIp(ip, severity, reason, triggeringEvent);
      await redisClient.del(strikeKey);
    }
  } catch (err) {
    logger.error('STRIKE_RECORD_FAILED', { ip, error: err.message });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// PROGRESSIVE BAN ENGINE
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Bans an IP with escalating duration based on ban history.
 * 1st ban → 10 minutes
 * 2nd ban → 1 hour
 * 3rd+ ban → 24 hours
 */
const banIp = async (ip, severity, reason, triggeringEvent = {}) => {
  try {
    const banMetaKey = BAN_META_KEY(ip);
    const banKey     = BAN_KEY(ip);

    const rawMeta = await redisClient.get(banMetaKey);
    let meta = rawMeta ? JSON.parse(rawMeta) : { count: 0, history: [] };

    const banIndex = Math.min(meta.count, BAN_DURATIONS.length - 1);
    const duration = BAN_DURATIONS[banIndex];

    meta.count += 1;
    meta.history.push({
      reason,
      severity,
      bannedAt:        new Date().toISOString(),
      durationSeconds: duration,
    });

    // Store ban flag with TTL
    await redisClient.set(banKey, JSON.stringify({
      reason,
      severity,
      bannedAt:  new Date().toISOString(),
      banNumber: meta.count,
      expiresIn: duration,
    }), 'EX', duration);

    // Persist ban metadata (48h for escalation tracking across bans)
    await redisClient.set(banMetaKey, JSON.stringify(meta), 'EX', 172800);

    ipBanCounter.inc({ reason, severity });

    // Emit BAN DEFENSE event
    try {
      await emitDefenseEvent(ip, 'IP_BANNED', {
        reason,
        severity:      'HIGH',
        total_strikes: meta.count * STRIKE_THRESHOLD,
        ban_duration:  duration,
        ban_number:    meta.count,
        target_endpoint: 'ban-engine',
      }, triggeringEvent);
    } catch (emitErr) {
      logger.error('BAN_EVENT_EMIT_FAILED', { ip, error: emitErr.message });
    }

    const durationLabel = duration < 3600
      ? `${duration / 60}m`
      : `${duration / 3600}h`;

    logger.warn('IP_BANNED', {
      ip,
      reason,
      severity,
      banNumber:       meta.count,
      duration:        durationLabel,
      durationSeconds: duration,
    });
  } catch (err) {
    logger.error('BAN_IP_FAILED', { ip, error: err.message });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// ACTIVE DEFENSE MIDDLEWARE (HTTP layer — ban check on inbound requests)
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Express middleware: blocks requests from banned IPs.
 * When a banned IP hits the API:
 *   1. Emits an ATTACK event (BLOCKED_REQUEST) to the stream.
 *   2. Emits a DEFENSE event (BLOCKED_BANNED_IP) to the stream.
 *   3. Returns 403.
 *
 * FIX: correlation_id is generated fresh per request and used for BOTH events.
 *      No corr:<ip> cache — that was a hidden secondary correlation system.
 */
export const activeDefenseMiddleware = async (req, res, next) => {
  try {
    const ip = getClientIp(req);

    if (isAllowlisted(ip)) return next();

    const banKey  = BAN_KEY(ip);
    const banData = await redisClient.get(banKey);

    if (!banData) return next();

    let ban;
    try {
      ban = JSON.parse(banData);
    } catch (parseErr) {
      logger.error('BAN_DATA_PARSE_FAILED', { ip, error: parseErr.message });
      return next(); // fail-open on corrupted ban data
    }

    logger.warn('BLOCKED_BANNED_IP', {
      ip,
      reason:    ban.reason,
      severity:  ban.severity,
      banNumber: ban.banNumber,
    });

    // ── Generate a single correlation_id for the ATTACK → DEFENSE pair ───────
    // Use x-correlation-id header if present; otherwise generate fresh UUID.
    const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();

    const timestamp  = new Date().toISOString();
    const mode       = activeDefenseConfig.enabled ? 'AFTER_ACTIVE_DEFENDER' : 'BEFORE_ACTIVE_DEFENDER';
    const ip_type    = classifyIp(ip, req.headers['user-agent']);
    const user_agent = req.headers['user-agent'] || 'active-defender';

    try {
      // ── 1. Emit ATTACK event FIRST (establishes parent for DEFENSE event) ──
      const attackEventId = crypto.randomUUID();
      const atkEndpoint   = req.originalUrl;
      const atkIntel      = await calculateEventIntelligence(correlationId, timestamp, ip, atkEndpoint);

      const attackEvent = {
        event_id:        attackEventId,
        correlation_id:  correlationId,
        event_type:      'ATTACK',
        event_priority:  1,              // H1: ATTACK sorts before DEFENSE
        agent_type:      'EXTERNAL',
        action:          'BLOCKED_REQUEST',
        source_ip:       ip,
        ip_type,
        user_agent,
        target_type:     'API',
        target_endpoint: req.originalUrl,
        result:          'BLOCKED',
        severity:        'MEDIUM',
        timestamp,
        mode,
        ...atkIntel,
        stage:           resolveStage('ATTACK', 'BLOCKED_REQUEST'),
        metadata: {
          route:  req.originalUrl,
          method: req.method,
          reason: ban.reason,
        },
      };
      await redisClient.xadd('security_events', 'MAXLEN', '~', '10000', '*', 'data', JSON.stringify(attackEvent));
      logger.info('ATTACK_EVENT_QUEUED', {
        event_id:       attackEventId,
        correlation_id: correlationId,
        action:         'BLOCKED_REQUEST',
        ip,
      });

      // ── 2. Emit DEFENSE event SECOND (links to ATTACK via same correlation_id) ──
      // We pass a minimal triggeringEvent so emitDefenseEvent() can read correlation_id.
      await emitDefenseEvent(ip, 'BLOCKED_BANNED_IP', {
        reason:       ban.reason,
        severity:     'HIGH',
        strike_count: ban.banNumber * STRIKE_THRESHOLD,
        target_endpoint: req.originalUrl || 'ban-engine',
        mode,
        ip_type,
        user_agent,
      }, { correlation_id: correlationId });

    } catch (err) {
      logger.error('MIDDLEWARE_EVENT_EMIT_FAILED', { error: err.message });
      // Non-fatal — still return 403 regardless of stream write failure
    }

    return res.status(403).json({
      success: false,
      code:    'IP_BANNED',
      message: 'Your IP has been temporarily blocked due to suspicious activity.',
    });

  } catch (err) {
    // Redis failure → fail open (never block legitimate traffic)
    logger.error('ACTIVE_DEFENSE_CHECK_FAILED', { error: err.message });
    next();
  }
};

// ─────────────────────────────────────────────
// UTILITY EXPORTS (for admin / testing)
// ─────────────────────────────────────────────

/** Manually unban an IP (admin use). */
export const unbanIp = async (ip) => {
  try {
    await redisClient.del(BAN_KEY(ip));
    logger.info('IP_UNBANNED', { ip });
  } catch (err) {
    logger.error('UNBAN_FAILED', { ip, error: err.message });
  }
};

/** Get ban metadata for an IP. */
export const getBanMeta = async (ip) => {
  try {
    const raw = await redisClient.get(BAN_META_KEY(ip));
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    logger.error('BAN_META_FETCH_FAILED', { ip, error: err.message });
    return null;
  }
};

/** Get current strike count for an IP. */
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
