import logger from '../../shared/utils/logger.js';
import crypto from 'crypto';
import { recordStrike } from '../../shared/middleware/activeDefender.js';
import redisClient from '../../shared/config/redis.js';
import { classifyIp } from '../../shared/utils/ipClassifier.js';
import { securityEventSeverityCounter } from '../../metrics/metrics.js';

// ─────────────────────────────────────────────
// SEQUENCE HELPERS (Removed: Centralized in eventWorker.js)
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// STEP 6 — EVENT DEDUPLICATION
// ─────────────────────────────────────────────

/**
 * Deduplicates events within a short time window (2s) using Redis SET NX.
 * Prevents identical events from flooding the pipeline under concurrency.
 */
export const checkDuplicateEvent = async (correlationId, eventSignature) => {
  const key = `dedup:${correlationId}:${eventSignature}`;
  const acquired = await redisClient.set(key, '1', 'EX', 2, 'NX');
  return acquired === null; // true if it ALREADY existed (i.e. is duplicate)
};

// ─────────────────────────────────────────────
// STEP 7 — EVENT INTELLIGENCE
// ─────────────────────────────────────────────

/**
 * Calculates temporal distance from previous event in correlation chain
 * and provides a short human-readable reason.
 */
export const calculateEventIntelligence = async (correlationId, currentTsStr, sourceIp, targetEndpoint) => {
  const currentTs = new Date(currentTsStr).getTime();
  const key = `last_ts:${correlationId}`;
  
  const lastTsStr = await redisClient.getset(key, currentTs);
  await redisClient.expire(key, 3600);
  
  if (!lastTsStr) {
    return { time_since_last_event_ms: 0, correlation_reason: null };
  }

  const deltaMs = currentTs - parseInt(lastTsStr, 10);
  const timeLabel = deltaMs < 2000 ? 'within 2s window' : `after ${Math.floor(deltaMs / 1000)}s`;
  
  return {
    time_since_last_event_ms: deltaMs,
    correlation_reason: `Same IP + same endpoint (${targetEndpoint}) ${timeLabel}`
  };
};

// ─────────────────────────────────────────────
// STEP 4 — STAGE MAPPING
// Maps event_type + action → pipeline stage.
// Single function — update here only.
// ─────────────────────────────────────────────

const ENFORCEMENT_ACTIONS = new Set([
  'IP_BANNED',
  'BLOCKED_BANNED_IP',
  'BLOCKED_REQUEST',
]);

/**
 * Returns the pipeline stage for an event.
 * DETECTION  — inbound attack observed
 * RESPONSE   — system records a strike
 * ENFORCEMENT — ban or block applied
 * null       — benign / informational event (no stage stamped)
 */
export const resolveStage = (eventType, action) => {
  if (eventType === 'ATTACK') return 'DETECTION';
  if (action === 'STRIKE_RECORDED') return 'RESPONSE';
  if (ENFORCEMENT_ACTIONS.has(action)) return 'ENFORCEMENT';
  return null;
};

// ─────────────────────────────────────────────
// STEP 5 — ATTACK CATEGORY MAPPING
// Maps action → attack category from reason field.
// Single reusable function — not hardcoded at call sites.
// ─────────────────────────────────────────────

const ACTION_TO_ATTACK_CATEGORY = {
  LOGIN_FAILED:              'BRUTE_FORCE',
  MFA_FAILED:                'BRUTE_FORCE',
  TOKEN_REUSE_DETECTED:      'SESSION_ATTACK',
  SUSPICIOUS_SESSION_DETECTED: 'SESSION_ATTACK',
  SESSION_HIJACK_DETECTED:   'SESSION_ATTACK',
  RBAC_ACCESS_DENIED:        'AUTHORIZATION_ATTACK',
  ABAC_ACCESS_DENIED:        'AUTHORIZATION_ATTACK',
};

/**
 * Returns the attack category for a given action, or null for benign actions.
 * Extend ACTION_TO_ATTACK_CATEGORY to add new mappings — never call this
 * with hardcoded strings at individual event sites.
 */
export const resolveAttackCategory = (action) => {
  return ACTION_TO_ATTACK_CATEGORY[action] ?? null;
};

// ─────────────────────────────────────────────
// ATTACK EVENT EMISSION
// ─────────────────────────────────────────────

/**
 * Actions that represent an inbound attack attempt.
 * Only these trigger a preceding ATTACK event in the stream.
 */
const ATTACK_ACTIONS = new Set(Object.keys(ACTION_TO_ATTACK_CATEGORY));

/**
 * Emits an ATTACK event to the stream BEFORE the defense/audit event.
 * Shares the same correlation_id so sequence + parent chain links them.
 * Returns the emitted attack event_id (used as parent for the next event).
 */
const emitAttackEvent = async ({ correlationId, action, result, sourceIp, ipType, userAgent, severity, timestamp, targetEndpoint }) => {
  const eventSignature = crypto.createHash('sha256').update(`ATTACK:${action}:${sourceIp}`).digest('hex');
  if (await checkDuplicateEvent(correlationId, eventSignature)) {
    return null;
  }

  const eventId = crypto.randomUUID();
  const intelligence = await calculateEventIntelligence(correlationId, timestamp, sourceIp, targetEndpoint || 'API');

  const attackEvent = {
    event_id: eventId,
    correlation_id: correlationId,
    event_type: 'ATTACK',
    action,
    result,
    source_ip: sourceIp,
    ip_type: ipType,
    user_agent: userAgent,
    agent_type: 'EXTERNAL',
    target_type: 'API',
    severity,
    timestamp,
    ...intelligence,
    stage:           resolveStage('ATTACK', action),
    attack_category: resolveAttackCategory(action),
  };

  await redisClient.xadd(
    'security_events',
    'MAXLEN', '~', '10000',
    '*',
    'data',
    JSON.stringify(attackEvent)
  );

  logger.info('ATTACK_EVENT_QUEUED', { action, source_ip: sourceIp, event_id: eventId });
  return eventId;
};

// ─────────────────────────────────────────────
// SEVERITY MAPPING: status → defense severity
// ─────────────────────────────────────────────
const SEVERITY_MAP = {
  FAILURE: 'HIGH',
  MFA_FAILED: 'HIGH',
  SUSPICIOUS_SESSION_DETECTED: 'CRITICAL',
  SESSION_COMPROMISED: 'CRITICAL',
};

const inferSeverity = (status) => {
  return SEVERITY_MAP[status] || (status?.includes('FAIL') ? 'MEDIUM' : null);
};

export const logSecurityEvent = async (payload) => {
  const { userId, action, status, ip, userAgent, metadata, event_type, source_ip, sessionId, ...restOfPayload } = payload;
  const resolvedIp = ip || source_ip;
  const resolvedStatus = status || payload.result || 'SUCCESS';
  const resolvedEventType = event_type || metadata?.event_type || 'SECURITY';

  const metaJson = metadata ? JSON.parse(JSON.stringify(metadata)) : {};
  const mergedMeta = { ...metaJson, ...restOfPayload, event_type: resolvedEventType };
  
  const correlationId = mergedMeta?.correlation_id || payload.correlationId || crypto.randomUUID();

  // ── Step 6: Deduplication Check ──
  const eventSignature = crypto.createHash('sha256').update(`${resolvedEventType}:${action}:${resolvedIp}`).digest('hex');
  if (await checkDuplicateEvent(correlationId, eventSignature)) {
    return;
  }

  const severity = inferSeverity(resolvedStatus);
  const triggeringEvent = { correlation_id: correlationId, event_group_id: payload.event_group_id };
  if (severity && resolvedIp && resolvedEventType !== 'DEFENSE') {
    recordStrike(resolvedIp, severity, `${action}:${resolvedStatus}`, triggeringEvent).catch((err) => {
      logger.error('RECORD_STRIKE_FAILED', { error: err.message, ip: resolvedIp });
    });
  }

  const ipType = classifyIp(resolvedIp, userAgent);
  const timestamp = payload.timestamp || mergedMeta?.timestamp || new Date().toISOString();
  const resolvedSeverity = payload.severity || mergedMeta?.severity || (resolvedStatus === 'FAILURE' ? 'MEDIUM' : 'LOW');

  // ── Step 3: Emit ATTACK event first for hostile actions ──
  // Only for non-DEFENSE, non-ATTACK events whose action is in the attack set.
  // This inserts ATTACK (seq=N) → original event (seq=N+1) on the same correlation_id.
  const isAttackAction = ATTACK_ACTIONS.has(action) && resolvedEventType !== 'DEFENSE' && resolvedEventType !== 'ATTACK';
  if (isAttackAction) {
    await emitAttackEvent({
      correlationId,
      action,
      result: resolvedStatus,
      sourceIp: resolvedIp || 'unknown',
      ipType,
      userAgent: userAgent || 'unknown',
      severity: resolvedSeverity,
      timestamp,
      targetEndpoint: mergedMeta?.path || 'internal',
    });
  }

  // 🕸️ GRAPH_EVENT: Emit normalized event for Neo4j IMMEDIATELY
  const baseGraphEvent = {
      event_id: crypto.randomUUID(),
      correlation_id: correlationId,
      user_id: userId || 'SYSTEM',
      user_email: mergedMeta?.user_email || null,
      session_id: sessionId || mergedMeta?.jti || null,
      event_type: resolvedEventType,
      action,
      source_ip: resolvedIp || 'unknown',
      ip_type: ipType,
      user_agent: userAgent || 'unknown',
      agent_type: ipType === 'SIMULATED' ? 'SIMULATED' : 'REAL',
      target_type: 'API',
      target_endpoint: mergedMeta?.path || 'internal',
      result: resolvedStatus,
      severity: resolvedSeverity,
      timestamp,
  };

  // ── Step 7: Intelligence (atomic, concurrent-safe) ──
  const eventId = baseGraphEvent.event_id;
  const targetEndpoint = baseGraphEvent.target_endpoint;
  const intelligence = await calculateEventIntelligence(correlationId, timestamp, resolvedIp, targetEndpoint);

  // ── Steps 4 & 5: stage + attack_category ──
  const stage           = resolveStage(resolvedEventType, action);
  const attack_category = resolveAttackCategory(action);

  const graphEvent = {
    ...baseGraphEvent,
    ...mergedMeta,
    time_since_last_event_ms: intelligence.time_since_last_event_ms,
    // Only include fields when they carry a value — keeps null fields out of clean events
    ...(intelligence.correlation_reason && { correlation_reason: intelligence.correlation_reason }),
    ...(stage           !== null && { stage }),
    ...(attack_category !== null && { attack_category }),
  };

  logger.info('GRAPH_EVENT', graphEvent);

  try {
    if (graphEvent.severity) {
      securityEventSeverityCounter.inc({ severity: graphEvent.severity });
    }

    await redisClient.xadd(
      'security_events',
      'MAXLEN', '~', '10000',
      '*',
      'data',
      JSON.stringify(graphEvent)
    );

    if (resolvedEventType === 'DEFENSE') {
      logger.info('DEFENSE_EVENT_QUEUED', { action, source_ip: resolvedIp, status: resolvedStatus });
    }
  } catch (error) {
    logger.error('Failed to queue security event to Redis', {
      error: error.message,
      action,
      event_type: resolvedEventType,
      source_ip: resolvedIp,
    });
  }
};