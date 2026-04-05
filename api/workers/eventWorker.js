/**
 * ─────────────────────────────────────────────────────────────────────────────
 * eventWorker.js — Production-Grade Redis Stream Consumer
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * TASK 1 CHANGE (defense dispatch removal):
 *   dispatchDefenseIfNeeded() and all defense:needed / defense:escalate flag
 *   reading code is REMOVED. riskEngine now pushes directly to the
 *   defense_events stream via XADD. defenseWorker consumes that stream via
 *   XREADGROUP. This worker has NO defense responsibilities.
 *
 * TASK 2 ENFORCEMENT (deterministic ordering):
 *   Every event emitted/persisted carries:
 *     - event_priority:       ATTACK=1, DEFENSE=2 (guards Neo4j chain order)
 *     - event_sequence_index: monotonic INCR per correlation_id
 *     - parent_event_id:      previous event in the same chain
 *   All three fields are stored in PostgreSQL metadata and emitted to saveToNeo4j().
 *   NO timestamp-only ordering anywhere in this file.
 *
 * TASK 3 ENFORCEMENT (failure recovery):
 *   - Atomic SET NX idempotency on processed:<event_id> (EX 3600).
 *   - XAUTOCLAIM-based PEL reclaim on every loop iteration.
 *   - MAX_RETRIES → DLQ + XACK (no infinite retry).
 *   - DB dedup check on event_id before INSERT (belt-and-suspenders).
 *   - Graceful shutdown: 2s drain window before Redis quit.
 *   - Redis readiness check with bounded retries (max 10 × 2s).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

import Redis          from 'ioredis';
import { PrismaClient } from '@prisma/client';
import winston        from 'winston';
import crypto         from 'crypto';
import { 
  streamConsumerLag, securityEventsProcessedTotal, eventsProcessingLatencyMs,
  neo4jWriteTotal, neo4jWriteLatencyMs,
  neo4jFailedEventsQueueSize, dlqSize, retryAttemptsTotal, redisStreamLag,
  eventsInflightGauge, processingBacklogSize, workerLastProcessedTimestamp,
  workerAliveGauge, redisConnectionStatus, neo4jConnectionStatus
} from '../src/metrics/metrics.js';
import { RiskEngine }        from './riskEngine.js';
import { redis as redisConfig } from '../src/shared/config/index.js';
import { mergeEventToGraph, closeNeo4jDriver } from '../src/shared/db/neo4j.js';

// ─────────────────────────────────────────────
// Logger
// ─────────────────────────────────────────────
const logger = winston.createLogger({
  level:  process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'event-worker', pid: process.pid },
  transports:  [new winston.transports.Console()],
});

const prisma = new PrismaClient({
  log: [{ emit: 'event', level: 'error' }],
});
prisma.$on('error', (e) => logger.error('PRISMA_ERROR', { message: e.message }));

// ─────────────────────────────────────────────
// Redis client
// ─────────────────────────────────────────────
const redisClient = new Redis(redisConfig.url, {
  retryStrategy:      (times) => Math.min(times * 200, 10_000),
  enableOfflineQueue: true,
  lazyConnect:        false,
});
redisClient.on('error',        (err) => logger.error('REDIS_ERROR',        { error: err.message }));
redisClient.on('reconnecting', ()    => logger.warn ('REDIS_RECONNECTING'));
redisClient.on('connect',      ()    => logger.info ('REDIS_CONNECTED'));

const riskEngine = new RiskEngine(redisClient);

// ─────────────────────────────────────────────
// STREAM / GROUP CONSTANTS
// ─────────────────────────────────────────────
const STREAM_KEY    = 'security_events';
const DLQ_KEY       = 'security_events_dlq';
const GROUP_NAME    = 'audit_workers';
const CONSUMER_NAME = `worker_${process.pid}`;

// ─────────────────────────────────────────────
// RELIABILITY CONSTANTS
// ─────────────────────────────────────────────
const MAX_RETRIES   = 3;
const CLAIM_IDLE_MS = 30_000;
const RECLAIM_COUNT = 50;

// ─────────────────────────────────────────────
// TASK 2: EVENT PRIORITY MAP
// ATTACK=1 must sort BEFORE DEFENSE=2 in all downstream systems.
// Used by Neo4j ingestion, PostgreSQL queries, in-memory sort.
// Key: correlation_id → event_priority → event_sequence_index
// ─────────────────────────────────────────────
const EVENT_PRIORITY = { ATTACK: 1, DEFENSE: 2, SECURITY: 1 };
const getEventPriority = (event_type) => EVENT_PRIORITY[event_type] ?? 1;

// ─────────────────────────────────────────────
// Sequence key TTL — matches riskEngine RISK_STATE_TTL grace window
// ─────────────────────────────────────────────
const SEQ_TTL_SECONDS = 3_600;   // 1 hour

// ─────────────────────────────────────────────
// GRACEFUL SHUTDOWN
// ─────────────────────────────────────────────
let shuttingDown = false;

async function shutdown(signal) {
  logger.info('WORKER_SHUTDOWN_INITIATED', { signal });
  shuttingDown = true;
  await new Promise((r) => setTimeout(r, 2000));   // drain in-flight ops
  await closeNeo4jDriver();
  await redisClient.quit();
  await prisma.$disconnect();
  logger.info('WORKER_SHUTDOWN_COMPLETE', { signal });
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ─────────────────────────────────────────────
// BOOTSTRAP
// ─────────────────────────────────────────────
async function initializeRedis() {
  let retries = 10;
  while (retries--) {
    try {
      await redisClient.ping();
      break;
    } catch (err) {
      if (retries === 0) throw new Error('Redis readiness check failed after 10 attempts');
      logger.warn('REDIS_NOT_READY', { retriesLeft: retries });
      await new Promise(r => setTimeout(r, 2000));
    }
  }

  try {
    await redisClient.xgroup('CREATE', STREAM_KEY, GROUP_NAME, '0', 'MKSTREAM');
    logger.info('CONSUMER_GROUP_CREATED', { group: GROUP_NAME });
  } catch (err) {
    if (err.message.includes('BUSYGROUP')) {
      logger.info('CONSUMER_GROUP_EXISTS', { group: GROUP_NAME });
    } else {
      throw err;
    }
  }

  // TASK 3: On startup, reclaim PEL messages from crashed workers
  logger.info('STARTUP_PEL_RECLAIM');
  await reclaimAndRetry();
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
const UUID_RE     = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isValidUUID = (val) => typeof val === 'string' && UUID_RE.test(val);

// TASK 2: DEFENSE events (agent_type=SYSTEM) skip risk engine — system events
// must never re-enter the scoring path (prevents amplification + circular loop).
const isSystemEvent = (ev) =>
  ev.event_type === 'DEFENSE' || ev.agent_type === 'SYSTEM';

// C-2 FIX: SECURITY events that preceded an ATTACK event are tagged
// _skip_risk_engine:true by audit.service.js. Skip risk scoring for them
// to prevent 2x score inflation from the same hostile action.
const shouldSkipRiskEngine = (ev) =>
  isSystemEvent(ev) || ev._skip_risk_engine === true;

// Structured log context — every log line includes these fields for tracing
function logCtx(event) {
  return {
    event_id:       event?.event_id       ?? null,
    correlation_id: event?.correlation_id ?? null,
    action:         event?.action         ?? null,
    event_type:     event?.event_type     ?? null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// DB WRITE — idempotent on event_id
// TASK 2: event_priority stored in metadata for Prisma sort queries.
// TASK 3: Pre-INSERT existence check prevents duplicate rows on re-delivery.
// ─────────────────────────────────────────────────────────────────────────────
async function saveToPostgres(eventData) {
  // TASK 3: Belt-and-suspenders DB dedup (SET NX is the primary idempotency gate;
  // this catches the edge case where the processed: key expired before re-delivery)
  if (eventData.event_id) {
    const existing = await prisma.auditLog.findFirst({
      where:  { metadata: { path: ['event_id'], equals: eventData.event_id } },
      select: { id: true },
    });
    if (existing) {
      logger.debug('DB_DUPLICATE_SKIPPED', { ...logCtx(eventData) });
      return;
    }
  }

  const userId = isValidUUID(eventData.user_id) ? eventData.user_id : undefined;

  await prisma.auditLog.create({
    data: {
      event_id:  eventData.event_id,
      userId,
      action:    eventData.action     || 'UNKNOWN',
      status:    eventData.result     || 'SUCCESS',
      ip:        eventData.source_ip  || 'unknown',
      userAgent: eventData.user_agent || 'unknown',
      metadata: {
        ...(eventData.metadata || {}),
        // Canonical fields — always override raw metadata spread
        event_id:             eventData.event_id,
        correlation_id:       eventData.correlation_id,
        event_type:           eventData.event_type,
        agent_type:           eventData.agent_type,
        // TASK 2: priority + sequence stored for downstream sort queries
        //   ORDER BY metadata->>'correlation_id', metadata->>'event_priority',
        //            CAST(metadata->>'event_sequence_index' AS INTEGER)
        event_priority:       eventData.event_priority,
        event_sequence_index: eventData.event_sequence_index,
        parent_event_id:      eventData.parent_event_id,
        action:               eventData.action,
        source_ip:            eventData.source_ip,
        user_id:              eventData.user_id    ?? null,
        user_email:           eventData.user_email ?? null,
        session_id:           eventData.session_id ?? null,
        risk_score:           eventData.risk_score ?? null,
        risk_level:           eventData.risk_level ?? null,
        risk_error:           eventData.risk_error ?? null,
        sequence:             eventData.sequence   ?? [],
        risk_delta:           eventData.risk_delta ?? null,
        is_defense_triggered: eventData.is_defense_triggered ?? false,
        defense_reason:       eventData.defense_reason ?? null,
        defense_action:       eventData.defense_action ?? null,
      },
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// NEO4J EMISSION
// ─────────────────────────────────────────────────────────────────────────────
//
// C-3 FIX: Neo4j write failures are no longer silently swallowed.
//
// Strategy:
//   1. On failure, write the event_id to the sorted set `neo4j:failed_events`
//      (score = epoch ms) so a repair job can detect the gap without scanning.
//   2. Re-throw the error so the caller does NOT mark the event as processed.
//      The PEL retains it → XAUTOCLAIM will redeliver for up to MAX_RETRIES.
//      After MAX_RETRIES the event goes to DLQ (handled in processMessage error block).
//
// Trade-off: Neo4j is documented as a secondary read-optimised sink.
//   Retrying here risks duplicate MERGE calls, but MERGE is fully idempotent
//   (unique constraint on event_id) so duplicates are safe.
// ─────────────────────────────────────────────────────────────────────────────
async function saveToNeo4j(eventData) {
  logger.debug('GRAPH_EVENT', {
    correlation_id:       eventData.correlation_id,
    event_priority:       eventData.event_priority,
    event_sequence_index: eventData.event_sequence_index,
    parent_event_id:      eventData.parent_event_id,
    event_id:             eventData.event_id,
  });

  const writeStart = Date.now();
  try {
    logger.info('NEO4J_WRITE_START', { event_id: eventData.event_id });
    await mergeEventToGraph(eventData);
    neo4jWriteLatencyMs.observe(Date.now() - writeStart);
    neo4jWriteTotal.inc({
      action: eventData.action || 'UNKNOWN',
      event_type: eventData.event_type || 'UNKNOWN',
      severity: eventData.severity || 'LOW',
      status: 'success'
    });
    logger.info('NEO4J_WRITE_SUCCESS', { event_id: eventData.event_id });
  } catch (err) {
    neo4jWriteTotal.inc({
      action: eventData.action || 'UNKNOWN',
      event_type: eventData.event_type || 'UNKNOWN',
      severity: eventData.severity || 'LOW',
      status: 'error'
    });
    logger.error('NEO4J_WRITE_ERROR', { event_id: eventData.event_id, error: err.message });

    // C-3: Write event_id to repair set (score = ms, enables time-range repair queries)
    try {
      await redisClient.zadd(
        'neo4j:failed_events',
        Date.now(),
        eventData.event_id
      );
      neo4jFailedEventsQueueSize.inc();
      logger.warn('NEO4J_REPAIR_QUEUED', { event_id: eventData.event_id });
    } catch (repairErr) {
      logger.error('NEO4J_REPAIR_QUEUE_FAILED', { event_id: eventData.event_id, error: repairErr.message });
    }

    // Re-throw so caller does NOT mark event as processed — PEL will redeliver.
    throw err;
  }
}

// ─────────────────────────────────────────────
// DEAD-LETTER QUEUE
// ─────────────────────────────────────────────
async function sendToDLQ(messageId, rawData, reason, context = {}) {
  try {
    await redisClient.xadd(
      DLQ_KEY,
      'MAXLEN', '~', '5000',
      '*',
      'original_id', messageId,
      'data',        rawData || '',
      'reason',      reason,
      'failed_at',   new Date().toISOString()
    );
    logger.error('EVENT_SENT_TO_DLQ', { messageId, reason, ...context });
  } catch (dlqErr) {
    logger.error('DLQ_WRITE_FAILED', { messageId, error: dlqErr.message, ...context });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SEQUENCE + PARENT ENRICHMENT
//
// TASK 2: Assigns event_priority, event_sequence_index, parent_event_id
// to every event regardless of type. These three fields together with
// correlation_id form the canonical sort key for deterministic ordering.
//
// Pipeline:
//   INCR seq:<correlationId>                → monotonic sequence number
//   GETSET prev:<correlationId> <event_id>  → returns previous event_id
//
// TTL: Uses EXPIRE GT (Redis 7+) to extend only when new TTL > current.
// Falls back to plain EXPIRE on Redis < 7.
// ─────────────────────────────────────────────────────────────────────────────
async function enrichSequenceAndParent(eventData) {
  let correlationId = eventData.correlation_id;

  if (!correlationId) {
    correlationId = crypto.randomUUID();
    eventData.correlation_id = correlationId;
    logger.warn('CORRELATION_ID_GENERATED', {
      ...logCtx(eventData),
      generated_correlation_id: correlationId,
    });
  }

  const metaKey = `emeta:${eventData.event_id}`;
  const existingMeta = await redisClient.hgetall(metaKey);

  // BUG FIX 2: Idempotent sequence assignment. Retried messages MUST NOT
  // advance INCR again, nor overwrite the GETSET pointer.
  // If the worker crashes between sequence generation and DB write, the retry
  // will perfectly adopt the identical seq and parent_id generated previously.
  if (existingMeta && existingMeta.seq) {
    eventData.event_sequence_index = parseInt(existingMeta.seq, 10);
    eventData.parent_event_id      = existingMeta.prev === 'null' ? null : (existingMeta.prev || null);
    eventData.event_priority       = getEventPriority(eventData.event_type);
    return;
  }

  const seqKey  = `seq:${correlationId}`;
  const prevKey = `prev:${correlationId}`;

  // Atomic pipeline: 1 RTT for both ops
  const pipe = redisClient.pipeline();
  pipe.incr(seqKey);
  pipe.getset(prevKey, eventData.event_id);
  const [[, seq], [, previousEventId]] = await pipe.exec();

  // TASK 2: canonical ordering fields
  eventData.event_sequence_index = seq;
  eventData.parent_event_id      = previousEventId || null;
  eventData.event_priority       = getEventPriority(eventData.event_type);

  // Adaptive TTL — EXPIRE GT prevents thrashing on hot chains (Redis 7+)
  const ttlPipe = redisClient.pipeline();
  ttlPipe.hset(metaKey, 'seq', seq, 'prev', previousEventId || 'null');
  ttlPipe.call('EXPIRE', metaKey, SEQ_TTL_SECONDS, 'GT');
  ttlPipe.call('EXPIRE', seqKey,  SEQ_TTL_SECONDS, 'GT');
  ttlPipe.call('EXPIRE', prevKey, SEQ_TTL_SECONDS, 'GT');
  try {
    await ttlPipe.exec();
  } catch {
    // Redis < 7 fallback
    const fb = redisClient.pipeline();
    fb.hset(metaKey, 'seq', seq, 'prev', previousEventId || 'null');
    fb.expire(metaKey, SEQ_TTL_SECONDS);
    fb.expire(seqKey,  SEQ_TTL_SECONDS);
    fb.expire(prevKey, SEQ_TTL_SECONDS);
    await fb.exec();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROCESS ONE MESSAGE
//
// Returns true  → caller should XACK.
// Throws        → transient; caller skips ACK so PEL retains for reclaim.
//
// TASK 3 idempotency path:
//   SET processed:<event_id> 1 EX 3600 NX
//   → null  : already processed → ACK immediately (idempotent skip)
//   → 'OK'  : first time → proceed
// (DB pre-INSERT check in saveToPostgres is the 2nd gate for expired keys)
// ─────────────────────────────────────────────────────────────────────────────
async function processMessage(messageId, keyValues) {
  // ── 1. Extract raw data field ──────────────────────────────────────────────
  let rawData = null;
  for (let i = 0; i < keyValues.length; i += 2) {
    if (keyValues[i] === 'data') { rawData = keyValues[i + 1]; break; }
  }

  if (!rawData) {
    logger.warn('EVENT_MISSING_DATA_FIELD', { messageId });
    return true;   // ACK — permanently malformed
  }

  // ── 2. Parse ───────────────────────────────────────────────────────────────
  let eventData;
  try {
    eventData = JSON.parse(rawData);
  } catch {
    await sendToDLQ(messageId, rawData, 'JSON_PARSE_ERROR');
    return true;
  }

  // ── 3. Assign event_id ────────────────────────────────────────────────────
  eventData.event_id = eventData.event_id || crypto.randomUUID();

  // ── 4. TASK 3: Atomic idempotency gate (Two-Stage) ────────────────────────
  const processedKey  = `processed:${eventData.event_id}`;
  const processingKey = `processing:${eventData.event_id}`;

  const isProcessed = await redisClient.get(processedKey);
  if (isProcessed) {
    logger.debug('EVENT_ALREADY_PROCESSED', { ...logCtx(eventData) });
    return true;
  }

  const acquired = await redisClient.set(processingKey, '1', 'EX', 300, 'NX');
  if (acquired === null) {
    logger.debug('EVENT_PROCESSING_BY_OTHER_WORKER', { ...logCtx(eventData) });
    return false; // Cannot acquire lock — leave in PEL, do not ACK
  }

  try {
    // ── 5. DEFENSE fast-path ──────────────────────────────────────────────────
    // TASK 2: DEFENSE events still get sequence + priority assigned so
    // downstream systems have a complete sort key. They are never risk-scored.
    if (isSystemEvent(eventData)) {
      await enrichSequenceAndParent(eventData);

      eventData.risk_score           = null;
      eventData.risk_level           = null;
      eventData.is_defense_triggered = false;

      // FIX 2: Heartbeat TTL before slow external operations
      await redisClient.expire(processingKey, 300);

      await saveToPostgres(eventData);
      await saveToNeo4j(eventData);

      logger.info('DEFENSE_EVENT_PERSISTED', {
        ...logCtx(eventData),
        event_sequence_index: eventData.event_sequence_index,
        event_priority:       eventData.event_priority,   // always 2 for DEFENSE
      });

      // FIX 1: Safe state transition — write completion proof BEFORE dropping mutex
      await redisClient.set(processedKey, '1', 'EX', 3600);
      await redisClient.del(processingKey);

      securityEventsProcessedTotal.inc({
        action: eventData.action || 'UNKNOWN',
        event_type: eventData.event_type || 'UNKNOWN',
        severity: eventData.severity || 'LOW',
        status: 'success'
      });
      const processLatency = Date.now() - new Date(eventData.timestamp).getTime();
      eventsProcessingLatencyMs.observe(processLatency > 0 ? processLatency : 0);

      return true;
    }

    // ── 6. TASK 2: Enrichment for ATTACK events ──────────────────────────────
    await enrichSequenceAndParent(eventData);

    // ── 7. Risk Engine ─────────────────────────────────────────────────────────
    const riskStart = Date.now();

    // C-2 FIX: Skip risk engine for events tagged by audit.service as already
    // having a companion ATTACK event scored. Also skips SYSTEM/DEFENSE events.
    if (shouldSkipRiskEngine(eventData)) {
      eventData.risk_score = eventData.risk_score ?? null;
      eventData.risk_level = eventData.risk_level ?? null;
      logger.debug('RISK_ENGINE_SKIPPED', {
        ...logCtx(eventData),
        reason: eventData._skip_risk_engine ? 'companion_attack_scored' : 'system_event',
      });
    } else {
      try {
        // FIX 2: Heartbeat TTL before compute-intensive risk pipeline
        await redisClient.expire(processingKey, 300);

        const riskData = await riskEngine.processEvent(eventData);
        if (riskData) Object.assign(eventData, riskData);
        eventData.risk_score = eventData.risk_score ?? 0;
        eventData.risk_level = eventData.risk_level ?? 'LOW';

        logger.info('RISK_ENGINE_COMPLETED', {
          ...logCtx(eventData),
          risk_score:  eventData.risk_score,
          risk_level:  eventData.risk_level,
          risk_delta:  eventData.risk_delta,
          duration_ms: Date.now() - riskStart,
        });
      } catch (err) {
        logger.error('RISK_ENGINE_ERROR', {
          error:       err.message,
          duration_ms: Date.now() - riskStart,
          ...logCtx(eventData),
        });
        eventData.risk_score = 0;
        eventData.risk_level = 'UNKNOWN';
        eventData.risk_error = err.message;
      }
    }

    // ── 8. Persist ─────────────────────────────────────────────────────────────
    const dbStart = Date.now();

    // FIX 2: Heartbeat TTL before external database writes
    await redisClient.expire(processingKey, 300);

    await saveToPostgres(eventData);
    await saveToNeo4j(eventData);

    logger.info('EVENT_PERSISTED', {
      ...logCtx(eventData),
      event_priority:       eventData.event_priority,
      event_sequence_index: eventData.event_sequence_index,
      risk_score:           eventData.risk_score,
      duration_ms:          Date.now() - dbStart,
    });

    // NOTE: No defense dispatch here.
    // riskEngine._pushDefenseTask() pushes to defense_events stream.
    // defenseWorker consumes that stream independently.

    // FIX 1: Safe state transition — write completion proof BEFORE dropping mutex
    await redisClient.set(processedKey, '1', 'EX', 3600);
    await redisClient.del(processingKey);

    securityEventsProcessedTotal.inc({
      action: eventData.action || 'UNKNOWN',
      event_type: eventData.event_type || 'UNKNOWN',
      severity: eventData.severity || 'LOW',
      status: 'success'
    });
    const processLatency = Date.now() - new Date(eventData.timestamp).getTime();
    eventsProcessingLatencyMs.observe({ worker: 'eventWorker' }, processLatency > 0 ? processLatency : 0);
    workerLastProcessedTimestamp.set({ worker: 'eventWorker' }, Date.now());

    eventsInflightGauge.dec({ worker: 'eventWorker' });
    return true;
  } catch (err) {
    // BUG FIX 3: Failing without clearing the lock results in silent event loss!
    // The retry via XAUTOCLAIM would see the NX lock still held and skip/ACK it.
    // By clearing processingKey, the next worker to reclaim gets to try again.
    await redisClient.del(processingKey).catch(() => {});
    eventsInflightGauge.dec({ worker: 'eventWorker' });
    throw err;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TASK 3: RECLAIM + DLQ ESCALATION
//
// XAUTOCLAIM atomically reassigns PEL entries idle > CLAIM_IDLE_MS to this
// consumer. Covers:
//   - Worker crashed before XACK
//   - Worker restarted (messages still in PEL from prior instance)
//   - Slow processing exceeding CLAIM_IDLE_MS
//
// After MAX_RETRIES deliveries → DLQ + XACK. No infinite retry.
// ─────────────────────────────────────────────────────────────────────────────
async function reclaimAndRetry() {
  try {
    const result = await redisClient.xautoclaim(
      STREAM_KEY, GROUP_NAME, CONSUMER_NAME,
      CLAIM_IDLE_MS, '0-0',
      'COUNT', RECLAIM_COUNT
    );

    const claimed = result[1] ?? [];
    if (claimed.length === 0) return;

    logger.info('RECLAIM_PASS', { count: claimed.length });
    retryAttemptsTotal.inc({ stream: STREAM_KEY }, claimed.length);

    for (const [msgId, keyValues] of claimed) {
      // Check delivery count via XPENDING range scan
      let deliveryCount = 0;
      try {
        const pending = await redisClient.xpending(
          STREAM_KEY, GROUP_NAME, msgId, msgId, 1
        );
        deliveryCount = pending[0]?.[3] ?? 0;
      } catch (pendingErr) {
        logger.warn('XPENDING_FAILED', { msgId, error: pendingErr.message });
      }

      if (deliveryCount > MAX_RETRIES) {
        let rawData = '';
        for (let i = 0; i < (keyValues?.length ?? 0); i += 2) {
          if (keyValues[i] === 'data') { rawData = keyValues[i + 1]; break; }
        }
        await sendToDLQ(msgId, rawData, `MAX_RETRIES_EXCEEDED (${deliveryCount})`);
        await redisClient.xack(STREAM_KEY, GROUP_NAME, msgId);
        logger.error('EVENT_MAX_RETRIES_EXCEEDED', { msgId, deliveryCount });
        continue;
      }

      try {
        const ok = await processMessage(msgId, keyValues ?? []);
        if (ok) await redisClient.xack(STREAM_KEY, GROUP_NAME, msgId);
      } catch (err) {
        logger.error('RECLAIM_PROCESS_FAILED', { msgId, error: err.message });
      }
    }
  } catch (err) {
    logger.error('RECLAIM_PASS_FAILED', { error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN LOOP
// ─────────────────────────────────────────────────────────────────────────────
async function processStream() {
  logger.info('WORKER_STARTED', { consumer: CONSUMER_NAME, stream: STREAM_KEY });

  let iterCount = 0;
  workerAliveGauge.set({ worker: 'eventWorker' }, 1);

  while (!shuttingDown) {
    try {
      iterCount++;
      if (iterCount % 10 === 0) {
        workerAliveGauge.set({ worker: 'eventWorker' }, 1);
        redisConnectionStatus.set(redisClient.status === 'ready' ? 1 : 0);
        // Track stream lag periodically
        const info = await redisClient.xinfo('GROUPS', STREAM_KEY).catch(() => null);
        if (info) {
          const groupInfo = info.find(g => Array.isArray(g) ? g[1] === GROUP_NAME : g.name === GROUP_NAME);
          if (groupInfo) {
            let lagVal = 0;
            if (Array.isArray(groupInfo)) {
              const lagMatch = groupInfo.indexOf('lag');
              if (lagMatch !== -1) lagVal = groupInfo[lagMatch + 1];
            } else {
              lagVal = groupInfo.lag;
            }
            redisStreamLag.set({ stream: STREAM_KEY, group: GROUP_NAME }, lagVal ?? 0);
            processingBacklogSize.set({ stream: STREAM_KEY }, lagVal ?? 0);
          }
        }
      }

      const response = await redisClient.xreadgroup(
        'GROUP', GROUP_NAME, CONSUMER_NAME,
        'COUNT', 50,
        'BLOCK', 5000,
        'STREAMS', STREAM_KEY, '>'
      );

      if (response && response.length > 0) {
        const messages = response[0][1];

        if (messages.length > 0) {
          logger.info('WORKER_BATCH', { count: messages.length, consumer: CONSUMER_NAME });
        }

        for (const [messageId, keyValues] of messages) {
          if (shuttingDown) break;
          try {
            const ok = await processMessage(messageId, keyValues);
            if (ok) await redisClient.xack(STREAM_KEY, GROUP_NAME, messageId);
          } catch (err) {
            // Leave in PEL — reclaim will retry
            logger.error('EVENT_PROCESS_FAILED', { messageId, error: err.message });
          }
        }
      }

      // TASK 3: Reclaim pass on every iteration
      await reclaimAndRetry();

      // ── Consumer lag metrics ───────────────────────────────────────────────
      try {
        const groups = await redisClient.xinfo('GROUPS', STREAM_KEY);
        for (const g of groups) {
          let name, lag, pending;
          if (Array.isArray(g)) {
            for (let i = 0; i < g.length; i += 2) {
              if (g[i] === 'name')    name    = g[i + 1];
              if (g[i] === 'lag')     lag     = g[i + 1];
              if (g[i] === 'pending') pending = g[i + 1];
            }
          } else {
            name = g.name; lag = g.lag; pending = g.pending;
          }
          if (name === GROUP_NAME) {
            const finalLag = (lag !== undefined && lag !== null) ? lag : (pending || 0);
            streamConsumerLag.set({ stream: STREAM_KEY, group: GROUP_NAME }, finalLag);
          }
        }
      } catch (metricsErr) {
        logger.error('METRICS_LAG_FAILED', { error: metricsErr.message });
      }

    } catch (err) {
      logger.error('STREAM_LOOP_ERROR', { error: err.message });
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────
(async () => {
  try {
    await initializeRedis();
    await processStream();
  } catch (err) {
    logger.error('WORKER_FATAL', { error: err.message });
    process.exit(1);
  }
})();