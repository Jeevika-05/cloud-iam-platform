/**
 * ─────────────────────────────────────────────────────────────────────────────
 * defenseWorker.js — Reliable Stream-Based Defense Action Worker
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * TASK 1: SCAN → XREADGROUP (Stream Consumer Group)
 * TASK 3: Full failure recovery (PEL reclaim, DLQ, idempotent dispatch)
 *
 * ── ARCHITECTURE ─────────────────────────────────────────────────────────────
 *
 *   Producer: riskEngine._pushDefenseTask()
 *     → XADD defense_events * data <JSON>
 *
 *   Consumer: defenseWorker (this file)
 *     → XREADGROUP GROUP defense_workers worker_<pid> COUNT 10 BLOCK 2000
 *          STREAMS defense_events >
 *     → process each message (strike/ban via recordStrike)
 *     → XACK defense_events defense_workers <msgId>
 *
 * ── RELIABILITY ──────────────────────────────────────────────────────────────
 *
 *   Delivery guarantee: at-least-once (PEL ensures no message lost on crash)
 *
 *   Idempotency (prevents double-strike):
 *     Each message has a dedup_key: "<ip>:<slot>:<severity>"
 *     Before calling recordStrike, worker runs:
 *       SET defense:dedup:<dedup_key> 1 EX 600 NX
 *     If NX fails (key exists) → already executed → ACK without action.
 *     This means: even if a message is re-delivered 3x (crash during processing),
 *     only ONE recordStrike() will fire.
 *
 *   Retry policy:
 *     - Message stays in PEL until XACK.
 *     - XAUTOCLAIM reclaims messages idle > 30s.
 *     - After MAX_RETRIES deliveries → send to defense_events_dlq + XACK.
 *
 *   DLQ:
 *     - defense_events_dlq is a separate Redis Stream (MAXLEN ~1000).
 *     - Permanently failing defense tasks land here for manual inspection.
 *
 *   Multi-instance safety:
 *     - Multiple defenseWorker processes can run concurrently.
 *     - XREADGROUP delivers each message to exactly ONE consumer.
 *     - The dedup SET NX is a belt-and-suspenders guard even if two workers
 *       claim overlapping PEL during a reclaim race (extremely rare).
 *
 * ── STARTUP RECOVERY ─────────────────────────────────────────────────────────
 *   On startup, the worker runs a PEL reclaim pass for messages assigned to
 *   crashed consumers (idle > CLAIM_IDLE_MS). This ensures no defense task
 *   is silently lost when a previous worker instance crashed mid-processing.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

import Redis   from 'ioredis';
import winston from 'winston';
import { redis as redisConfig } from '../src/shared/config/index.js';
import { recordStrike }         from '../src/shared/middleware/activeDefender.js';
import { 
  dlqSize, retryAttemptsTotal, redisStreamLag, eventsInflightGauge,
  workerAliveGauge, redisConnectionStatus, processingBacklogSize,
  workerLastProcessedTimestamp 
} from '../src/metrics/metrics.js';

// ─────────────────────────────────────────────
// Logger
// ─────────────────────────────────────────────
const logger = winston.createLogger({
  level:  process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'defense-worker', pid: process.pid },
  transports:  [new winston.transports.Console()],
});

// ─────────────────────────────────────────────
// Redis client — dedicated connection for this process
// ─────────────────────────────────────────────
const redisClient = new Redis(redisConfig.url, {
  retryStrategy:      (times) => Math.min(times * 200, 10_000),
  enableOfflineQueue: true,
  lazyConnect:        false,
});
redisClient.on('error',        (err) => logger.error('REDIS_ERROR',        { error: err.message }));
redisClient.on('reconnecting', ()    => logger.warn ('REDIS_RECONNECTING'));
redisClient.on('connect',      ()    => logger.info ('REDIS_CONNECTED'));

// ─────────────────────────────────────────────
// STREAM / GROUP CONSTANTS
// ─────────────────────────────────────────────
const DEFENSE_STREAM   = 'defense_events';
const DEFENSE_DLQ      = 'defense_events_dlq';
const GROUP_NAME       = 'defense_workers';
const CONSUMER_NAME    = `defense_worker_${process.pid}`;

// ─────────────────────────────────────────────
// RELIABILITY CONSTANTS
// ─────────────────────────────────────────────
const MAX_RETRIES        = 3;          // max delivery attempts before DLQ
const CLAIM_IDLE_MS      = 30_000;     // reclaim messages idle > 30s
const RECLAIM_COUNT      = 50;         // max messages per reclaim pass
const BATCH_SIZE         = 10;         // messages per XREADGROUP read
const BLOCK_MS           = 2_000;      // BLOCK timeout on XREADGROUP
const DEDUP_TTL_SECONDS  = 600;        // 10 min — matches riskEngine slot window
const DEDUP_KEY          = (k) => `defense:dedup:${k}`;

// ─────────────────────────────────────────────
// GRACEFUL SHUTDOWN
// ─────────────────────────────────────────────
let shuttingDown = false;

async function shutdown(signal) {
  logger.info('DEFENSE_WORKER_SHUTDOWN', { signal });
  shuttingDown = true;
  await new Promise(r => setTimeout(r, 1500));
  await redisClient.quit();
  logger.info('DEFENSE_WORKER_STOPPED', { signal });
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ─────────────────────────────────────────────
// BOOTSTRAP — create consumer group + startup PEL reclaim
// ─────────────────────────────────────────────
async function initialize() {
  // Readiness check
  let retries = 10;
  while (retries--) {
    try {
      await redisClient.ping();
      break;
    } catch {
      if (retries === 0) throw new Error('Redis not ready after 10 attempts');
      logger.warn('REDIS_NOT_READY', { retriesLeft: retries });
      await new Promise(r => setTimeout(r, 2000));
    }
  }

  // Create consumer group (idempotent — BUSYGROUP is expected on restart)
  try {
    await redisClient.xgroup('CREATE', DEFENSE_STREAM, GROUP_NAME, '0', 'MKSTREAM');
    logger.info('DEFENSE_GROUP_CREATED', { group: GROUP_NAME, stream: DEFENSE_STREAM });
  } catch (err) {
    if (err.message.includes('BUSYGROUP')) {
      logger.info('DEFENSE_GROUP_EXISTS', { group: GROUP_NAME });
    } else {
      throw err;
    }
  }

  // TASK 3: Startup PEL reclaim — recover messages from crashed consumers
  logger.info('DEFENSE_STARTUP_RECLAIM', { idle_ms: CLAIM_IDLE_MS });
  await reclaimAndRetry();
}

// ─────────────────────────────────────────────
// DLQ WRITER
// ─────────────────────────────────────────────
async function sendToDLQ(messageId, rawData, reason, context = {}) {
  try {
    await redisClient.xadd(
      DEFENSE_DLQ,
      'MAXLEN', '~', 1_000,
      '*',
      'original_id', messageId,
      'data',        rawData || '',
      'reason',      reason,
      'failed_at',   new Date().toISOString()
    );
    dlqSize.inc({ stream: DEFENSE_DLQ });
    logger.error('DEFENSE_SENT_TO_DLQ', { messageId, reason, ...context });
  } catch (dlqErr) {
    logger.error('DEFENSE_DLQ_WRITE_FAILED', { messageId, error: dlqErr.message });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROCESS ONE DEFENSE MESSAGE
//
// Returns true  → caller should XACK.
// Returns false → transient failure; leave in PEL for retry.
//
// IDEMPOTENCY CONTRACT:
//   1. Parse dedup_key from payload.
//   2. SET defense:dedup:<dedup_key> 1 EX 600 NX
//   3. If NX returns null → key existed → already executed → ACK without action.
//   4. If NX returns 'OK' → first execution → call recordStrike() → ACK.
//   5. If recordStrike() throws → delete dedup key (allow retry) → return false.
//
// This means:
//   - Exactly one recordStrike() fires per (ip, slot, severity) combination.
//   - Worker crashes between recordStrike() and XACK → message re-delivered
//     → dedup key still set → skipped silently → ACK.
//   - Worker crashes before recordStrike() sets dedup key → re-delivered
//     → dedup key absent → retried correctly.
// ─────────────────────────────────────────────────────────────────────────────
async function processDefenseMessage(messageId, keyValues) {
  eventsInflightGauge.inc({ worker: 'defenseWorker' });
  // ── 1. Extract data field from flat ioredis array ─────────────────────────
  let rawData = null;
  for (let i = 0; i < keyValues.length; i += 2) {
    if (keyValues[i] === 'data') { rawData = keyValues[i + 1]; break; }
  }

  if (!rawData) {
    logger.warn('DEFENSE_MISSING_DATA', { messageId });
    eventsInflightGauge.dec({ worker: 'defenseWorker' });
    return true; // ACK — permanently malformed, no value in retrying
  }

  // ── 2. Parse JSON ──────────────────────────────────────────────────────────
  let task;
  try {
    task = JSON.parse(rawData);
  } catch {
    await sendToDLQ(messageId, rawData, 'JSON_PARSE_ERROR');
    eventsInflightGauge.dec({ worker: 'defenseWorker' });
    return true;
  }

  const { source_ip, severity, reason, score, dedup_key, correlation_id, event_id } = task;

  if (!source_ip || !severity || !dedup_key) {
    logger.warn('DEFENSE_INVALID_PAYLOAD', { messageId, task });
    await sendToDLQ(messageId, rawData, 'INVALID_PAYLOAD_MISSING_FIELDS');
    eventsInflightGauge.dec({ worker: 'defenseWorker' });
    return true;
  }

  // ── 3. Deduplication via SET NX ───────────────────────────────────────────
  // This is the idempotency gate. Only ONE worker instance (or retry) will
  // get 'OK' from this call. All others see null and skip.
  const dedupResult = await redisClient.set(
    DEDUP_KEY(dedup_key),
    '1',
    'EX', DEDUP_TTL_SECONDS,
    'NX'
  );

  if (dedupResult === null) {
    // Already executed (or being executed) — ACK and skip
    logger.debug('DEFENSE_DEDUP_SKIPPED', {
      dedup_key,
      source_ip,
      severity,
      correlation_id: correlation_id ?? null,
      event_id:       event_id       ?? null,
    });
    eventsInflightGauge.dec({ worker: 'defenseWorker' });
    return true;
  }

  // ── 4. Execute defense action ─────────────────────────────────────────────
  try {
    await recordStrike(
      source_ip,
      severity,
      reason || `defense_stream_score_${score ?? 0}`,
      { correlation_id: correlation_id ?? null, event_id: event_id ?? null }
    );

    logger.info('DEFENSE_STRIKE_EXECUTED', {
      source_ip,
      severity,
      score:          score ?? null,
      dedup_key,
      correlation_id: correlation_id ?? null,
      event_id:       event_id       ?? null,
    });

    workerLastProcessedTimestamp.set({ worker: 'defenseWorker' }, Date.now());
    eventsInflightGauge.dec({ worker: 'defenseWorker' });
    return true; // ACK

  } catch (err) {
    logger.error('DEFENSE_STRIKE_FAILED', {
      source_ip,
      severity,
      error:          err.message,
      dedup_key,
      correlation_id: correlation_id ?? null,
    });

    // TASK 3: On failure, delete the dedup key so the next retry can re-attempt.
    // Without this, a failed execution would leave the dedup key set and the
    // retry would skip, silently losing the defense action.
    try {
      await redisClient.del(DEDUP_KEY(dedup_key));
    } catch (delErr) {
      logger.error('DEFENSE_DEDUP_KEY_DEL_FAILED', { dedup_key, error: delErr.message });
    }

    eventsInflightGauge.dec({ worker: 'defenseWorker' });
    return false; // Leave in PEL — retry on next reclaim pass
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RECLAIM + DLQ ESCALATION
//
// TASK 3: Uses XAUTOCLAIM to reclaim messages idle > CLAIM_IDLE_MS.
// This recovers messages from:
//   - Crashed workers (never ACK'd)
//   - Slow workers (took too long)
//
// After MAX_RETRIES → DLQ + XACK (no infinite retry).
// ─────────────────────────────────────────────────────────────────────────────
async function reclaimAndRetry() {
  try {
    // XAUTOCLAIM reassigns idle PEL messages from any consumer to us
    const result = await redisClient.xautoclaim(
      DEFENSE_STREAM, GROUP_NAME, CONSUMER_NAME,
      CLAIM_IDLE_MS, '0-0',
      'COUNT', RECLAIM_COUNT
    );

    const claimed = result[1] ?? [];
    if (claimed.length === 0) return;

    logger.info('DEFENSE_RECLAIM_PASS', { count: claimed.length });
    retryAttemptsTotal.inc({ stream: DEFENSE_STREAM }, claimed.length);

    for (const [msgId, keyValues] of claimed) {
      // Check delivery count — escalate to DLQ if beyond MAX_RETRIES
      let deliveryCount = 0;
      try {
        const pending = await redisClient.xpending(
          DEFENSE_STREAM, GROUP_NAME, msgId, msgId, 1
        );
        deliveryCount = pending[0]?.[3] ?? 0;
      } catch (pendingErr) {
        logger.warn('DEFENSE_XPENDING_FAILED', { msgId, error: pendingErr.message });
      }

      if (deliveryCount > MAX_RETRIES) {
        let rawData = '';
        for (let i = 0; i < (keyValues?.length ?? 0); i += 2) {
          if (keyValues[i] === 'data') { rawData = keyValues[i + 1]; break; }
        }
        await sendToDLQ(msgId, rawData, `MAX_RETRIES_EXCEEDED (${deliveryCount})`);
        await redisClient.xack(DEFENSE_STREAM, GROUP_NAME, msgId);
        logger.error('DEFENSE_MAX_RETRIES_EXCEEDED', { msgId, deliveryCount });
        continue;
      }

      // Retry processing
      try {
        const ok = await processDefenseMessage(msgId, keyValues ?? []);
        if (ok) await redisClient.xack(DEFENSE_STREAM, GROUP_NAME, msgId);
        // If not ok → stays in PEL → next reclaim pass picks it up
      } catch (err) {
        logger.error('DEFENSE_RECLAIM_PROCESS_FAILED', { msgId, error: err.message });
      }
    }
  } catch (err) {
    logger.error('DEFENSE_RECLAIM_PASS_FAILED', { error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN LOOP
// ─────────────────────────────────────────────────────────────────────────────
async function run() {
  logger.info('DEFENSE_WORKER_STARTED', {
    consumer:  CONSUMER_NAME,
    stream:    DEFENSE_STREAM,
    group:     GROUP_NAME,
    batch:     BATCH_SIZE,
    block_ms:  BLOCK_MS,
  });

  let iterCount = 0;
  workerAliveGauge.set({ worker: 'defenseWorker' }, 1);

  while (!shuttingDown) {
    try {
      iterCount++;
      if (iterCount % 10 === 0) {
        workerAliveGauge.set({ worker: 'defenseWorker' }, 1);
        redisConnectionStatus.set(redisClient.status === 'ready' ? 1 : 0);
        // Track stream lag periodically
        const info = await redisClient.xinfo('GROUPS', DEFENSE_STREAM).catch(() => null);
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
            redisStreamLag.set({ stream: DEFENSE_STREAM, group: GROUP_NAME }, lagVal ?? 0);
            processingBacklogSize.set({ stream: DEFENSE_STREAM }, lagVal ?? 0);
          }
        }
      }

      // TASK 1: XREADGROUP — reliable, group-aware stream consumption
      const response = await redisClient.xreadgroup(
        'GROUP', GROUP_NAME, CONSUMER_NAME,
        'COUNT', BATCH_SIZE,
        'BLOCK', BLOCK_MS,
        'STREAMS', DEFENSE_STREAM, '>'
      );

      if (response && response.length > 0) {
        const messages = response[0][1];
        if (messages.length > 0) {
          logger.info('DEFENSE_BATCH', { count: messages.length });
        }

        for (const [messageId, keyValues] of messages) {
          if (shuttingDown) break;
          try {
            const ok = await processDefenseMessage(messageId, keyValues);
            if (ok) {
              await redisClient.xack(DEFENSE_STREAM, GROUP_NAME, messageId);
            }
            // If not ok → stays in PEL — reclaim loop will retry
          } catch (err) {
            // Unhandled error — leave in PEL for retry
            logger.error('DEFENSE_MESSAGE_PROCESS_ERROR', {
              messageId,
              error: err.message,
            });
          }
        }
      }

      // TASK 3: Reclaim pass after every batch — catches idle PEL messages
      await reclaimAndRetry();

    } catch (err) {
      logger.error('DEFENSE_STREAM_LOOP_ERROR', { error: err.message });
      await new Promise(r => setTimeout(r, 2000));
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────
(async () => {
  try {
    await initialize();
    await run();
  } catch (err) {
    logger.error('DEFENSE_WORKER_FATAL', { error: err.message });
    process.exit(1);
  }
})();
