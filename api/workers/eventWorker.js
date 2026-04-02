import Redis from 'ioredis';
import { PrismaClient } from '@prisma/client';
import winston from 'winston';
import { streamConsumerLag } from '../src/metrics/metrics.js';
import { RiskEngine } from './riskEngine.js';

const prisma = new PrismaClient();
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()],
});

const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
redisClient.on('error', (err) => logger.error('Redis Worker Error:', err.message));

const riskEngine = new RiskEngine(redisClient);

// ─────────────────────────────────────────────
// STREAM / GROUP CONSTANTS
// ─────────────────────────────────────────────
const STREAM_KEY    = 'security_events';
const DLQ_KEY       = 'security_events_dlq';  // dead-letter stream
const GROUP_NAME    = 'audit_workers';
const CONSUMER_NAME = `worker_${process.pid}`;

// ─────────────────────────────────────────────
// DLQ / RECLAIM POLICY
// ─────────────────────────────────────────────
const MAX_RETRIES   = 3;       // move to DLQ after this many delivery attempts
const CLAIM_IDLE_MS = 30_000;  // reclaim messages idle for > 30 s
const RECLAIM_COUNT = 50;      // max messages to inspect per reclaim pass

// ─────────────────────────────────────────────
// GRACEFUL SHUTDOWN
// ─────────────────────────────────────────────
let shuttingDown = false;

async function shutdown(signal) {
  logger.info('WORKER_SHUTDOWN_INITIATED', { signal });
  shuttingDown = true;
  // Give the current batch a moment to finish its DB write + ACK
  await new Promise((r) => setTimeout(r, 2000));
  await redisClient.quit();
  await prisma.$disconnect();
  logger.info('WORKER_SHUTDOWN_COMPLETE');
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ─────────────────────────────────────────────
// BOOTSTRAP: ensure consumer group exists
// ─────────────────────────────────────────────
async function initializeRedis() {
  try {
    // '0' = replay from beginning; MKSTREAM = create stream if absent
    await redisClient.xgroup('CREATE', STREAM_KEY, GROUP_NAME, '0', 'MKSTREAM');
    logger.info('CONSUMER_GROUP_CREATED', { group: GROUP_NAME });
  } catch (err) {
    if (err.message.includes('BUSYGROUP')) {
      logger.info('CONSUMER_GROUP_EXISTS', { group: GROUP_NAME });
    } else {
      throw err;
    }
  }
}

// ─────────────────────────────────────────────
// DB WRITE  (sole writer — no duplicate inserts)
// ─────────────────────────────────────────────
async function saveToPostgres(eventData) {
  await prisma.auditLog.create({
    data: {
      userId:
        eventData.user_id && eventData.user_id !== 'SYSTEM'
          ? eventData.user_id
          : undefined,
      action:    eventData.action     || 'UNKNOWN',
      status:    eventData.result     || 'SUCCESS',
      ip:        eventData.source_ip  || 'unknown',
      userAgent: eventData.user_agent || 'unknown',
      metadata:  eventData,
    },
  });
}

// ─────────────────────────────────────────────
// NEO4J STUB (log-scraping compatibility preserved)
// ─────────────────────────────────────────────
function saveToNeo4j(eventData) {
  logger.info('GRAPH_EVENT', eventData);
}

// ─────────────────────────────────────────────
// DEAD-LETTER QUEUE
// Archives permanently failed messages to a separate
// stream for manual inspection and replay.
// ─────────────────────────────────────────────
async function sendToDLQ(messageId, rawData, reason) {
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
    logger.error('EVENT_SENT_TO_DLQ', { messageId, reason });
  } catch (dlqErr) {
    // DLQ write failure must never crash the main loop
    logger.error('DLQ_WRITE_FAILED', { messageId, error: dlqErr.message });
  }
}

// ─────────────────────────────────────────────
// PROCESS ONE MESSAGE
// Returns true when the caller should ACK.
// Throws on transient DB errors so the message
// remains in the PEL for the reclaim loop to retry.
// ─────────────────────────────────────────────
async function processMessage(messageId, keyValues) {
  // Extract 'data' from the flat ['key','val',...] array ioredis returns
  let rawData = null;
  for (let i = 0; i < keyValues.length; i += 2) {
    if (keyValues[i] === 'data') { rawData = keyValues[i + 1]; break; }
  }

  if (!rawData) {
    logger.warn('EVENT_MISSING_DATA_FIELD', { messageId });
    return true; // ACK — permanently malformed, no point retrying
  }

  let eventData;
  try {
    eventData = JSON.parse(rawData);
  } catch {
    await sendToDLQ(messageId, rawData, 'JSON_PARSE_ERROR');
    return true; // ACK — unparseable messages must not loop forever
  }

  // Throws on DB error → caller skips ACK → PEL retains message for reclaim
  await saveToPostgres(eventData);
  saveToNeo4j(eventData);

  // Non-blocking Risk Evaluation
  riskEngine.processEvent(eventData).catch(err => {
    logger.error('RISK_ENGINE_ERROR', { error: err.message, event_id: eventData?.event_id });
  });

  return true;
}

// ─────────────────────────────────────────────
// RECLAIM + DLQ ESCALATION
// Uses XAUTOCLAIM (Redis >= 6.2, confirmed Redis 7).
// Runs after every main batch:
//   • Reclaims messages idle > CLAIM_IDLE_MS
//   • Retries up to MAX_RETRIES times
//   • Moves permanently failed messages to DLQ + ACKs them
// ─────────────────────────────────────────────
async function reclaimAndRetry() {
  try {
    // Returns [nextCursor, [[id, fields], ...], [deletedIds]]
    const result = await redisClient.xautoclaim(
      STREAM_KEY, GROUP_NAME, CONSUMER_NAME,
      CLAIM_IDLE_MS, '0-0',
      'COUNT', RECLAIM_COUNT
    );

    const claimed = result[1] ?? [];
    if (claimed.length === 0) return;

    logger.info('RECLAIM_PASS', { count: claimed.length });

    for (const [msgId, keyValues] of claimed) {
      // XPENDING with explicit ID range returns per-message delivery count
      const pending = await redisClient.xpending(
        STREAM_KEY, GROUP_NAME, msgId, msgId, 1
      );
      const deliveryCount = pending[0]?.[3] ?? 0;

      if (deliveryCount > MAX_RETRIES) {
        let rawData = '';
        for (let i = 0; i < (keyValues?.length ?? 0); i += 2) {
          if (keyValues[i] === 'data') { rawData = keyValues[i + 1]; break; }
        }
        await sendToDLQ(msgId, rawData, `MAX_RETRIES_EXCEEDED (${deliveryCount})`);
        await redisClient.xack(STREAM_KEY, GROUP_NAME, msgId);
        continue;
      }

      try {
        const ok = await processMessage(msgId, keyValues ?? []);
        if (ok) await redisClient.xack(STREAM_KEY, GROUP_NAME, msgId);
      } catch (err) {
        logger.error('RECLAIM_PROCESS_FAILED', { msgId, error: err.message });
        // Leave in PEL — next reclaim pass will pick it up again
      }
    }
  } catch (err) {
    logger.error('RECLAIM_PASS_FAILED', { error: err.message });
  }
}

// ─────────────────────────────────────────────
// MAIN LOOP
// ─────────────────────────────────────────────
async function processStream() {
  logger.info('WORKER_STARTED', { consumer: CONSUMER_NAME, stream: STREAM_KEY });

  while (!shuttingDown) {
    try {
      // '>' = only messages not yet delivered to any consumer in this group
      const response = await redisClient.xreadgroup(
        'GROUP', GROUP_NAME, CONSUMER_NAME,
        'COUNT', 50,
        'BLOCK', 5000,
        'STREAMS', STREAM_KEY, '>'
      );

      if (response && response.length > 0) {
        const messages = response[0][1];

        if (messages.length > 0) {
          logger.info('WORKER_BATCH', { count: messages.length });
        }

        for (const [messageId, keyValues] of messages) {
          if (shuttingDown) break;
          try {
            const ok = await processMessage(messageId, keyValues);
            if (ok) await redisClient.xack(STREAM_KEY, GROUP_NAME, messageId);
          } catch (err) {
            // Transient DB error — skip ACK so reclaim loop can retry
            logger.error('EVENT_PROCESS_FAILED', { messageId, error: err.message });
          }
        }
      }

      // Run reclaim pass after every batch (near-zero cost when PEL is empty)
      await reclaimAndRetry();

      try {
        const groups = await redisClient.xinfo('GROUPS', STREAM_KEY);
        for (const g of groups) {
          let name, lag, pending;
          if (Array.isArray(g)) {
            for (let i = 0; i < g.length; i += 2) {
              if (g[i] === 'name') name = g[i+1];
              if (g[i] === 'lag') lag = g[i+1];
              if (g[i] === 'pending') pending = g[i+1];
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

// ─────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────
(async () => {
  try {
    await initializeRedis();
    await processStream();
  } catch (err) {
    logger.error('WORKER_FATAL', { error: err.message });
    process.exit(1);
  }
})();