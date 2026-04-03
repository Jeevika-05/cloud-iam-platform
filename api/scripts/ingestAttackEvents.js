/**
 * ─────────────────────────────────────────────────────────────────────────────
 * ATTACK EVENT INGESTION ADAPTER
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Reads ATTACK events from the Rust simulation engine's results.json and
 * pushes them into the shared `security_events` Redis stream BEFORE the
 * backend worker processes any DEFENSE events.
 *
 * This makes ATTACK events first-class citizens in the pipeline:
 *
 *   [Rust Engine → results.json]
 *         ↓  (this script)
 *   Redis Stream: security_events
 *         ↓
 *   [eventWorker.js]  ←  enrichSequenceAndParent → seq=1, parent=null
 *         ↓
 *   DEFENSE events    ←  enrichSequenceAndParent → seq=2, parent=ATTACK.event_id
 *         ↓
 *   Neo4j graph: ATTACK(1) → DEFENSE(2) → DEFENSE(3) …
 *
 * Guarantees:
 *   • Idempotent  — SETNX dedup key prevents re-ingestion on script re-run
 *   • Additive    — does NOT touch the Rust engine or existing worker logic
 *   • Ordered     — events are pushed in the order they appear in results.json
 *   • Schema-safe — every field required by downstream consumers is present
 *
 * Usage:
 *   node scripts/ingestAttackEvents.js [--file path/to/results.json] [--dry-run]
 *
 * Environment:
 *   REDIS_URL   — e.g. redis://localhost:6379  (falls back to config/index.js)
 *   RESULTS_FILE — override default path
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import Redis from 'ioredis';

// ─── Path helpers (ESM) ───────────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ─── CLI args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const DRY_RUN     = args.includes('--dry-run');
const fileArgIdx  = args.indexOf('--file');
const RESULTS_FILE = fileArgIdx !== -1
  ? args[fileArgIdx + 1]
  : process.env.RESULTS_FILE
    ?? path.resolve(__dirname, '../reports/results.json');

// ─── Redis ────────────────────────────────────────────────────────────────────
const REDIS_URL  = process.env.REDIS_URL ?? 'redis://localhost:6379';
const STREAM_KEY = 'security_events';

// Dedup key prefix — collision-free per correlation_id + event_id pair
const dedupKey = (correlationId, eventId) =>
  `attack:ingested:${correlationId}:${eventId}`;

// How long to keep the dedup sentinel (24 h — covers any replay window)
const DEDUP_TTL_S = 86_400;

// ─── Attack-category mapping ──────────────────────────────────────────────────
// Maps the Rust engine's `action` field to a human-readable attack category.
// Extend here when new attack types are added — never inline at call sites.
const ACTION_TO_ATTACK_CATEGORY = {
  TOKEN_RACE:                'SESSION_ATTACK',
  JWT_TAMPER:                'TOKEN_FORGERY',
  PASSWORD_BRUTE:            'BRUTE_FORCE',
  MFA_BRUTE_FORCE_SINGLE_IP: 'BRUTE_FORCE',
  MFA_DISTRIBUTED:           'BRUTE_FORCE',
  SESSION_REUSE:             'SESSION_ATTACK',
  SESSION_INVALIDATION:      'SESSION_ATTACK',
  IDOR:                      'AUTHORIZATION_ATTACK',
  CSRF:                      'CSRF',
  MASS_ASSIGNMENT:           'INJECTION',
  ACCESS_TOKEN_ABUSE:        'TOKEN_ABUSE',
  RATE_FLOOD:                'DENIAL_OF_SERVICE',
  MFA_REPLAY:                'REPLAY_ATTACK',
};

const resolveAttackCategory = (action) =>
  ACTION_TO_ATTACK_CATEGORY[action?.toUpperCase()] ?? 'UNKNOWN';

// ─── Schema transformer ───────────────────────────────────────────────────────
/**
 * Transforms a raw graph_event from results.json into the canonical event
 * schema used by eventWorker.js and downstream Neo4j ingestion.
 *
 * Fields NOT set here (set by eventWorker.enrichSequenceAndParent):
 *   • event_sequence_index
 *   • parent_event_id
 *
 * @param {object} raw  — one entry from results.json `graph_events[]`
 * @returns {object}    — normalized event ready for Redis xadd
 */
function transformAttackEvent(raw) {
  if (!raw.event_id)       throw new Error('Missing event_id');
  if (!raw.correlation_id) throw new Error('Missing correlation_id');
  if (!raw.action)         throw new Error('Missing action');
  if (!raw.source_ip)      throw new Error('Missing source_ip');

  return {
    // ── Identity ────────────────────────────────────────────────────────────
    event_id:        raw.event_id,
    correlation_id:  raw.correlation_id,

    // ── Classification ───────────────────────────────────────────────────────
    event_type:      'ATTACK',
    stage:           'DETECTION',
    attack_category: resolveAttackCategory(raw.action),

    // ── What happened ────────────────────────────────────────────────────────
    action:          raw.action,
    result:          raw.result   ?? 'UNKNOWN',
    severity:        raw.severity ?? 'MEDIUM',

    // ── Who / where ──────────────────────────────────────────────────────────
    source_ip:       raw.source_ip,
    ip_type:         raw.ip_type        ?? 'SIMULATED',
    target_endpoint: raw.target_endpoint ?? '/unknown',
    target_type:     raw.target_type    ?? 'API',

    // ── Agent metadata ───────────────────────────────────────────────────────
    user_id:         raw.user_id   ?? null,
    user_email:      raw.user_email ?? null,
    user_agent:      raw.user_agent ?? 'attack-engine',
    agent_type:      raw.agent_type ?? 'SIMULATED',

    // ── Timing ───────────────────────────────────────────────────────────────
    timestamp:       raw.timestamp ?? new Date().toISOString(),

    // ── Source tag (helps Neo4j distinguish ingested vs live events) ─────────
    ingestion_source: 'results_json',
  };
}

// ─── Ingestion ────────────────────────────────────────────────────────────────
/**
 * Attempts to push one ATTACK event into the Redis stream.
 * Returns 'ingested' | 'duplicate' | 'error'.
 */
async function ingestOne(redis, raw, idx) {
  let event;
  try {
    event = transformAttackEvent(raw);
  } catch (err) {
    console.error(`[SKIP] event[${idx}] transform failed — ${err.message}`, raw);
    return 'error';
  }

  // ── STEP 3: Deduplication (SETNX) ─────────────────────────────────────────
  // Use NX so that concurrent or repeated runs never double-push the same event.
  const dk = dedupKey(event.correlation_id, event.event_id);
  const acquired = await redis.set(dk, '1', 'EX', DEDUP_TTL_S, 'NX');
  if (acquired === null) {
    console.log(`[SKIP] Duplicate — correlation=${event.correlation_id} event=${event.event_id}`);
    return 'duplicate';
  }

  if (DRY_RUN) {
    console.log(`[DRY-RUN] Would push event_id=${event.event_id} action=${event.action}`);
    // Roll back the dedup key so a real run can still push it
    await redis.del(dk);
    return 'dry-run';
  }

  // ── STEP 1: Push into shared Redis stream ──────────────────────────────────
  // '*'  — let Redis auto-assign the stream entry ID (ordering by wall-clock)
  // eventWorker.enrichSequenceAndParent will stamp sequence + parent on consume
  await redis.xadd(
    STREAM_KEY,
    'MAXLEN', '~', '10000',
    '*',
    'data', JSON.stringify(event)
  );

  console.log(`[OK]   Ingested  event_id=${event.event_id} action=${event.action} corr=${event.correlation_id}`);
  return 'ingested';
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log('══════════════════════════════════════════════════');
  console.log(' ATTACK EVENT INGESTION ADAPTER');
  console.log(` File    : ${RESULTS_FILE}`);
  console.log(` Redis   : ${REDIS_URL}`);
  console.log(` Dry-run : ${DRY_RUN}`);
  console.log('══════════════════════════════════════════════════\n');

  // ── Load results.json ───────────────────────────────────────────────────────
  let raw;
  try {
    const text = await fs.readFile(RESULTS_FILE, 'utf8');
    raw = JSON.parse(text);
  } catch (err) {
    console.error(`[FATAL] Cannot read ${RESULTS_FILE}: ${err.message}`);
    process.exit(1);
  }

  const graphEvents = raw?.graph_events;
  if (!Array.isArray(graphEvents) || graphEvents.length === 0) {
    console.warn('[WARN] No graph_events found in results.json — nothing to ingest.');
    process.exit(0);
  }

  console.log(`Found ${graphEvents.length} ATTACK event(s) to process.\n`);

  // ── Connect to Redis ────────────────────────────────────────────────────────
  const redis = new Redis(REDIS_URL);
  redis.on('error', (err) => {
    console.error('[REDIS ERROR]', err.message);
  });

  // ── Ingest events sequentially (preserves results.json ordering) ────────────
  // Sequential processing is intentional: ATTACK events must be pushed in
  // chronological order so that stream entry IDs reflect the attack timeline.
  const stats = { ingested: 0, duplicate: 0, error: 0, 'dry-run': 0 };

  for (let i = 0; i < graphEvents.length; i++) {
    const outcome = await ingestOne(redis, graphEvents[i], i);
    stats[outcome] = (stats[outcome] ?? 0) + 1;
  }

  await redis.quit();

  console.log('\n══════════════════════════════════════════════════');
  console.log(' INGESTION COMPLETE');
  console.log(`  Ingested  : ${stats.ingested}`);
  console.log(`  Duplicates: ${stats.duplicate}`);
  console.log(`  Errors    : ${stats.error}`);
  if (DRY_RUN) console.log(`  Dry-run   : ${stats['dry-run']}`);
  console.log('══════════════════════════════════════════════════\n');

  if (stats.error > 0) process.exit(1);
}

main().catch((err) => {
  console.error('[UNHANDLED]', err);
  process.exit(1);
});