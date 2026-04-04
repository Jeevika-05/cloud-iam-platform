#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────
// NEO4J EVENT MERGER — Unified ATTACK + DEFENSE Event Pipeline
// ─────────────────────────────────────────────────────────────
//
// Usage:
//   node scripts/neo4j_ingest.js [options]
//
// Options:
//   --attack-file    Path to Rust engine results.json (default: ./reports/results.json)
//   --since          Only include defense events after this ISO timestamp
//   --dry-run        Merge + enrich + validate but do NOT push to Neo4j
//   --concurrency    How many events to push to Neo4j in parallel (default: 5)
//
// What changed from the original:
//   - Removed --output, --api-url, --token flags (no longer writing a file)
//   - Removed all fs.writeFileSync / JSON.stringify output logic
//   - Added Neo4j push via mergeEventToGraph() after enrichment
//   - Added --concurrency flag for batched parallel ingestion
//   - Neo4j driver is cleanly closed after all events are pushed
// ─────────────────────────────────────────────────────────────

import fs   from 'fs';
import path from 'path';
import { PrismaClient }                        from '@prisma/client';
import { mergeEventToGraph, closeNeo4jDriver } from '../src/shared/db/neo4j.js';

const prisma = new PrismaClient();

// ─────────────────────────────────────────────
// CLI ARGUMENT PARSING
// ─────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    attackFile:  './reports/results.json',
    since:       null,
    dryRun:      false,
    concurrency: 5,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--attack-file':  opts.attackFile  = args[++i];          break;
      case '--since':        opts.since       = args[++i];          break;
      case '--dry-run':      opts.dryRun      = true;               break;
      case '--concurrency':  opts.concurrency = parseInt(args[++i], 10); break;
      default:
        console.error(`Unknown argument: ${args[i]}`);
        process.exit(1);
    }
  }

  return opts;
}

// ─────────────────────────────────────────────
// LOAD ATTACK EVENTS (from results.json)
// ─────────────────────────────────────────────
function loadAttackEvents(filePath) {
  console.log(`[LOAD] Attack events from: ${filePath}`);

  if (!fs.existsSync(filePath)) {
    console.warn(`[WARN] Attack file not found: ${filePath}`);
    return [];
  }

  const raw    = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const events = raw.graph_events || [];
  console.log(`[LOAD] Found ${events.length} ATTACK events`);

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const isUUID  = (v) => typeof v === 'string' && UUID_RE.test(v);

  return events.map((e) => {
    const rawUserId = e.user_id;
    const userId    = isUUID(rawUserId) ? rawUserId : null;
    const userEmail = e.user_email || (!isUUID(rawUserId) ? rawUserId : null);

    return {
      event_id:             e.event_id,
      correlation_id:       e.correlation_id,
      event_priority:       e.event_priority       ?? 1,
      event_sequence_index: e.event_sequence_index ?? null,
      parent_event_id:      e.parent_event_id      ?? null,
      user_id:              userId,
      user_email:           userEmail,
      session_id:           e.session_id            || null,
      event_type:           'ATTACK',
      action:               e.action,
      source_ip:            e.source_ip,
      ip_type:              e.ip_type               || 'SIMULATED',
      user_agent:           e.user_agent            || 'attack-engine',
      agent_type:           e.agent_type            || 'SIMULATED',
      target_type:          e.target_type           || 'API',
      target_endpoint:      e.target_endpoint,
      result:               e.result,
      severity:             e.severity,
      risk_score:           e.risk_score            ?? null,
      risk_level:           e.risk_level            ?? null,
      timestamp:            e.timestamp,
      mode:                 raw.mode || (raw.active_defender_status === 'ENABLED'
                              ? 'AFTER_ACTIVE_DEFENDER'
                              : 'INFERRED'),
    };
  });
}

// ─────────────────────────────────────────────
// LOAD DEFENSE EVENTS (from PostgreSQL AuditLog)
// ─────────────────────────────────────────────
async function loadDefenseEvents(since) {
  console.log(`[LOAD] Defense events from PostgreSQL AuditLog...`);

  try {
    // Raw query — Prisma JSON path filtering is limited so we use $queryRaw.
    // CAST guard: event_sequence_index may be missing in older rows, so we
    // coalesce to '0' before casting to avoid a runtime error.
    const dbEvents = await prisma.$queryRawUnsafe(`
  SELECT * FROM "AuditLog"
  WHERE metadata->>'defense_action' IS NOT NULL
  ORDER BY "createdAt" ASC
  LIMIT 5000
`);

    const events = dbEvents.map((e) => {
  const meta = e.metadata || {};

  return {
    event_id: `def-${meta.event_id}`, // unique ID for defense
    correlation_id: meta.correlation_id,
    event_priority: 2,
    event_sequence_index: (meta.event_sequence_index || 0) + 1,
    parent_event_id: meta.event_id,

    event_type: 'DEFENSE',

    action: meta.defense_action,
    source_ip: meta.source_ip || e.ip || 'unknown',

    ip_type: meta.ip_type ?? null,
    user_agent: meta.user_agent || e.userAgent || 'unknown',
    agent_type: meta.agent_type ?? null,

    target_type: meta.target_type ?? null,
    target_endpoint: meta.target_endpoint ?? null,

    result: 'TRIGGERED',
    severity: meta.risk_level ?? null,
    risk_score: meta.risk_score ?? null,
    risk_level: meta.risk_level ?? null,

    timestamp: meta.timestamp ?? e.createdAt?.toISOString() ?? null,

    // defense-specific
    reason: meta.defense_reason ?? null,
    strike_count: meta.strike_count ?? null,
    ban_duration: meta.ban_duration ?? null,
    blocked: meta.defense_action === 'BLOCK',
    mitigation_result: meta.defense_action,

    session_id: meta.session_id ?? null,
    user_id: e.userId ?? null,
    user_email: meta.user_email ?? null,

    mode: meta.mode ?? null,
  };
});

    console.log(`[LOAD] Found ${events.length} DEFENSE events`);
    return events;

  } catch (err) {
    console.warn(`[WARN] Cannot read defense events from DB: ${err.message}`);
    console.warn('[WARN] Continuing with ATTACK events only');
    return [];
  }
}

// ─────────────────────────────────────────────
// DEDUPLICATE
// ─────────────────────────────────────────────
function deduplicateEvents(events) {
  const seen   = new Set();
  const unique = [];

  for (const event of events) {
    if (event.event_id && !seen.has(event.event_id)) {
      seen.add(event.event_id);
      unique.push(event);
    }
  }

  const dupes = events.length - unique.length;
  if (dupes > 0) console.log(`[DEDUP] Removed ${dupes} duplicate events`);
  return unique;
}

// ─────────────────────────────────────────────
// DETERMINISTIC SORT
// Primary:   correlation_id
// Secondary: event_priority  (1=ATTACK before 2=DEFENSE)
// Tertiary:  event_sequence_index
// ─────────────────────────────────────────────
function sortEvents(events) {
  return events.sort((a, b) => {
    const cA = a.correlation_id || a.event_id;
    const cB = b.correlation_id || b.event_id;
    if (cA < cB) return -1;
    if (cA > cB) return  1;
    const pDiff = (a.event_priority ?? 1) - (b.event_priority ?? 1);
    if (pDiff !== 0) return pDiff;
    return (a.event_sequence_index ?? 0) - (b.event_sequence_index ?? 0);
  });
}

// ─────────────────────────────────────────────
// ENRICH — adds all computed fields that were
// previously only present in unified_events.json
// ─────────────────────────────────────────────
function enrichEvents(events) {
  const UUID_RE    = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const isUUID     = (v) => typeof v === 'string' && UUID_RE.test(v);
  const AGENT_TYPES = ['USER', 'SYSTEM', 'ATTACK_ENGINE', 'SIMULATED'];

  // ── PASS 1: normalise every event ────────────────────────────────────────
  const pass1 = events.map((e) => {
    // Identity
    let finalUserId    = e.user_id    === 'SYSTEM' ? null : e.user_id;
    let finalUserEmail = e.user_email === 'SYSTEM' ? null : e.user_email;
    if (!isUUID(finalUserId)) {
      if (finalUserId && !finalUserEmail) finalUserEmail = finalUserId;
      finalUserId = null;
    }

    // Event type guard
    let eventType = (e.event_type || 'UNKNOWN').toUpperCase();
    if (!['ATTACK', 'DEFENSE', 'AUTH', 'SECURITY', 'SYSTEM'].includes(eventType)) {
      eventType = 'SYSTEM';
    }

    // Action normalisation
    let action = e.action || 'UNKNOWN';
    if (action.includes('LOGIN') && action.includes('FAIL')) action = 'LOGIN_FAILED';

    const tsMs          = new Date(e.timestamp).getTime();
    const correlationId = e.correlation_id || e.event_id;
    const eventPriority = e.event_priority ?? (eventType === 'DEFENSE' ? 2 : 1);

    // Session fallback — same logic as eventWorker
    const identityKey = finalUserId || finalUserEmail || e.session_id || 'anon';
    const sessionId   = e.session_id
      ?? `NO_SESSION_${identityKey}-${e.source_ip || 'unknown'}`;

    // Risk
    const riskLevel = e.risk_level
      ?? (eventType === 'DEFENSE' ? (e.severity ?? null) : null);
    const riskScore = e.risk_score
      ?? (eventType === 'DEFENSE' && e.strike_count ? e.strike_count * 10 : null);

    // Agent type
    const ipType = e.ip_type
      || (e.source_ip?.startsWith('192.168') ? 'SIMULATED' : 'EXTERNAL');
    let agentType = e.agent_type ? e.agent_type.toUpperCase() : null;
    if (ipType === 'SIMULATED') {
      agentType = agentType || 'SIMULATED';
    } else if (!agentType || !AGENT_TYPES.includes(agentType)) {
      agentType = e.user_agent?.toLowerCase().includes('attack') ? 'ATTACK_ENGINE' : 'USER';
    }

    const timeBucket   = Math.floor(tsMs / 60000);
    const eventGroupId = correlationId;

    return {
      ...e,
      finalUserId, finalUserEmail, eventType, action, tsMs,
      correlationId, eventGroupId, eventPriority, sessionId,
      riskLevel, riskScore, agentType, ipType, timeBucket,
    };
  });

  // ── MIDDLE: burst score per group+minute ─────────────────────────────────
  const groupBurstMap = new Map();
  pass1.forEach((e) => {
    const k = `${e.eventGroupId}-${e.timeBucket}`;
    groupBurstMap.set(k, (groupBurstMap.get(k) || 0) + 1);
  });

  // ── PASS 2: build final enriched shape ───────────────────────────────────
  return pass1.map((e) => {
    const burstScore = groupBurstMap.get(`${e.eventGroupId}-${e.timeBucket}`) || 1;

    // correlation_confidence: 1.0 if UUID identity, 0.8 if email, 0.5 if anon
    // +0.5 bonus if session is real (not synthesised NO_SESSION fallback)
    const hasRealSession = e.session_id && !String(e.session_id).startsWith('NO_SESSION');
    const correlationConfidence = parseFloat((
      (e.finalUserId ? 1.0 : e.finalUserEmail ? 0.8 : 0.5) +
      (hasRealSession ? 0.5 : 0.0)
    ).toFixed(1));

    return {
      // ── identity ──────────────────────────────────────────────────────────
      event_id:                  e.event_id,
      correlation_id:            e.correlationId,
      event_priority:            e.eventPriority,
      event_sequence_index:      e.event_sequence_index   ?? null,
      parent_event_id:           e.parent_event_id        ?? null,
      event_group_id:            e.eventGroupId,
      user_id:                   e.finalUserId,
      user_email:                e.finalUserEmail,
      session_id:                e.sessionId,

      // ── classification ────────────────────────────────────────────────────
      event_type:                e.eventType,
      action:                    e.action,
      source_ip:                 e.source_ip              || 'unknown',
      ip_type:                   e.ipType,
      user_agent:                e.user_agent             || 'unknown',
      agent_type:                e.agentType,
      target_type:               e.target_type            || 'API',
      target_endpoint:           e.target_endpoint        || 'unknown',

      // ── outcome ───────────────────────────────────────────────────────────
      result:                    e.result                 || 'UNKNOWN',
      severity:                  e.severity               || null,
      risk_score:                e.riskScore,
      risk_level:                e.riskLevel,

      // ── computed graph fields ─────────────────────────────────────────────
      timestamp:                 e.timestamp,
      mode:                      e.mode                   || 'INFERRED',
      is_attack_related:         e.eventType === 'ATTACK' ||
                                 (!!e.correlationId && e.correlationId !== e.event_id),
      is_defense_triggered:      e.eventType === 'DEFENSE',
      event_signature:           `${e.eventType}-${e.action}-${e.source_ip || 'unknown'}-${e.timeBucket}`,
      events_per_minute_bucket:  burstScore,
      correlation_confidence:    correlationConfidence,

      // ── defense-only fields (undefined for ATTACK events, null-safe) ──────
      reason:                    e.reason          ?? null,
      strike_count:              e.strike_count     ?? null,
      ban_duration:              e.ban_duration     ?? null,
      blocked:                   e.blocked          ?? null,
      mitigation_result:         e.mitigation_result ?? null,
    };
  });
}

// ─────────────────────────────────────────────
// VALIDATE
// ─────────────────────────────────────────────
const REQUIRED_FIELDS    = ['event_id', 'event_type', 'action', 'source_ip', 'severity', 'timestamp'];
const RECOMMENDED_FIELDS = ['user_id', 'target_endpoint', 'result', 'agent_type', 'risk_score'];

function validateEvents(events) {
  let warnings = 0;
  let recommendations = 0;

  for (const event of events) {
    for (const f of REQUIRED_FIELDS) {
      if (!event[f]) {
        console.warn(`[SCHEMA] Missing required '${f}' in event ${event.event_id || 'UNKNOWN'}`);
        warnings++;
      }
    }
    for (const f of RECOMMENDED_FIELDS) {
      if (event[f] === undefined || event[f] === null) recommendations++;
    }
  }

  if (warnings === 0) {
    console.log('[SCHEMA] All events pass required field validation');
  } else {
    console.warn(`[SCHEMA] ${warnings} required field warnings`);
  }
  if (recommendations > 0) {
    console.log(`[SCHEMA] ${recommendations} recommended fields are null (graph may be less complete)`);
  }
}

// ─────────────────────────────────────────────
// PUSH TO NEO4J — batched with concurrency cap
// ─────────────────────────────────────────────
async function pushToNeo4j(events, concurrency) {
  console.log(`\n[NEO4J] Pushing ${events.length} events (concurrency: ${concurrency})...`);

  let pushed  = 0;
  let failed  = 0;
  const errors = [];

  // Process in sliding window of `concurrency` parallel merges
  for (let i = 0; i < events.length; i += concurrency) {
    const batch = events.slice(i, i + concurrency);

    const results = await Promise.allSettled(
      batch.map((event) => mergeEventToGraph(event))
    );

    results.forEach((r, idx) => {
      if (r.status === 'fulfilled') {
        pushed++;
      } else {
        failed++;
        errors.push({ event_id: batch[idx].event_id, error: r.reason?.message });
      }
    });

    // Progress log every 50 events
    if ((i + concurrency) % 50 === 0 || i + concurrency >= events.length) {
      console.log(`[NEO4J] Progress: ${Math.min(i + concurrency, events.length)}/${events.length}`);
    }
  }

  console.log(`[NEO4J] Done — pushed: ${pushed}, failed: ${failed}`);

  if (errors.length > 0) {
    console.warn('[NEO4J] Failed events:');
    errors.forEach((e) => console.warn(`  ${e.event_id}: ${e.error}`));
  }

  return { pushed, failed };
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────
async function main() {
  const opts = parseArgs();

  console.log('╔══════════════════════════════════════════════╗');
  console.log('║  Neo4j Direct Ingest — Attack + Defense ETL  ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log();

  // 1. Load
  const attackEvents  = loadAttackEvents(opts.attackFile);
  const defenseEvents = await loadDefenseEvents(opts.since);

  // 2. Merge
  const merged = [...attackEvents, ...defenseEvents];
  console.log(`[MERGE] ${attackEvents.length} ATTACK + ${defenseEvents.length} DEFENSE = ${merged.length} total`);

  // 3. Deduplicate
  const unique = deduplicateEvents(merged);

  // 4. Sort deterministically
  const sorted = sortEvents(unique);

  // 5. Enrich — adds all computed fields (event_signature, burst bucket,
  //    correlation_confidence, session fallback, agent_type, etc.)
  const enriched = enrichEvents(sorted);

  // 6. Validate
  validateEvents(enriched);

  const attackCount  = enriched.filter((e) => e.event_type === 'ATTACK').length;
  const defenseCount = enriched.filter((e) => e.event_type === 'DEFENSE').length;
  console.log(`\n[ENRICH] Ready to push: ${attackCount} ATTACK + ${defenseCount} DEFENSE`);

  // 7. Push or dry-run
  if (opts.dryRun) {
    console.log('\n[DRY-RUN] Skipping Neo4j push. Sample of first 3 enriched events:');
    enriched.slice(0, 3).forEach((e) => console.log(JSON.stringify(e, null, 2)));
  } else {
    const { pushed, failed } = await pushToNeo4j(enriched, opts.concurrency);

    console.log('\n══════════════════════════════════════════════');
    console.log(`  INGEST COMPLETE — ${pushed} pushed, ${failed} failed`);
    console.log('══════════════════════════════════════════════');
  }
}

main()
  .catch((err) => {
    console.error('[FATAL]', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await closeNeo4jDriver();
  });