#!/usr/bin/env node
// =============================================================================
// neo4j_ingest.js — Unified ATTACK + DEFENSE Event ETL Pipeline  v2.1
// =============================================================================
//
// Usage:
//   node scripts/neo4j_ingest.js [options]
//
// Options:
//   --attack-file    Path to Rust engine results.json   (default: ./reports/results.json)
//   --since          Only include defense events after this ISO timestamp
//   --dry-run        Merge + enrich + validate but do NOT push to Neo4j
//   --concurrency    Parallel Neo4j writes per batch    (default: 5)
//
// Pipeline:
//   load → merge → deduplicate → sort → enrich → validate → push
//
// Corrections from v2.0 review:
//   [FIX-07] sortEvents: null guard added so events without correlation_id
//            AND event_id sort stably instead of relying on undefined comparison.
//   [FIX-08] enrichEvents: event_sequence_index is derived from position within
//            the correlation group for attack events that lack the field in the
//            Rust engine output. This ensures NEXT chain edges have a meaningful
//            sequence_delta instead of null - null = NaN.
//   [FIX-09] loadDefenseEvents: SQL injection risk in sinceClause removed.
//            $since is now passed as a parameterized query argument instead of
//            string-interpolated into the SQL.
//   [FIX-10] Recommended fields list in validateEvents refined: agent_type
//            removed from warnings for DEFENSE events (it is legitimately null
//            for DB-sourced defense rows where the AuditLog doesn't record it).
//
// Key design decisions (unchanged from v2.0):
//   - enrichEvents() is the single source of truth for field shape.
//     It aligns with the EXACT params object that neo4j.js expects.
//   - Defense events use event_id prefix "def-" to avoid collision with
//     attack event IDs from the Rust engine.
//   - session_id fallback creates deterministic synthetic IDs so anonymous
//     events still cluster by identity+IP without polluting the graph
//     (neo4j.js filters out NO_SESSION_ prefix for Session node creation).
//   - correlation_confidence scores identity quality (UUID=1.0, email=0.8,
//     anon=0.5) and adds a session bonus (+0.5 for real sessions).
//   - event_signature enables deduplication at the graph level
//     (same type+action+IP+minute bucket → same signature).
// =============================================================================

import fs   from 'fs';
import path from 'path';
import { PrismaClient }                        from '@prisma/client';
import { mergeEventToGraph, closeNeo4jDriver } from '../src/shared/db/neo4j.js';

const prisma = new PrismaClient();

// ── Helpers ───────────────────────────────────────────────────────────────────
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUUID  = (v) => typeof v === 'string' && UUID_RE.test(v);

// ─────────────────────────────────────────────────────────────────────────────
// CLI ARGUMENT PARSING
// ─────────────────────────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    attackFile:  './reports/results.json',
    since:       null,
    dryRun:      false,
    concurrency: 1,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--attack-file':  opts.attackFile  = args[++i];               break;
      case '--since':        opts.since       = args[++i];               break;
      case '--dry-run':      opts.dryRun      = true;                    break;
      case '--concurrency':  opts.concurrency = parseInt(args[++i], 10); break;
      default:
        console.error(`[ERROR] Unknown argument: ${args[i]}`);
        process.exit(1);
    }
  }

  return opts;
}

// ─────────────────────────────────────────────────────────────────────────────
// LOAD ATTACK EVENTS  (from Rust engine results.json)
// ─────────────────────────────────────────────────────────────────────────────
function loadAttackEvents(filePath) {
  console.log(`[LOAD] Attack events from: ${filePath}`);

  if (!fs.existsSync(filePath)) {
    console.warn(`[WARN] Attack file not found: ${filePath}`);
    return [];
  }

  const raw    = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const events = raw.graph_events || [];
  const mode   = raw.mode || (raw.active_defender_status === 'ENABLED'
    ? 'AFTER_ACTIVE_DEFENDER'
    : 'INFERRED');

  console.log(`[LOAD] ${events.length} ATTACK events  (mode: ${mode})`);

  return events.map((e) => {
    // Identity — resolve UUID vs email-as-id at load time
    const rawUserId = e.user_id;
    const userId    = isUUID(rawUserId) ? rawUserId : null;
    const userEmail = e.user_email
      || (!isUUID(rawUserId) && rawUserId ? rawUserId : null);

    return {
      // Identity
      event_id:             e.event_id,
      correlation_id:       e.correlation_id       ?? null,
      event_priority:       e.event_priority        ?? 1,
      event_sequence_index: e.event_sequence_index  ?? null,  // enriched later [FIX-08]
      parent_event_id:      e.parent_event_id       ?? null,
      user_id:              userId,
      user_email:           userEmail,
      session_id:           e.session_id            ?? null,

      // Classification
      event_type:           'ATTACK',
      action:               e.action                || 'UNKNOWN',
      source_ip:            e.source_ip             || 'unknown',
      ip_type:              e.ip_type               || null,
      user_agent:           e.user_agent            || 'attack-engine',
      agent_type:           e.agent_type            || 'SIMULATED',
      target_type:          e.target_type           || 'API',
      target_endpoint:      e.target_endpoint       || 'unknown',

      // Outcome
      result:               e.result                || null,
      severity:             e.severity              || null,
      risk_score:           e.risk_score            ?? null,
      risk_level:           e.risk_level            ?? null,

      // Meta
      timestamp:            e.timestamp             || null,
      mode,
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// LOAD DEFENSE EVENTS  (from PostgreSQL AuditLog)
//
// [FIX-09] $since is now passed as a query parameter, not string-interpolated.
//          The original sinceClause used template literal interpolation which
//          is a SQL injection vector even for trusted internal timestamps,
//          and also breaks Prisma's query plan caching.
// ─────────────────────────────────────────────────────────────────────────────
async function loadDefenseEvents(since) {
  console.log(`[LOAD] Defense events from PostgreSQL AuditLog...`);

  try {
    // Raw SQL — Prisma JSON path filtering is too limited for this query.
    // defense_action IS NOT NULL is the selector for defense rows.
    // We parse all identity fields from the metadata JSON column.
    //
    // [FIX-09]: $since is passed as a positional parameter ($1) so the driver
    // handles escaping and the query plan is re-used across calls.
    let dbEvents;
    if (since) {
      dbEvents = await prisma.$queryRawUnsafe(`
        SELECT
          id,
          "userId",
          "createdAt",
          metadata
        FROM "AuditLog"
        WHERE metadata->>'defense_action' IS NOT NULL
          AND "createdAt" >= $1::timestamptz
        ORDER BY "createdAt" ASC
        LIMIT 5000
      `, since);
    } else {
      dbEvents = await prisma.$queryRawUnsafe(`
        SELECT
          id,
          "userId",
          "createdAt",
          metadata
        FROM "AuditLog"
        WHERE metadata->>'defense_action' IS NOT NULL
        ORDER BY "createdAt" ASC
        LIMIT 5000
      `);
    }

    const events = dbEvents.map((row) => {
      const meta = row.metadata || {};

      // Defense event IDs are prefixed with "def-" to avoid collision with
      // attack event UUIDs from the Rust engine.
      const eventId  = `def-${meta.event_id}`;
      const parentId = meta.event_id ?? null;   // attack event that triggered this defense
      const seqIdx   = (meta.event_sequence_index ?? 0) + 1;

      const userId    = isUUID(row.userId) ? row.userId   : null;
      const userEmail = meta.user_email
        || (!isUUID(row.userId) && row.userId ? row.userId : null)
        || null;

      return {
        // Identity
        event_id:             eventId,
        correlation_id:       meta.correlation_id       ?? null,
        event_priority:       2,                        // DEFENSE always after ATTACK
        event_sequence_index: seqIdx,
        parent_event_id:      parentId,
        user_id:              userId,
        user_email:           userEmail,
        session_id:           meta.session_id           ?? null,

        // Classification
        event_type:           'DEFENSE',
        action:               meta.defense_action       || 'UNKNOWN',
        source_ip:            meta.source_ip            || 'unknown',
        ip_type:              meta.ip_type              ?? null,
        user_agent:           meta.user_agent           ?? null,
        agent_type:           meta.agent_type           ?? null,
        target_type:          meta.target_type          ?? null,
        target_endpoint:      meta.target_endpoint      ?? null,
        mode:                 meta.mode                 ?? null,

        // Outcome
        result:               'TRIGGERED',
        severity:             meta.risk_level           ?? null,
        risk_score:           meta.risk_score           ?? null,
        risk_level:           meta.risk_level           ?? null,

        // Defense-specific
        reason:               meta.defense_reason       ?? null,
        strike_count:         meta.strike_count         ?? null,
        ban_duration:         meta.ban_duration         ?? null,
        blocked:              meta.defense_action === 'BLOCK' || meta.defense_action === 'BAN',
        mitigation_result:    meta.defense_action       ?? null,

        // Meta
        timestamp:            meta.timestamp
                                ?? row.createdAt?.toISOString()
                                ?? null,
      };
    });

    console.log(`[LOAD] ${events.length} DEFENSE events`);
    return events;

  } catch (err) {
    console.warn(`[WARN] Cannot read defense events from DB: ${err.message}`);
    console.warn('[WARN] Continuing with ATTACK events only');
    return [];
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// DEDUPLICATE  (by event_id)
// ─────────────────────────────────────────────────────────────────────────────
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
  if (dupes > 0) console.log(`[DEDUP] Removed ${dupes} duplicates`);
  return unique;
}

// ─────────────────────────────────────────────────────────────────────────────
// DETERMINISTIC SORT
//   Primary:   correlation_id  (groups attack chains together)
//   Secondary: event_priority  (1=ATTACK before 2=DEFENSE)
//   Tertiary:  event_sequence_index
//
// [FIX-07] Null guard on sort keys prevents JS sort instability when both
//           correlation_id and event_id are absent (shouldn't happen with valid
//           data but guards against malformed upstream records).
// ─────────────────────────────────────────────────────────────────────────────
function sortEvents(events) {
  return events.sort((a, b) => {
    // [FIX-07]: fallback to '' so null/undefined events sort deterministically
    const cA = a.correlation_id || a.event_id || '';
    const cB = b.correlation_id || b.event_id || '';
    if (cA < cB) return -1;
    if (cA > cB) return  1;
    const pDiff = (a.event_priority ?? 1) - (b.event_priority ?? 1);
    if (pDiff !== 0) return pDiff;
    return (a.event_sequence_index ?? 0) - (b.event_sequence_index ?? 0);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// ENRICH
//
// This is the single authoritative field-shaping step.
// Output EXACTLY matches the params object expected by neo4j.js mergeEventToGraph().
//
// Computed fields added here:
//   event_group_id          — alias for correlation_id, used for group queries
//   event_signature         — deduplication key: type+action+ip+minute_bucket
//   events_per_minute_bucket — burst count for this group in this minute
//   correlation_confidence  — identity quality score (0.5–1.5)
//   session_id              — with NO_SESSION_ fallback for anonymous events
//   ip_type                 — inferred from IP range if not set
//   agent_type              — inferred from user_agent / ip_type if not set
//   risk_level              — inferred from severity for DEFENSE events
//   risk_score              — inferred from strike_count for DEFENSE events
//   event_sequence_index    — [FIX-08] derived from position in correlation
//                             group when not provided by the Rust engine
// ─────────────────────────────────────────────────────────────────────────────
function enrichEvents(events) {
  const VALID_EVENT_TYPES = ['ATTACK', 'DEFENSE', 'AUTH', 'SECURITY', 'SYSTEM'];
  const VALID_AGENT_TYPES = ['USER', 'SYSTEM', 'ATTACK_ENGINE', 'SIMULATED', 'EXTERNAL'];

  // ── PASS 1: normalize every event ─────────────────────────────────────────
  const pass1 = events.map((e) => {
    // --- Identity normalization ---
    let finalUserId    = e.user_id    === 'SYSTEM' ? null : e.user_id;
    let finalUserEmail = e.user_email === 'SYSTEM' ? null : e.user_email;

    // If user_id is not a UUID, treat it as an email fallback
    if (!isUUID(finalUserId)) {
      if (finalUserId && !finalUserEmail) finalUserEmail = finalUserId;
      finalUserId = null;
    }

    // --- Event type guard ---
    let eventType = (e.event_type || 'UNKNOWN').toUpperCase();
    if (!VALID_EVENT_TYPES.includes(eventType)) eventType = 'SYSTEM';

    // --- Action normalization ---
    let action = (e.action || 'UNKNOWN').toUpperCase().trim();
    // Normalize login failure variants to a single canonical action
    if (action.includes('LOGIN') && action.includes('FAIL')) action = 'LOGIN_FAILED';

    // --- Timestamp ---
    const tsMs = e.timestamp ? new Date(e.timestamp).getTime() : Date.now();

    // --- Correlation ---
    const correlationId = e.correlation_id || e.event_id;
    const eventPriority = e.event_priority ?? (eventType === 'DEFENSE' ? 2 : 1);

    // --- Session fallback ---
    // Creates a deterministic synthetic session ID for anonymous events.
    // The "NO_SESSION_" prefix is filtered in neo4j.js so no Session node is created.
    const identityKey = finalUserId || finalUserEmail || e.session_id || 'anon';
    const sessionId   = e.session_id
      || `NO_SESSION_${identityKey}-${e.source_ip || 'unknown'}`;

    // --- Network context ---
    const ipType = e.ip_type
      || (e.source_ip?.startsWith('192.168.') || e.source_ip?.startsWith('10.')
          ? 'SIMULATED'
          : 'EXTERNAL');

    // --- Agent type ---
    let agentType = e.agent_type ? e.agent_type.toUpperCase() : null;
    if (!agentType || !VALID_AGENT_TYPES.includes(agentType)) {
      if (ipType === 'SIMULATED')                                        agentType = 'SIMULATED';
      else if (e.user_agent?.toLowerCase().includes('attack'))           agentType = 'ATTACK_ENGINE';
      else                                                               agentType = 'USER';
    }

    // --- Risk normalization ---
    const riskLevel = e.risk_level
      ?? (eventType === 'DEFENSE' ? (e.severity ?? null) : null);
    const riskScore = e.risk_score
      ?? (eventType === 'DEFENSE' && e.strike_count ? e.strike_count * 10 : null);

    // --- Time bucket (minute resolution for burst detection) ---
    const timeBucket = Math.floor(tsMs / 60_000);

    return {
      // carry all original fields
      ...e,
      // resolved / normalized
      finalUserId, finalUserEmail,
      eventType, action,
      correlationId, eventPriority,
      sessionId, ipType, agentType,
      riskLevel, riskScore,
      tsMs, timeBucket,
    };
  });

  // ── Burst counter: events per correlation group per minute ─────────────────
  const groupBurstMap = new Map();
  pass1.forEach((e) => {
    const k = `${e.correlationId}-${e.timeBucket}`;
    groupBurstMap.set(k, (groupBurstMap.get(k) || 0) + 1);
  });

  // ── [FIX-08] Derive event_sequence_index for events that lack it ──────────
  // The Rust engine results.json does not include event_sequence_index.
  // We derive it from the position of each event within its correlation group,
  // ordered by timestamp. This ensures NEXT chain edges get a meaningful
  // sequence_delta on the relationship instead of (null - null = NaN).
  //
  // Defense events already carry seqIdx = (attack_seq_index + 1) from
  // loadDefenseEvents(), so we only fill in nulls here.
  const groupSeqCounters = new Map();
  // Sort pass1 by correlationId + tsMs so we assign sequence in time order
  const sortedForSeq = [...pass1].sort((a, b) => {
    const cA = a.correlationId || '';
    const cB = b.correlationId || '';
    if (cA !== cB) return cA < cB ? -1 : 1;
    return a.tsMs - b.tsMs;
  });
  // Build a map: event_id → derived_sequence
  const derivedSeqMap = new Map();
  for (const e of sortedForSeq) {
    if (e.event_sequence_index != null) {
      // Already has a sequence — respect it, but update the counter so
      // subsequent events in the same group don't collide.
      const existing = groupSeqCounters.get(e.correlationId) ?? 0;
      groupSeqCounters.set(e.correlationId, Math.max(existing, e.event_sequence_index + 1));
      derivedSeqMap.set(e.event_id, e.event_sequence_index);
    } else {
      const next = groupSeqCounters.get(e.correlationId) ?? 0;
      derivedSeqMap.set(e.event_id, next);
      groupSeqCounters.set(e.correlationId, next + 1);
    }
  }

  // ── PASS 2: build final enriched shape ─────────────────────────────────────
  return pass1.map((e) => {
    const burstScore = groupBurstMap.get(`${e.correlationId}-${e.timeBucket}`) || 1;

    // correlation_confidence: quality of identity resolution
    //   UUID identity  → 1.0
    //   Email only     → 0.8
    //   Anonymous      → 0.5
    //   + real session bonus → +0.5  (max total: 1.5)
    const hasRealSession = e.sessionId && !e.sessionId.startsWith('NO_SESSION_');
    const correlationConfidence = parseFloat((
      (e.finalUserId ? 1.0 : e.finalUserEmail ? 0.8 : 0.5) +
      (hasRealSession ? 0.5 : 0.0)
    ).toFixed(1));

    // event_signature: stable fingerprint for graph-level deduplication
    const eventSignature = [
      e.eventType,
      e.action,
      e.source_ip || 'unknown',
      e.timeBucket,
    ].join('-');

    // [FIX-08] Use derived sequence if original was null
    const sequenceIndex = e.event_sequence_index ?? derivedSeqMap.get(e.event_id) ?? null;

    // ── Final shape — MUST match neo4j.js params exactly ──────────────────────
    return {
      // ── Identity ─────────────────────────────────────────────────────────────
      event_id:                  e.event_id,
      correlation_id:            e.correlationId,
      event_group_id:            e.correlationId,          // explicit alias for group queries
      event_priority:            e.eventPriority,
      event_sequence_index:      sequenceIndex,            // [FIX-08] derived if absent
      parent_event_id:           e.parent_event_id         ?? null,
      user_id:                   e.finalUserId,
      user_email:                e.finalUserEmail,
      session_id:                e.sessionId,

      // ── Classification ────────────────────────────────────────────────────────
      event_type:                e.eventType,
      action:                    e.action,
      source_ip:                 e.source_ip                || 'unknown',
      ip_type:                   e.ipType,
      user_agent:                e.user_agent               || null,
      agent_type:                e.agentType,
      target_type:               e.target_type              || 'API',
      target_endpoint:           e.target_endpoint          || 'unknown',
      mode:                      e.mode                     || 'INFERRED',

      // ── Outcome ───────────────────────────────────────────────────────────────
      result:                    e.result                   || null,
      severity:                  e.severity                 || null,
      risk_score:                e.riskScore,
      risk_level:                e.riskLevel,

      // ── Computed / enrichment ─────────────────────────────────────────────────
      timestamp:                 e.timestamp                || null,
      event_signature:           eventSignature,
      events_per_minute_bucket:  burstScore,
      correlation_confidence:    correlationConfidence,
      is_root_event:             e.parent_event_id == null,
      is_attack_related:         e.eventType === 'ATTACK' ||
                                 (!!e.correlationId && e.correlationId !== e.event_id),
      is_defense_triggered:      e.eventType === 'DEFENSE',

      // ── Defense-only ──────────────────────────────────────────────────────────
      reason:                    e.reason                   ?? null,
      strike_count:              e.strike_count             ?? null,
      ban_duration:              e.ban_duration             ?? null,
      blocked:                   e.blocked                  ?? null,
      mitigation_result:         e.mitigation_result        ?? null,
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATE
//
// Required fields: must be present and non-null for a valid graph node.
// Recommended fields: warn if missing — graph will be less complete.
//
// [FIX-10] agent_type removed from recommended field warnings for DEFENSE
//           events. Defense events sourced from AuditLog legitimately have
//           null agent_type (the AuditLog records the defense system action,
//           not the originating agent). Mixing this warning into DEFENSE
//           events creates noise that obscures real data quality issues.
// ─────────────────────────────────────────────────────────────────────────────
const REQUIRED_FIELDS    = ['event_id', 'event_type', 'action', 'source_ip', 'timestamp'];
const RECOMMENDED_ATTACK = ['severity', 'risk_score', 'user_id', 'target_endpoint',
                            'result', 'agent_type', 'correlation_id'];
const RECOMMENDED_DEFENSE = ['severity', 'risk_score', 'user_id', 'target_endpoint',
                             'result', 'correlation_id'];  // agent_type intentionally omitted

function validateEvents(events) {
  let reqWarnings = 0;
  let recWarnings = 0;

  for (const event of events) {
    for (const f of REQUIRED_FIELDS) {
      if (event[f] == null || event[f] === '') {
        console.warn(`[SCHEMA] REQUIRED '${f}' missing in ${event.event_id || 'UNKNOWN'}`);
        reqWarnings++;
      }
    }
    const recFields = event.event_type === 'DEFENSE' ? RECOMMENDED_DEFENSE : RECOMMENDED_ATTACK;
    for (const f of recFields) {
      if (event[f] == null) recWarnings++;
    }
  }

  if (reqWarnings === 0) {
    console.log('[SCHEMA] ✓ All events pass required field validation');
  } else {
    console.warn(`[SCHEMA] ✗ ${reqWarnings} required field violations`);
  }
  if (recWarnings > 0) {
    console.log(`[SCHEMA] ⚠  ${recWarnings} recommended fields are null — graph may be less complete`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUSH TO NEO4J — sliding window of parallel writes
// ─────────────────────────────────────────────────────────────────────────────
async function pushToNeo4j(events, concurrency) {
  console.log(`\n[NEO4J] Pushing ${events.length} events (concurrency: ${concurrency})...`);

  let pushed = 0;
  let failed = 0;
  const errors = [];

  for (let i = 0; i < events.length; i += concurrency) {
    const batch   = events.slice(i, i + concurrency);
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

    // Progress every 50 events
    const done = Math.min(i + concurrency, events.length);
    if (done % 50 === 0 || done === events.length) {
      console.log(`[NEO4J] Progress: ${done}/${events.length}`);
    }
  }

  console.log(`[NEO4J] Done — pushed: ${pushed}, failed: ${failed}`);

  if (errors.length > 0) {
    console.warn('[NEO4J] Failed events:');
    errors.forEach((e) => console.warn(`  ${e.event_id}: ${e.error}`));
  }

  return { pushed, failed };
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────
async function main() {
  const opts = parseArgs();

  console.log('╔══════════════════════════════════════════════╗');
  console.log('║  Neo4j Direct Ingest — Attack + Defense ETL  ║');
  console.log('╚══════════════════════════════════════════════╝\n');

  // 1. Load
  const attackEvents  = loadAttackEvents(opts.attackFile);
  const defenseEvents = await loadDefenseEvents(opts.since);

  // 2. Merge
  const merged = [...attackEvents, ...defenseEvents];
  console.log(`[MERGE] ${attackEvents.length} ATTACK + ${defenseEvents.length} DEFENSE = ${merged.length} total`);

  // 3. Deduplicate
  const unique = deduplicateEvents(merged);

  // 4. Sort (deterministic chain ordering)
  const sorted = sortEvents(unique);

  // 5. Enrich (adds all computed + visualization fields)
  const enriched = enrichEvents(sorted);

  // 6. Validate
  validateEvents(enriched);

  const attackCount  = enriched.filter((e) => e.event_type === 'ATTACK').length;
  const defenseCount = enriched.filter((e) => e.event_type === 'DEFENSE').length;
  console.log(`\n[ENRICH] Ready: ${attackCount} ATTACK + ${defenseCount} DEFENSE`);

  // 7. Push or dry-run
  if (opts.dryRun) {
    console.log('\n[DRY-RUN] Skipping Neo4j push. First 3 enriched events:');
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