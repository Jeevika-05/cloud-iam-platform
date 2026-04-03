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
//   --api-url        Backend URL for defense events (default: http://localhost:3000)
//   --output         Output file path (default: ./reports/unified_events.json)
//   --since          Only include defense events after this ISO timestamp
//   --token          JWT access token for API authentication
//   --dry-run        Print to stdout instead of writing file
//
// This script merges:
//   1. ATTACK events from results.json (Rust engine output)
//   2. DEFENSE events from /api/v1/audit/events/defense (backend AuditLog)
//
// Output: unified_events.json — ready for Neo4j LOAD CSV / APOC import
// ─────────────────────────────────────────────────────────────

import fs from 'fs';
import path from 'path';

// ─────────────────────────────────────────────
// CLI ARGUMENT PARSING
// ─────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    attackFile: './reports/results.json',
    apiUrl: 'http://localhost:3000',
    output: './reports/unified_events.json',
    since: null,
    token: null,
    dryRun: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--attack-file': opts.attackFile = args[++i]; break;
      case '--api-url':     opts.apiUrl = args[++i]; break;
      case '--output':      opts.output = args[++i]; break;
      case '--since':       opts.since = args[++i]; break;
      case '--token':       opts.token = args[++i]; break;
      case '--dry-run':     opts.dryRun = true; break;
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
  console.log(`[MERGE] Loading attack events from: ${filePath}`);

  if (!fs.existsSync(filePath)) {
    console.warn(`[WARN] Attack file not found: ${filePath}`);
    return [];
  }

  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const events = raw.graph_events || [];

  console.log(`[MERGE] Found ${events.length} ATTACK events`);

  // UUID validation for identity normalization
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const isUUID = (v) => typeof v === 'string' && UUID_RE.test(v);

  // Normalize: ensure consistent schema for Neo4j graph modeling
  return events.map((e) => {
    // Identity normalization: user_id MUST be UUID or null.
    // If the Rust engine set user_id to an email, move it to user_email.
    const rawUserId = e.user_id;
    const userId = isUUID(rawUserId) ? rawUserId : null;
    const userEmail = e.user_email || (!isUUID(rawUserId) ? rawUserId : null);

    return {
      event_id: e.event_id,
      correlation_id: e.correlation_id,
      user_id: userId,
      user_email: userEmail,
      session_id: e.session_id || null,
      event_type: 'ATTACK',
      action: e.action,
      source_ip: e.source_ip,
      ip_type: e.ip_type || 'SIMULATED',
      user_agent: e.user_agent || 'attack-engine',
      agent_type: e.agent_type || 'SIMULATED',
      target_type: e.target_type || 'API',
      target_endpoint: e.target_endpoint,
      result: e.result,
      severity: e.severity,
      risk_score: e.risk_score ?? null,
      risk_level: e.risk_level ?? null,
      timestamp: e.timestamp,
      mode: raw.mode || (raw.active_defender_status === 'ENABLED' ? 'AFTER_ACTIVE_DEFENDER' : 'INFERRED'),
    };
  });
}

// ─────────────────────────────────────────────
// LOAD DEFENSE EVENTS (from API)
// ─────────────────────────────────────────────
async function loadDefenseEvents(apiUrl, token, since) {
  const url = new URL('/api/v1/audit/events/defense', apiUrl);
  if (since) url.searchParams.set('since', since);
  url.searchParams.set('limit', '5000');

  console.log(`[MERGE] Fetching defense events from: ${url.toString()}`);

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['x-internal-token'] = token;

    const response = await fetch(url.toString(), { headers });

    if (!response.ok) {
      const body = await response.text();
      console.warn(`[WARN] Defense API returned ${response.status}: ${body}`);
      console.warn('[WARN] Continuing with ATTACK events only');
      return [];
    }

    const data = await response.json();
    const events = data.events || [];

    console.log(`[MERGE] Found ${events.length} DEFENSE events`);
    return events;
  } catch (err) {
    console.warn(`[WARN] Cannot reach defense API: ${err.message}`);
    console.warn('[WARN] Continuing with ATTACK events only');
    return [];
  }
}

// ─────────────────────────────────────────────
// SCHEMA ENRICHMENT & CORRELATION
// ─────────────────────────────────────────────
function enrichEvents(events) {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const isUUID = (v) => typeof v === 'string' && UUID_RE.test(v);

  // Time-aware map: tracks most recent attack { id, tsMs } per correlation key
  const lastAttackByKey = new Map();
  const AGENT_TYPES = ["USER", "SYSTEM", "ATTACK_ENGINE"];
  const ATTACK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes max expiration for linkage

  // ============================================
  // PASS 1: Normalization & Map Relationships
  // ============================================
  const pass1 = events.map((e) => {
    // 1. Identity Normalization
    let finalUserId = e.user_id === 'SYSTEM' ? null : e.user_id;
    let finalUserEmail = e.user_email === 'SYSTEM' ? null : e.user_email;

    if (!isUUID(finalUserId)) {
      if (finalUserId && !finalUserEmail) finalUserEmail = finalUserId;
      finalUserId = null;
    }

    // 2. Event Normalization
    let eventType = e.event_type ? e.event_type.toUpperCase() : 'UNKNOWN';
    if (!['ATTACK', 'DEFENSE', 'AUTH', 'SECURITY', 'SYSTEM'].includes(eventType)) {
       eventType = 'SYSTEM';
    }

    let action = e.action || 'UNKNOWN';
    if (action.includes('LOGIN') && action.includes('FAIL')) action = 'LOGIN_FAILED';

    const tsMs = new Date(e.timestamp).getTime();

    // 3. Correlation Integrity & Linkage
    const identityKey = finalUserId || finalUserEmail || e.session_id || 'anon';
    const baseKey = `${identityKey}-${e.source_ip || 'unknown'}`;
    
    let correlationId = e.correlation_id;
    if (eventType === 'ATTACK') {
      correlationId = e.event_id; // Root attack accurately to sync with lookup matches
      lastAttackByKey.set(baseKey, { id: e.event_id, ts: tsMs });
    } else if (eventType === 'DEFENSE') {
      const lastAttack = lastAttackByKey.get(baseKey);
      // Link only if within timeout window to prevent long-running merging
      if (lastAttack && (tsMs - lastAttack.ts <= ATTACK_TIMEOUT_MS)) {
        correlationId = lastAttack.id;
      }
    }

    // Strict Attack Clustering Root
    const eventGroupId = correlationId || e.event_id;

    // 4. Session Protection (no global NO_SESSION collapse)
    const sessionId = e.session_id ?? `NO_SESSION_${identityKey}-${e.source_ip || 'unknown'}`;

    // 5. Risk Scoring & System Classification
    let riskLevel = e.risk_level ?? e.metadata?.risk_level ?? (eventType === 'DEFENSE' ? (e.severity ?? null) : null);
    let riskScore = e.risk_score ?? e.metadata?.risk_score ?? (eventType === 'DEFENSE' && e.strike_count ? e.strike_count * 10 : null);
    
    let agentType = e.agent_type ? e.agent_type.toUpperCase() : null;
    const ipType = e.ip_type || (e.source_ip?.startsWith('192.168') ? 'SIMULATED' : 'REAL');
    
    if (ipType === 'SIMULATED') {
      agentType = 'ATTACK_ENGINE';
    } else if (!agentType || !AGENT_TYPES.includes(agentType)) {
      agentType = e.user_agent?.toLowerCase().includes('attack') ? 'ATTACK_ENGINE' : 'USER';
    }

    const timeBucket = Math.floor(tsMs / 60000);

    return {
      ...e,
      finalUserId, finalUserEmail, eventType, action, tsMs,
      correlationId, eventGroupId, sessionId, riskLevel, riskScore,
      agentType, ipType, timeBucket
    };
  });

  // ============================================
  // MIDDLE: Pre-calculate Group-Scoped Metrics
  // ============================================
  const groupBurstMap = new Map(); // e.g., "groupId-timeBucket" -> total count
  pass1.forEach(e => {
    const burstKey = `${e.eventGroupId}-${e.timeBucket}`;
    groupBurstMap.set(burstKey, (groupBurstMap.get(burstKey) || 0) + 1);
  });

  // ============================================
  // PASS 2: Construct Final Output
  // ============================================
  return pass1.map((e) => {
    const burstKey = `${e.eventGroupId}-${e.timeBucket}`;
    const burstScore = groupBurstMap.get(burstKey) || 1;
    
    return {
      event_id: e.event_id,
      correlation_id: e.correlationId || e.event_id, 
      event_group_id: e.eventGroupId,
      user_id: e.finalUserId,
      user_email: e.finalUserEmail, 
      session_id: e.sessionId,
      event_type: e.eventType,
      action: e.action,
      source_ip: e.source_ip || 'unknown',
      ip_type: e.ipType,
      user_agent: e.user_agent || 'unknown',
      agent_type: e.agentType,
      target_type: e.target_type || 'API',
      target_endpoint: e.target_endpoint || 'unknown',
      result: e.result || 'UNKNOWN',
      severity: e.severity || null, 
      risk_score: e.riskScore,
      risk_level: e.riskLevel,
      timestamp: e.timestamp,
      mode: e.mode || 'INFERRED',
      is_attack_related: e.eventType === 'ATTACK' || (!!e.correlationId && e.correlationId !== e.event_id),
      is_defense_triggered: e.eventType === 'DEFENSE',
      event_signature: `${e.eventType}-${e.action}-${e.source_ip || 'unknown'}-${e.timeBucket}`,
      events_per_minute_bucket: burstScore,
      correlation_confidence: parseFloat(( (e.finalUserId ? 1.0 : (e.finalUserEmail ? 0.8 : 0.5)) + (e.session_id ? 0.5 : 0.0) ).toFixed(1)),
      ...(e.eventType === 'DEFENSE' && {
        reason: e.reason || 'UNKNOWN',
        strike_count: e.strike_count || 1,
        ban_duration: e.ban_duration || null
      })
    };
  });
}

// ─────────────────────────────────────────────
// DEDUPLICATE EVENTS
// ─────────────────────────────────────────────
function deduplicateEvents(events) {
  const seen = new Set();
  const unique = [];

  for (const event of events) {
    const key = event.event_id;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(event);
    }
  }

  const dupes = events.length - unique.length;
  if (dupes > 0) {
    console.log(`[MERGE] Removed ${dupes} duplicate events`);
  }

  return unique;
}

// ─────────────────────────────────────────────
// SORT BY TIMESTAMP
// ─────────────────────────────────────────────
function sortByTimestamp(events) {
  return events.sort((a, b) => {
    const ta = new Date(a.timestamp).getTime();
    const tb = new Date(b.timestamp).getTime();
    return ta - tb;
  });
}

// ─────────────────────────────────────────────
// VALIDATE EVENT SCHEMA
// ─────────────────────────────────────────────
const REQUIRED_FIELDS = [
  'event_id', 'event_type', 'action', 'source_ip', 'severity', 'timestamp',
];

// Fields that should be present for complete Neo4j graph modeling
const RECOMMENDED_FIELDS = [
  'user_id', 'target_endpoint', 'result', 'agent_type', 'target_type',
  'risk_score', 'risk_level',
];

function validateEvents(events) {
  let warnings = 0;
  let recommendations = 0;

  for (const event of events) {
    for (const field of REQUIRED_FIELDS) {
      if (!event[field]) {
        console.warn(`[SCHEMA] Missing required field '${field}' in event ${event.event_id || 'UNKNOWN'} (action: ${event.action})`);
        warnings++;
      }
    }
    for (const field of RECOMMENDED_FIELDS) {
      if (event[field] === undefined || event[field] === null) {
        recommendations++;
      }
    }
  }

  if (warnings === 0) {
    console.log('[SCHEMA] ✅ All events pass required field validation');
  } else {
    console.warn(`[SCHEMA] ⚠️  ${warnings} required field warnings found`);
  }
  if (recommendations > 0) {
    console.log(`[SCHEMA] ℹ️  ${recommendations} recommended fields are null/missing (may affect graph completeness)`);
  }
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────
async function main() {
  const opts = parseArgs();

  console.log('╔══════════════════════════════════════════╗');
  console.log('║  Neo4j Event Merger — Unified Pipeline   ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log();

  // 1. Load ATTACK events
  const attackEvents = loadAttackEvents(opts.attackFile);

  // 2. Load DEFENSE events
  const defenseEvents = await loadDefenseEvents(opts.apiUrl, opts.token, opts.since);

  // 3. Merge
  const merged = [...attackEvents, ...defenseEvents];
  console.log(`[MERGE] Merged: ${attackEvents.length} ATTACK + ${defenseEvents.length} DEFENSE = ${merged.length} total`);

  // 4. Deduplicate
  const unique = deduplicateEvents(merged);

  // 5. Sort by timestamp (Required for causality linking)
  const sorted = sortByTimestamp(unique);

  // 6. Enrich Schema and Add Graph Correlation
  const enriched = enrichEvents(sorted);

  // 6b. Apply Strict Sequence Tracking (Per Group)
  // MODIFIED
  const correlationIndexMap = new Map();
  const correlationParentMap = new Map();

  enriched.forEach((e) => {
    const groupId = e.correlation_id || e.event_group_id;

    const currentIndex = correlationIndexMap.get(groupId) || 0;
    const nextIndex = currentIndex + 1;
    
    const parentId = correlationParentMap.get(groupId) || null;

    correlationIndexMap.set(groupId, nextIndex);
    correlationParentMap.set(groupId, e.event_id);

    e.event_sequence_index = nextIndex;
    e.parent_event_id = parentId;
  });

  // 7. Validate schema
  validateEvents(enriched);

  // 8. Build output
  const attackCount = enriched.filter(e => e.event_type === 'ATTACK').length;
  const defenseCount = enriched.filter(e => e.event_type === 'DEFENSE').length;

  const output = {
    _metadata: {
      generated_at: new Date().toISOString(),
      source: 'neo4j_event_merger',
      version: '1.0.0',
      attack_source: path.basename(opts.attackFile),
      defense_source: `${opts.apiUrl}/api/v1/audit/events/defense`,
      total_events: enriched.length,
      attack_events: attackCount,
      defense_events: defenseCount,
      time_range: enriched.length > 0
        ? { first: enriched[0].timestamp, last: enriched[enriched.length - 1].timestamp }
        : null,
    },
    events: enriched,
  };

  // 8. Write output
  const json = JSON.stringify(output, null, 2);

  if (opts.dryRun) {
    console.log();
    console.log('[OUTPUT] Dry run — printing to stdout:');
    console.log(json);
  } else {
    const outputDir = path.dirname(opts.output);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    fs.writeFileSync(opts.output, json, 'utf8');
    console.log();
    console.log(`[FILE] Unified events written to: ${opts.output}`);
    console.log(`[FILE] Total: ${enriched.length} events (${attackCount} ATTACK, ${defenseCount} DEFENSE)`);
  }

  console.log();
  console.log('═══════════════════════════════════════════');
  console.log('  MERGE COMPLETE');
  console.log('═══════════════════════════════════════════');
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(1);
});
