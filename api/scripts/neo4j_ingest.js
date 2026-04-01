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

  // Normalize: ensure all events have the mode field
  return events.map((e) => ({
    event_id: e.event_id,
    correlation_id: e.correlation_id,
    user_id: e.user_id,
    user_email: e.user_email || null,
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
    timestamp: e.timestamp,
    mode: raw.mode || (raw.active_defender_status === 'ENABLED' ? 'AFTER_ACTIVE_DEFENDER' : 'INFERRED'),
  }));
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
    if (token) headers['Authorization'] = `Bearer ${token}`;

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

function validateEvents(events) {
  let warnings = 0;

  for (const event of events) {
    for (const field of REQUIRED_FIELDS) {
      if (!event[field]) {
        console.warn(`[SCHEMA] Missing field '${field}' in event ${event.event_id || 'UNKNOWN'} (action: ${event.action})`);
        warnings++;
      }
    }
  }

  if (warnings === 0) {
    console.log('[SCHEMA] ✅ All events pass schema validation');
  } else {
    console.warn(`[SCHEMA] ⚠️  ${warnings} field warnings found`);
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

  // 5. Sort by timestamp
  const sorted = sortByTimestamp(unique);

  // 6. Validate schema
  validateEvents(sorted);

  // 7. Build output
  const attackCount = sorted.filter(e => e.event_type === 'ATTACK').length;
  const defenseCount = sorted.filter(e => e.event_type === 'DEFENSE').length;

  const output = {
    _metadata: {
      generated_at: new Date().toISOString(),
      source: 'neo4j_event_merger',
      version: '1.0.0',
      attack_source: path.basename(opts.attackFile),
      defense_source: `${opts.apiUrl}/api/v1/audit/events/defense`,
      total_events: sorted.length,
      attack_events: attackCount,
      defense_events: defenseCount,
      time_range: sorted.length > 0
        ? { first: sorted[0].timestamp, last: sorted[sorted.length - 1].timestamp }
        : null,
    },
    events: sorted,
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
    console.log(`[FILE] Total: ${sorted.length} events (${attackCount} ATTACK, ${defenseCount} DEFENSE)`);
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
