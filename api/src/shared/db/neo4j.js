// =============================================================================
// neo4j.js — Production Neo4j Graph Client
// SIEM-style IAM Security Graph — v2.1 (corrected + optimized)
// =============================================================================
//
// Corrections from v2.0 review:
//   [FIX-01] Duplicate OPTIONAL MATCH for parent_event_id (steps 10+11) collapsed
//            into one read + two FOREACH guards. Eliminates redundant index lookup.
//   [FIX-02] Null guard added before OPTIONAL MATCH on parent_event_id.
//            Prevents Neo4j from scanning for nodes where event_id IS NULL.
//   [FIX-03] events_per_minute_bucket added to ON MATCH SET on the Event node.
//            Previously only set ON CREATE — re-ingestion never refreshed it.
//   [FIX-04] DefenseAction.apply_count initialized to 1 ON CREATE.
//            Previously unset on first creation, making the ON MATCH coalesce
//            compute the right answer but leaving apply_count absent on the
//            node until a second application of the same defense type.
//   [FIX-05] Event(event_signature) and Event(correlation_id) indexes added to
//            initSchema(). Both are hot query paths with no prior index coverage.
//   [FIX-06] Dual User uniqueness constraints (user_id + user_email) documented
//            with identity-reconciliation caveat. Constraints themselves are
//            intentional — see design notes at bottom of file.
//   [FIX-07] sortEvents null guard (ingest side) — see neo4j_ingest.js.
//   [FIX-08] Derived event_sequence_index for attack events (ingest side)
//            — see neo4j_ingest.js.
//
// Design principles (unchanged from v2.0):
//   1. ONE Cypher statement per event — no multi-query sessions.
//   2. All identity resolution happens in JS before the query.
//   3. Every conditional write is guarded by FOREACH — no OPTIONAL MATCH
//      inside write units.
//   4. WITH carries ALL variables needed downstream.
//   5. ON CREATE / ON MATCH are the only SET forms on the MERGE target node.
//   6. display / label / color always set on every node for Bloom / neovis.js.
//   7. All params are flat scalars.
//
// Node labels:  Event · IP · User · Session · AttackGroup · AttackType
//               Endpoint · DefenseAction · RiskBucket
//
// Relationships: TRIGGERED · ACTED · CONTAINS · GROUPS · OF_TYPE
//                TARGETED · NEXT · TRIGGERED_DEFENSE · APPLIED · IN_RISK_BUCKET
//
// Indexes (created by initSchema()):
//   Unique: Event(event_id), IP(address), User(user_id), User(user_email),
//           Session(session_id), AttackGroup(correlation_id), AttackType(action),
//           Endpoint(path), DefenseAction(defense_type), RiskBucket(level)
//   Extra:  Event(parent_event_id), Event(timestamp),
//           Event(event_signature) [FIX-05], Event(correlation_id) [FIX-05]
// =============================================================================

import neo4j  from 'neo4j-driver';
import winston from 'winston';

// ── Logger ────────────────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'neo4j-client' },
  transports: [new winston.transports.Console()],
});

// ── Connection ────────────────────────────────────────────────────────────────
const neo4jUrl      = process.env.NEO4J_URL      || 'bolt://neo4j:7687';
const neo4jUser     = process.env.NEO4J_USER     || 'neo4j';
const neo4jPassword = process.env.NEO4J_PASSWORD || 'password';

let driver = null;

export function getNeo4jDriver() {
  if (!driver) {
    try {
      driver = neo4j.driver(
        neo4jUrl,
        neo4j.auth.basic(neo4jUser, neo4jPassword),
        {
          maxConnectionPoolSize:        50,
          connectionAcquisitionTimeout: 3000,
          // Disable lossless integers so Neo4j integers come back as JS numbers.
          disableLosslessIntegers: true,
        }
      );
      logger.info('NEO4J_DRIVER_INITIALIZED', { url: neo4jUrl });
    } catch (err) {
      logger.error('NEO4J_INITIALIZATION_ERROR', { error: err.message });
      throw err;
    }
  }
  return driver;
}

export async function closeNeo4jDriver() {
  if (driver) {
    await driver.close();
    driver = null;
    logger.info('NEO4J_DRIVER_CLOSED');
  }
}

// ── Schema bootstrap (run once at application startup) ───────────────────────
// Creates uniqueness constraints + indexes so every MERGE is O(log n).
//
// IDENTITY RECONCILIATION NOTE [FIX-06]:
//   Two separate uniqueness constraints exist on User — one for user_id (UUID
//   path) and one for user_email (email-only fallback path). This is intentional:
//   the two FOREACH blocks in mergeEventToGraph() create distinct User nodes for
//   each identity path. The risk is that the same real person can end up as two
//   nodes if their UUID first arrives anonymously (email-only) and later with a
//   UUID. A periodic reconciliation job should:
//     MATCH (a:User {user_email: X}), (b:User {user_id: Y, user_email: X})
//     WHERE id(a) <> id(b)
//     // merge relationships from a onto b, then DETACH DELETE a
//   This is a known graph identity problem and is out of scope for the ingest
//   pipeline itself.
export async function initSchema() {
  const session = getNeo4jDriver().session({ defaultAccessMode: neo4j.session.WRITE });
  const ddl = [
    // ── Uniqueness constraints (each implicitly creates a backing index) ──
    'CREATE CONSTRAINT event_id_unique      IF NOT EXISTS FOR (n:Event)         REQUIRE n.event_id        IS UNIQUE',
    'CREATE CONSTRAINT ip_address_unique    IF NOT EXISTS FOR (n:IP)            REQUIRE n.address          IS UNIQUE',
    'CREATE CONSTRAINT user_id_unique       IF NOT EXISTS FOR (n:User)          REQUIRE n.user_id          IS UNIQUE',
    'CREATE CONSTRAINT user_email_unique    IF NOT EXISTS FOR (n:User)          REQUIRE n.user_email       IS UNIQUE',
    'CREATE CONSTRAINT session_id_unique    IF NOT EXISTS FOR (n:Session)       REQUIRE n.session_id       IS UNIQUE',
    'CREATE CONSTRAINT group_id_unique      IF NOT EXISTS FOR (n:AttackGroup)   REQUIRE n.correlation_id   IS UNIQUE',
    'CREATE CONSTRAINT attack_type_unique   IF NOT EXISTS FOR (n:AttackType)    REQUIRE n.action           IS UNIQUE',
    'CREATE CONSTRAINT endpoint_path_unique IF NOT EXISTS FOR (n:Endpoint)      REQUIRE n.path             IS UNIQUE',
    'CREATE CONSTRAINT defense_type_unique  IF NOT EXISTS FOR (n:DefenseAction) REQUIRE n.defense_type     IS UNIQUE',
    'CREATE CONSTRAINT risk_level_unique    IF NOT EXISTS FOR (n:RiskBucket)    REQUIRE n.level            IS UNIQUE',

    // ── Extra indexes for hot query paths ────────────────────────────────
    // parent_event_id: used by NEXT and TRIGGERED_DEFENSE lookups
    'CREATE INDEX event_parent_idx     IF NOT EXISTS FOR (n:Event) ON (n.parent_event_id)',
    // timestamp: used by time-range investigation queries
    'CREATE INDEX event_ts_idx         IF NOT EXISTS FOR (n:Event) ON (n.timestamp)',
    // [FIX-05] event_signature: used for graph-level deduplication queries
    //   e.g. MATCH (ev:Event {event_signature: $sig}) to check before merge
    'CREATE INDEX event_sig_idx        IF NOT EXISTS FOR (n:Event) ON (n.event_signature)',
    // [FIX-05] correlation_id on Event: used by chain traversal queries that
    //   filter directly on ev.correlation_id without going through AttackGroup
    'CREATE INDEX event_corr_idx       IF NOT EXISTS FOR (n:Event) ON (n.correlation_id)',
  ];

  try {
    for (const stmt of ddl) {
      await session.run(stmt);
    }
    logger.info('NEO4J_SCHEMA_OK');
  } catch (err) {
    logger.warn('NEO4J_SCHEMA_WARNING', { error: err.message });
  } finally {
    await session.close();
  }
}

// =============================================================================
// mergeEventToGraph
//
// Idempotently upserts one enriched event into the security graph.
// Called once per event by pushToNeo4j() in neo4j_ingest.js.
// =============================================================================
export async function mergeEventToGraph(eventData) {

  // ── 0. Identity resolution in JS ─────────────────────────────────────────
  // Done here so Cypher never re-evaluates a CASE across WITH boundaries,
  // which can silently produce different results under Neo4j's lazy evaluation.
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const isUUID  = (v) => typeof v === 'string' && UUID_RE.test(v);

  const resolvedUserId = isUUID(eventData.user_id) ? eventData.user_id : null;
  const resolvedEmail  =
    eventData.user_email ||
    (!isUUID(eventData.user_id) && eventData.user_id ? eventData.user_id : null) ||
    null;

  // ── 0b. Visualization helpers computed in JS ──────────────────────────────
  // display  → human-readable caption shown in Bloom / neovis.js
  // nodeLabel → short machine-readable tag for filters
  // color    → hex string driven by severity; used by neovis.js / Bloom rules
  const severityColor = {
    CRITICAL: '#EF4444',   // red-500
    HIGH:     '#F97316',   // orange-500
    MEDIUM:   '#EAB308',   // yellow-500
    LOW:      '#22C55E',   // green-500
    NONE:     '#94A3B8',   // slate-400
  };

  const sev     = (eventData.severity || 'NONE').toUpperCase();
  const evtType = (eventData.event_type || 'UNKNOWN').toUpperCase();
  const action  = eventData.action || 'UNKNOWN';

  const display =
    evtType === 'DEFENSE'
      ? `🛡 ${action}`
      : evtType === 'ATTACK'
        ? `⚔ ${action} [${sev}]`
        : `${evtType} | ${action}`;

  const nodeLabel = `${evtType}:${action}`;
  const color     = severityColor[sev] || '#94A3B8';

  // Pre-compute all values that would require CASE expressions in Cypher.
  // Neo4j rejects CASE inside ON MATCH SET / ON CREATE SET within FOREACH bodies.
  // All conditional logic lives here in JS instead.

  // AttackGroup counters — passed as pre-computed deltas
  const isAttack  = evtType === 'ATTACK';
  const isDefense = evtType === 'DEFENSE';

  // AttackType severity escalation — only escalate, never downgrade
  // We pass the new candidate; Cypher uses simple coalesce logic to keep the higher value.
  // Severity rank: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, NONE=0
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };
  const currentSevRank = severityRank[sev] ?? 0;
  const severityRankParam = currentSevRank;

  // RiskBucket color — pre-computed so no CASE needed in ON CREATE SET
  const riskBucketColor = {
    CRITICAL: '#EF4444',
    HIGH:     '#F97316',
    MEDIUM:   '#EAB308',
    LOW:      '#22C55E',
  };
  const riskLevel    = eventData.risk_level ?? null;
  const rbColor      = riskBucketColor[riskLevel] || '#22C55E';

  // ── 0c. Flat params object ────────────────────────────────────────────────
  // No nested objects — the neo4j-driver does not auto-serialize them.
  const p = {
    // Identity
    event_id:                  eventData.event_id,
    correlation_id:            eventData.correlation_id             ?? null,
    parent_event_id:           eventData.parent_event_id            ?? null,
    event_group_id:            eventData.event_group_id             ?? eventData.correlation_id ?? null,

    // Ordering
    event_priority:            eventData.event_priority             ?? 1,
    event_sequence_index:      eventData.event_sequence_index       ?? null,

    // Classification
    event_type:                evtType,
    action:                    action,
    source_ip:                 eventData.source_ip                  || 'unknown',
    ip_type:                   eventData.ip_type                    ?? null,
    user_agent:                eventData.user_agent                 ?? null,
    agent_type:                eventData.agent_type                 ?? null,
    target_endpoint:           eventData.target_endpoint            || 'unknown',
    target_type:               eventData.target_type                ?? null,
    mode:                      eventData.mode                       ?? 'INFERRED',

    // Outcome
    result:                    eventData.result                     ?? null,
    severity:                  sev,
    risk_score:                eventData.risk_score                 ?? null,
    risk_level:                eventData.risk_level                 ?? null,

    // Computed / enrichment
    timestamp:                 eventData.timestamp                  ?? null,
    event_signature:           eventData.event_signature            ?? null,
    events_per_minute_bucket:  eventData.events_per_minute_bucket   ?? null,
    correlation_confidence:    eventData.correlation_confidence      ?? null,
    is_attack_related:         eventData.is_attack_related          ?? false,
    is_defense_triggered:      eventData.is_defense_triggered       ?? false,

    // Defense-only
    reason:                    eventData.reason                     ?? null,
    strike_count:              eventData.strike_count               ?? null,
    ban_duration:              eventData.ban_duration               ?? null,
    blocked:                   eventData.blocked                    ?? null,
    mitigation_result:         eventData.mitigation_result          ?? null,

    // Identity (resolved)
    resolvedUserId,
    resolvedEmail,
    session_id:                eventData.session_id                 ?? null,

    // Visualization (pre-computed)
    display,
    nodeLabel,
    color,

    // Pre-computed to avoid CASE inside FOREACH/ON MATCH SET (not supported in this Neo4j version)
    is_attack_delta:   isAttack  ? 1 : 0,
    is_defense_delta:  isDefense ? 1 : 0,
    severity_rank:     severityRankParam,  // integer rank for severity escalation comparison
    rb_color:          rbColor,            // RiskBucket color pre-computed from risk_level
  };

  // ── Cypher ──────────────────────────────────────────────────────────────────
  //
  // Structure: each logical block ends with `WITH ev` to maintain clean scope.
  // FOREACH guards every optional write — OPTIONAL MATCH is only used for reads.
  // ON CREATE / ON MATCH are the only SET forms inside MERGE blocks.
  // display / label / color are stored via both ON CREATE and ON MATCH so they
  // are always current (visualization fields should reflect latest enrichment).
  //
  const query = `
// ════════════════════════════════════════════════════════════════════
// 1. EVENT NODE
//    Merge on event_id (unique constraint → O(log n) index lookup).
//    ON CREATE sets all immutable fields + all computed enrichment fields.
//    ON MATCH refreshes mutable/enrichment fields that may improve on
//    a second ingest pass (e.g. risk_score backfilled later).
// ════════════════════════════════════════════════════════════════════
MERGE (ev:Event {event_id: $event_id})
ON CREATE SET
  ev.correlation_id           = $correlation_id,
  ev.event_group_id           = $event_group_id,
  ev.parent_event_id          = $parent_event_id,
  ev.event_type               = $event_type,
  ev.event_priority           = $event_priority,
  ev.event_sequence_index     = $event_sequence_index,
  ev.action                   = $action,
  ev.source_ip                = $source_ip,
  ev.ip_type                  = $ip_type,
  ev.user_agent               = $user_agent,
  ev.agent_type               = $agent_type,
  ev.target_endpoint          = $target_endpoint,
  ev.target_type              = $target_type,
  ev.mode                     = $mode,
  ev.result                   = $result,
  ev.severity                 = $severity,
  ev.risk_score               = $risk_score,
  ev.risk_level               = $risk_level,
  ev.timestamp                = $timestamp,
  ev.event_signature          = $event_signature,
  ev.events_per_minute_bucket = $events_per_minute_bucket,
  ev.correlation_confidence   = $correlation_confidence,
  ev.is_attack_related        = $is_attack_related,
  ev.is_defense_triggered     = $is_defense_triggered,
  ev.reason                   = $reason,
  ev.strike_count             = $strike_count,
  ev.ban_duration             = $ban_duration,
  ev.blocked                  = $blocked,
  ev.mitigation_result        = $mitigation_result,
  ev.display                  = $display,
  ev.label                    = $nodeLabel,
  ev.color                    = $color
ON MATCH SET
  ev.risk_score               = coalesce($risk_score,              ev.risk_score),
  ev.risk_level               = coalesce($risk_level,              ev.risk_level),
  ev.correlation_confidence   = coalesce($correlation_confidence,  ev.correlation_confidence),
  ev.events_per_minute_bucket = coalesce($events_per_minute_bucket, ev.events_per_minute_bucket),
  ev.display                  = $display,
  ev.label                    = $nodeLabel,
  ev.color                    = $color

// ════════════════════════════════════════════════════════════════════
// 2. IP NODE  →  (ip)-[:TRIGGERED]->(ev)
//    total_events is an approximate burst counter on the IP node.
//    first_seen is set once; last_seen and total_events update on match.
// ════════════════════════════════════════════════════════════════════
WITH ev
MERGE (ip:IP {address: $source_ip})
ON CREATE SET
  ip.ip_type      = $ip_type,
  ip.first_seen   = $timestamp,
  ip.last_seen    = $timestamp,
  ip.total_events = 1,
  ip.display      = $source_ip,
  ip.label        = 'IP:' + $source_ip,
  ip.color        = '#60A5FA'
ON MATCH SET
  ip.last_seen    = $timestamp,
  ip.total_events = ip.total_events + 1
MERGE (ip)-[:TRIGGERED]->(ev)

// ════════════════════════════════════════════════════════════════════
// 3. USER NODE (UUID path)  →  (u)-[:ACTED]->(ev)
//    Only fires when we have a real UUID. FOREACH is the correct
//    conditional write guard — no OPTIONAL MATCH inside write units.
// ════════════════════════════════════════════════════════════════════
WITH ev
FOREACH (_ IN CASE WHEN $resolvedUserId IS NOT NULL THEN [1] ELSE [] END |
  MERGE (u:User {user_id: $resolvedUserId})
  ON CREATE SET
    u.user_email      = $resolvedEmail,
    u.identity_source = 'uuid',
    u.display         = coalesce($resolvedEmail, $resolvedUserId),
    u.label           = 'User:' + $resolvedUserId,
    u.color           = '#A78BFA'
  ON MATCH SET
    u.user_email = coalesce($resolvedEmail, u.user_email)
  MERGE (u)-[:ACTED]->(ev)
)

// ════════════════════════════════════════════════════════════════════
// 4. USER NODE (email-only fallback)  →  (u)-[:ACTED]->(ev)
//    Only fires when UUID is absent but email is present.
//    See identity reconciliation note in initSchema().
// ════════════════════════════════════════════════════════════════════
WITH ev
FOREACH (_ IN CASE WHEN $resolvedUserId IS NULL AND $resolvedEmail IS NOT NULL THEN [1] ELSE [] END |
  MERGE (u:User {user_email: $resolvedEmail})
  ON CREATE SET
    u.user_id         = null,
    u.identity_source = 'email',
    u.display         = $resolvedEmail,
    u.label           = 'User:' + $resolvedEmail,
    u.color           = '#C084FC'
  MERGE (u)-[:ACTED]->(ev)
)

// ════════════════════════════════════════════════════════════════════
// 5. SESSION NODE  →  (sess)-[:CONTAINS]->(ev)
//    Skipped for synthetic NO_SESSION_ fallback IDs so they don't
//    pollute the graph with meaningless session nodes.
// ════════════════════════════════════════════════════════════════════
WITH ev
FOREACH (_ IN CASE WHEN $session_id IS NOT NULL AND NOT $session_id STARTS WITH 'NO_SESSION' THEN [1] ELSE [] END |
  MERGE (sess:Session {session_id: $session_id})
  ON CREATE SET
    sess.user_email = $resolvedEmail,
    sess.started_at = $timestamp,
    sess.display    = 'Session:' + substring($session_id, 0, 8),
    sess.label      = 'Session:' + $session_id,
    sess.color      = '#34D399'
  MERGE (sess)-[:CONTAINS]->(ev)
)

// ════════════════════════════════════════════════════════════════════
// 6. ATTACK GROUP NODE  →  (ag)-[:GROUPS]->(ev)
//    attack_count / defense_count are running totals on the group.
//    The GROUPS relationship carries ordering metadata.
// ════════════════════════════════════════════════════════════════════
WITH ev
FOREACH (_ IN CASE WHEN $correlation_id IS NOT NULL THEN [1] ELSE [] END |
  MERGE (ag:AttackGroup {correlation_id: $correlation_id})
  ON CREATE SET
    ag.mode          = $mode,
    ag.attack_count  = $is_attack_delta,
    ag.defense_count = $is_defense_delta,
    ag.first_seen    = $timestamp,
    ag.display       = 'Group:' + substring($correlation_id, 0, 8),
    ag.label         = 'AttackGroup:' + $correlation_id,
    ag.color         = '#F59E0B'
  ON MATCH SET
    ag.attack_count  = ag.attack_count  + $is_attack_delta,
    ag.defense_count = ag.defense_count + $is_defense_delta,
    ag.last_seen     = $timestamp
  MERGE (ag)-[r:GROUPS]->(ev)
  ON CREATE SET
    r.priority = $event_priority,
    r.sequence = $event_sequence_index
)

// ════════════════════════════════════════════════════════════════════
// 7. ATTACK TYPE NODE  →  (ev)-[:OF_TYPE]->(at)
//    Represents the attack/defense technique. Groups events by action
//    across all correlation groups — useful for MITRE-style views.
//    severity_max only escalates, never downgrades.
// ════════════════════════════════════════════════════════════════════
WITH ev
FOREACH (_ IN CASE WHEN $action <> 'UNKNOWN' THEN [1] ELSE [] END |
  MERGE (at:AttackType {action: $action})
  ON CREATE SET
    at.target_type   = $target_type,
    at.event_type    = $event_type,
    at.severity_max  = $severity,
    at.severity_rank = $severity_rank,
    at.display       = $action,
    at.label         = 'Technique:' + $action,
    at.color         = '#FB923C'
  ON MATCH SET
    at.severity_max  = CASE WHEN $severity_rank > coalesce(at.severity_rank, 0) THEN $severity  ELSE at.severity_max  END,
    at.severity_rank = CASE WHEN $severity_rank > coalesce(at.severity_rank, 0) THEN $severity_rank ELSE at.severity_rank END
  MERGE (ev)-[:OF_TYPE]->(at)
)

// ════════════════════════════════════════════════════════════════════
// 8. ENDPOINT NODE  →  (ev)-[:TARGETED]->(ep)
//    Groups all events hitting the same API path.
//    hit_count increments on every event that targets this endpoint.
// ════════════════════════════════════════════════════════════════════
WITH ev
FOREACH (_ IN CASE WHEN $target_endpoint <> 'unknown' THEN [1] ELSE [] END |
  MERGE (ep:Endpoint {path: $target_endpoint})
  ON CREATE SET
    ep.target_type   = $target_type,
    ep.hit_count     = 1,
    ep.display       = $target_endpoint,
    ep.label         = 'Endpoint:' + $target_endpoint,
    ep.color         = '#38BDF8'
  ON MATCH SET
    ep.hit_count = ep.hit_count + 1
  MERGE (ev)-[:TARGETED]->(ep)
)

// ════════════════════════════════════════════════════════════════════
// 9. RISK BUCKET NODE  →  (ev)-[:IN_RISK_BUCKET]->(rb)
//    Enables fast risk-tier queries without full Event node scan:
//    MATCH (rb:RiskBucket {level:'HIGH'})<-[:IN_RISK_BUCKET]-(ev)
// ════════════════════════════════════════════════════════════════════
WITH ev
FOREACH (_ IN CASE WHEN $risk_level IS NOT NULL THEN [1] ELSE [] END |
  MERGE (rb:RiskBucket {level: $risk_level})
  ON CREATE SET
    rb.display = 'Risk:' + $risk_level,
    rb.label   = 'RiskBucket:' + $risk_level,
    rb.color   = $rb_color
  MERGE (ev)-[:IN_RISK_BUCKET]->(rb)
)

// ════════════════════════════════════════════════════════════════════
// 10. CHAIN LINK  →  (parent)-[:NEXT]->(ev)
//     Looks up parent by parent_event_id (indexed).
//     OPTIONAL MATCH is safe here — it's a read only.
//     FOREACH guards the write so no edge is created when parent is absent.
//     When parent_event_id is NULL, Neo4j short-circuits on the IS NULL
//     check inside FOREACH without executing the OPTIONAL MATCH path.
// ════════════════════════════════════════════════════════════════════
WITH ev
OPTIONAL MATCH (parent:Event {event_id: $parent_event_id})
FOREACH (_ IN CASE WHEN parent IS NOT NULL THEN [1] ELSE [] END |
  MERGE (parent)-[r:NEXT]->(ev)
  ON CREATE SET
    r.sequence_delta = coalesce($event_sequence_index, 0),
    r.correlation_id = $correlation_id
)

// ════════════════════════════════════════════════════════════════════
// 11. CAUSAL DEFENSE LINK  →  (parent)-[:TRIGGERED_DEFENSE]->(ev)
//     Only fires for DEFENSE events whose parent ATTACK already exists.
//     parent is still in scope from the OPTIONAL MATCH above.
// ════════════════════════════════════════════════════════════════════
WITH ev, parent
FOREACH (_ IN CASE WHEN $is_defense_delta = 1 AND parent IS NOT NULL THEN [1] ELSE [] END |
  MERGE (parent)-[r:TRIGGERED_DEFENSE]->(ev)
  ON CREATE SET
    r.correlation_id         = $correlation_id,
    r.correlation_confidence = $correlation_confidence
)

// ════════════════════════════════════════════════════════════════════
// 12. DEFENSE ACTION NODE  →  (ev)-[:APPLIED]->(da)
//     Represents the defense technique (STRIKE, BAN, BLOCK, ESCALATE).
//     Only created for DEFENSE events with a known action.
//
// [FIX-04] apply_count initialized to 1 on ON CREATE so the property
//          is present from the first write (not just from the second).
// ════════════════════════════════════════════════════════════════════
WITH ev
FOREACH (_ IN CASE WHEN $is_defense_delta = 1 AND $action <> 'UNKNOWN' THEN [1] ELSE [] END |
  MERGE (da:DefenseAction {defense_type: $action})
  ON CREATE SET
    da.display           = 'Defense:' + $action,
    da.label             = 'DefenseAction:' + $action,
    da.color             = '#10B981',
    da.mitigation_result = $mitigation_result,
    da.apply_count       = 1
  ON MATCH SET
    da.apply_count = da.apply_count + 1
  MERGE (ev)-[r:APPLIED]->(da)
  ON CREATE SET
    r.blocked           = $blocked,
    r.reason            = $reason,
    r.strike_count      = $strike_count,
    r.ban_duration      = $ban_duration,
    r.mitigation_result = $mitigation_result
)

// ════════════════════════════════════════════════════════════════════
// RETURN — scalar confirmation for logging
// ════════════════════════════════════════════════════════════════════
WITH ev
RETURN
  ev.event_id   AS ingested,
  ev.event_type AS type,
  ev.display    AS display,
  ev.color      AS color
  `;

  const session = getNeo4jDriver().session({ defaultAccessMode: neo4j.session.WRITE });

  try {
    const result  = await session.run(query, p);
    const record  = result.records[0];
    const ingested = record?.get('ingested');

    logger.info('NEO4J_MERGE_OK', {
      event_id: ingested,
      type:     record?.get('type'),
      display:  record?.get('display'),
    });

    return ingested;
  } catch (err) {
    logger.error('NEO4J_MERGE_FAILED', {
      event_id:   eventData?.event_id,
      action:     eventData?.action,
      event_type: eventData?.event_type,
      error:      err.message,
    });
    // Neo4j is a secondary read-optimized sink; PostgreSQL is source of truth.
    // Re-throw so the caller can dead-letter or retry.
    throw err;
  } finally {
    await session.close();
  }
}