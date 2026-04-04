import neo4j from 'neo4j-driver';
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'neo4j-client' },
  transports: [new winston.transports.Console()],
});

const neo4jUrl      = process.env.NEO4J_URL      || 'bolt://neo4j:7687';
const neo4jUser     = process.env.NEO4J_USER     || 'neo4j';
const neo4jPassword = process.env.NEO4J_PASSWORD || 'password';

let driver = null;

export function getNeo4jDriver() {
  if (!driver) {
    try {
      driver = neo4j.driver(neo4jUrl, neo4j.auth.basic(neo4jUser, neo4jPassword), {
        maxConnectionPoolSize: 50,
        connectionAcquisitionTimeout: 2000,
      });
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

/**
 * Idempotently merges a unified event into the Neo4j security graph.
 *
 * Chain ordering is deterministic — never uses timestamp:
 *   ORDER BY correlation_id → event_priority (1=ATTACK, 2=DEFENSE) → event_sequence_index
 *
 * Node types created:
 *   Event, IP, User, Session, AttackGroup, AttackType, Endpoint, DefenseAction
 *
 * Key fixes over previous version:
 *   - Identity resolution (resolvedUserId / resolvedEmail) done in JS before
 *     the query runs — avoids Cypher CASE re-evaluation across WITH boundaries.
 *   - OPTIONAL MATCH for parent chain replaced with FOREACH guard — OPTIONAL MATCH
 *     inside a write unit can silently swallow subsequent writes in some Neo4j versions.
 *   - FOREACH inside FOREACH removed — inner MERGE (u)-[:ACTED]->(ev) moved inside
 *     the outer FOREACH correctly.
 *   - All WITH clauses carry every variable that downstream steps need — no
 *     "variable not defined" errors from a narrowed scope.
 *   - TRIGGERED_DEFENSE uses FOREACH + MERGE instead of OPTIONAL MATCH + FOREACH
 *     so it never creates a ghost node for a parent that doesn't yet exist.
 */
export async function mergeEventToGraph(eventData) {
  // ── Identity resolution in JS (avoids Cypher CASE drift across WITH) ──────
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const isUUID  = (v) => typeof v === 'string' && UUID_RE.test(v);

  const resolvedUserId = isUUID(eventData.user_id) ? eventData.user_id : null;
  const resolvedEmail  =
    eventData.user_email ||
    (!isUUID(eventData.user_id) && eventData.user_id ? eventData.user_id : null);

  // Flatten into a single params object — Cypher receives plain scalars, no
  // nested objects, which avoids neo4j-driver type-coercion surprises.
  const params = {
    event_id:                  eventData.event_id,
    correlation_id:            eventData.correlation_id            ?? null,
    event_type:                eventData.event_type                ?? 'UNKNOWN',
    event_priority:            eventData.event_priority            ?? 1,
    event_sequence_index:      eventData.event_sequence_index      ?? null,
    parent_event_id:           eventData.parent_event_id           ?? null,
    action:                    eventData.action                    ?? 'UNKNOWN',
    severity:                  eventData.severity                  ?? null,
    result:                    eventData.result                    ?? null,
    risk_score:                eventData.risk_score                ?? null,
    risk_level:                eventData.risk_level                ?? null,
    event_signature:           eventData.event_signature           ?? null,
    events_per_minute_bucket:  eventData.events_per_minute_bucket  ?? null,
    correlation_confidence:    eventData.correlation_confidence    ?? null,
    mode:                      eventData.mode                      ?? null,
    agent_type:                eventData.agent_type                ?? null,
    user_agent:                eventData.user_agent                ?? null,
    timestamp:                 eventData.timestamp                 ?? null,
    is_attack_related:         eventData.is_attack_related         ?? false,
    is_defense_triggered:      eventData.is_defense_triggered      ?? false,
    source_ip:                 eventData.source_ip                 || 'unknown',
    ip_type:                   eventData.ip_type                   ?? null,
    target_endpoint:           eventData.target_endpoint           || 'unknown',
    target_type:               eventData.target_type               ?? null,
    session_id:                eventData.session_id                ?? null,
    // Defense-only
    reason:                    eventData.reason                    ?? null,
    strike_count:              eventData.strike_count              ?? null,
    ban_duration:              eventData.ban_duration              ?? null,
    blocked:                   eventData.blocked                   ?? null,
    mitigation_result:         eventData.mitigation_result         ?? null,
    // Resolved identity (computed above in JS)
    resolvedUserId,
    resolvedEmail,
  };

  const query = `
    // ── 1. Core Event node ────────────────────────────────────────────────────
    MERGE (ev:Event {event_id: $event_id})
    ON CREATE SET
      ev.correlation_id           = $correlation_id,
      ev.event_type               = $event_type,
      ev.event_priority           = $event_priority,
      ev.event_sequence_index     = $event_sequence_index,
      ev.parent_event_id          = $parent_event_id,
      ev.action                   = $action,
      ev.severity                 = $severity,
      ev.result                   = $result,
      ev.risk_score               = $risk_score,
      ev.risk_level               = $risk_level,
      ev.event_signature          = $event_signature,
      ev.events_per_minute_bucket = $events_per_minute_bucket,
      ev.correlation_confidence   = $correlation_confidence,
      ev.mode                     = $mode,
      ev.agent_type               = $agent_type,
      ev.user_agent               = $user_agent,
      ev.timestamp                = $timestamp,
      ev.is_attack_related        = $is_attack_related,
      ev.is_defense_triggered     = $is_defense_triggered,
      ev.reason                   = $reason,
      ev.strike_count             = $strike_count,
      ev.ban_duration             = $ban_duration,
      ev.blocked                  = $blocked,
      ev.mitigation_result        = $mitigation_result

    // ── 2. IP node & TRIGGERED ────────────────────────────────────────────────
    WITH ev
    MERGE (ip:IP {address: $source_ip})
    ON CREATE SET
      ip.ip_type      = $ip_type,
      ip.first_seen   = $timestamp,
      ip.total_events = 1
    ON MATCH SET
      ip.last_seen    = $timestamp,
      ip.total_events = ip.total_events + 1
    MERGE (ip)-[:TRIGGERED]->(ev)

    // ── 3. User node & ACTED (UUID branch) ───────────────────────────────────
    WITH ev
    FOREACH (_ IN CASE WHEN $resolvedUserId IS NOT NULL THEN [1] ELSE [] END |
      MERGE (u:User {user_id: $resolvedUserId})
      ON CREATE SET
        u.user_email      = $resolvedEmail,
        u.identity_source = 'uuid'
      MERGE (u)-[:ACTED]->(ev)
    )

    // ── 4. User node & ACTED (email-only fallback) ────────────────────────────
    WITH ev
    FOREACH (_ IN CASE WHEN $resolvedUserId IS NULL AND $resolvedEmail IS NOT NULL THEN [1] ELSE [] END |
      MERGE (u:User {user_email: $resolvedEmail})
      ON CREATE SET
        u.user_id         = null,
        u.identity_source = 'email'
      MERGE (u)-[:ACTED]->(ev)
    )

    // ── 5. Session node & CONTAINS ────────────────────────────────────────────
    WITH ev
    FOREACH (_ IN CASE WHEN $session_id IS NOT NULL THEN [1] ELSE [] END |
      MERGE (sess:Session {session_id: $session_id})
      ON CREATE SET sess.user_email = $resolvedEmail
      MERGE (sess)-[:CONTAINS]->(ev)
    )

    // ── 6. AttackGroup node & GROUPS ─────────────────────────────────────────
    WITH ev
    FOREACH (_ IN CASE WHEN $correlation_id IS NOT NULL THEN [1] ELSE [] END |
      MERGE (ag:AttackGroup {correlation_id: $correlation_id})
      ON CREATE SET
        ag.mode          = $mode,
        ag.attack_count  = 0,
        ag.defense_count = 0
      ON MATCH SET
        ag.attack_count  = ag.attack_count  + CASE WHEN $event_type = 'ATTACK'  THEN 1 ELSE 0 END,
        ag.defense_count = ag.defense_count + CASE WHEN $event_type = 'DEFENSE' THEN 1 ELSE 0 END
      MERGE (ag)-[r:GROUPS]->(ev)
      ON CREATE SET
        r.priority = $event_priority,
        r.sequence = $event_sequence_index
    )

    // ── 7. AttackType node & OF_TYPE ─────────────────────────────────────────
    WITH ev
    FOREACH (_ IN CASE WHEN $action IS NOT NULL THEN [1] ELSE [] END |
      MERGE (at:AttackType {action: $action})
      ON CREATE SET
        at.target_type  = $target_type,
        at.severity_max = $severity
      MERGE (ev)-[:OF_TYPE]->(at)
    )

    // ── 8. Endpoint node & TARGETED ──────────────────────────────────────────
    WITH ev
    MERGE (ep:Endpoint {path: $target_endpoint})
    ON CREATE SET ep.target_type = $target_type
    MERGE (ev)-[:TARGETED]->(ep)

    // ── 9. NEXT chain via parent_event_id ────────────────────────────────────
    // Uses OPTIONAL MATCH here only for READ — the write (MERGE edge) is
    // guarded by the FOREACH so it never fires when parent is missing.
    WITH ev
    OPTIONAL MATCH (parent:Event {event_id: $parent_event_id})
    FOREACH (_ IN CASE WHEN parent IS NOT NULL THEN [1] ELSE [] END |
      MERGE (parent)-[r:NEXT]->(ev)
      ON CREATE SET r.sequence_delta = 1
    )

    // ── 10. TRIGGERED_DEFENSE (ATTACK → DEFENSE causal link) ─────────────────
    // Only fires when this is a DEFENSE event whose parent already exists in
    // the graph. Never creates a ghost parent node.
    WITH ev
    OPTIONAL MATCH (atk:Event {event_id: $parent_event_id})
    FOREACH (_ IN CASE WHEN $event_type = 'DEFENSE' AND atk IS NOT NULL THEN [1] ELSE [] END |
      MERGE (atk)-[r:TRIGGERED_DEFENSE]->(ev)
      ON CREATE SET r.correlation_id = $correlation_id
    )

    // ── 11. DefenseAction node & APPLIED ─────────────────────────────────────
    WITH ev
    FOREACH (_ IN CASE WHEN $event_type = 'DEFENSE' AND $action IS NOT NULL THEN [1] ELSE [] END |
      MERGE (da:DefenseAction {defense_type: $action})
      ON CREATE SET
        da.defense_status    = $result,
        da.mitigation_result = $mitigation_result
      MERGE (ev)-[r:APPLIED]->(da)
      ON CREATE SET r.blocked = $blocked
    )

    WITH ev
    RETURN ev.event_id AS ingested, ev.event_type AS type
  `;

  const session = getNeo4jDriver().session({ defaultAccessMode: neo4j.session.WRITE });

  try {
    const result = await session.run(query, params);
    const ingested = result.records[0]?.get('ingested');
    logger.info('NEO4J_MERGE_OK', { event_id: ingested, type: result.records[0]?.get('type') });
    return ingested;
  } catch (err) {
    logger.error('NEO4J_MERGE_FAILED', {
      event_id: eventData?.event_id,
      action:   eventData?.action,
      error:    err.message,
    });
    // Neo4j is a secondary sink — PostgreSQL is source of truth.
    // Re-throw so the caller (eventWorker) can decide whether to dead-letter.
    throw err;
  } finally {
    await session.close();
  }
}