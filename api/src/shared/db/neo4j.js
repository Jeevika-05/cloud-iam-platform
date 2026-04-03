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

const neo4jUrl = process.env.NEO4J_URL || 'bolt://neo4j:7687';
const neo4jUser = process.env.NEO4J_USER || 'neo4j';
const neo4jPassword = process.env.NEO4J_PASSWORD || 'password';

// Singleton Driver
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
 * Idempotently merges an event into the Neo4j graph, establishing deterministic relationships.
 * 
 * Target Schema:
 * (IP {address})
 * (Event {event_id, correlation_id, event_type, action, priority, sequence, ...})
 * (IP)-[:TRIGGERED]->(Event)
 * (ParentEvent)-[:NEXT]->(Event)
 * (AttackEvent)-[:DEFENSE]->(DefenseEvent)
 */
export async function mergeEventToGraph(eventData) {
  const session = getNeo4jDriver().session({ defaultAccessMode: neo4j.session.WRITE });
  
  try {
    const parentId = eventData.parent_event_id || null;
    let fallbackCorrelation = eventData.correlation_id || eventData.event_id;

    // Cypher query designed for absolute idempotency.
    // Uses MERGE to ensure duplicate events do not create duplicate nodes.
    const cypher = `
      // 1. Ensure IP node exists
      MERGE (ip:IP {address: $source_ip})
      
      // 2. Ensure Event node exists
      MERGE (e:Event {event_id: $event_id})
      ON CREATE SET 
        e.correlation_id = $correlation_id,
        e.event_type = $event_type,
        e.action = $action,
        e.timestamp = $timestamp,
        e.priority = $priority,
        e.sequence = $sequence,
        e.risk_score = $risk_score,
        e.risk_level = $risk_level,
        e.agent_type = $agent_type,
        e.user_id = $user_id
      
      // 3. Link IP to Event
      MERGE (ip)-[:TRIGGERED]->(e)
      
      WITH e
      
      // 4. Sequential Linkage: (ParentEvent)-[:NEXT]->(Event)
      // Only executes if parent_id is provided
      CALL apoc.do.when(
        $parent_id IS NOT NULL,
        'MERGE (p:Event {event_id: parent_id}) MERGE (p)-[:NEXT]->(e) RETURN p',
        'RETURN NULL AS p',
        {parent_id: $parent_id, e: e}
      ) YIELD value AS seqResult
      
      WITH e
      
      // 5. Causal Linkage: (AttackEvent)-[:DEFENSE]->(DefenseEvent)
      // Only executes if this is a DEFENSE event explicitly targeting an attack chain
      CALL apoc.do.when(
        $event_type = "DEFENSE" AND $correlation_id IS NOT NULL,
        'MERGE (a:Event {event_id: correlation_id}) MERGE (a)-[:DEFENSE]->(e) RETURN a',
        'RETURN NULL AS a',
        {correlation_id: $correlation_id, e: e}
      ) YIELD value AS defResult
      
      RETURN e
    `;

    // Using APOC conditional execution requires APOC plugin. Assuming standard graph without apoc initially:
    // A standard Cypher approach avoiding APOC for pure sequential/causal links is safer.
    const pureCypher = `
      // 1. Ensure IP node exists
      MERGE (ip:IP {address: coalesce($source_ip, 'unknown')})
      
      // 2. Ensure Event node
      MERGE (e:Event {event_id: $event_id})
      ON CREATE SET 
        e.correlation_id = $correlation_id,
        e.event_type = $event_type,
        e.action = $action,
        e.timestamp = $timestamp,
        e.priority = $priority,
        e.sequence = $sequence,
        e.risk_score = $risk_score,
        e.risk_level = $risk_level,
        e.agent_type = $agent_type,
        e.user_id = $user_id
      
      // 3. Link IP -> Event
      MERGE (ip)-[:TRIGGERED]->(e)
      
      // 4. Link Parent -> Event (OPTIONAL MATCH pattern)
      FOREACH (ignoreMe IN CASE WHEN $parent_id IS NOT NULL THEN [1] ELSE [] END |
        MERGE (p:Event {event_id: $parent_id})
        MERGE (p)-[:NEXT]->(e)
      )
      
      // 5. Link Attack -> Defense (OPTIONAL MATCH pattern)
      FOREACH (ignoreMe IN CASE WHEN $event_type = 'DEFENSE' AND $correlation_id IS NOT NULL THEN [1] ELSE [] END |
        MERGE (a:Event {event_id: $correlation_id})
        MERGE (a)-[:DEFENSE]->(e)
      )
    `;

    await session.run(pureCypher, {
      event_id: eventData.event_id,
      correlation_id: fallbackCorrelation,
      event_type: eventData.event_type || 'UNKNOWN',
      action: eventData.action || 'UNKNOWN',
      timestamp: eventData.timestamp || new Date().toISOString(),
      priority: eventData.event_priority ?? 1,
      sequence: eventData.event_sequence_index ?? 0,
      risk_score: eventData.risk_score ?? null,
      risk_level: eventData.risk_level ?? 'LOW',
      agent_type: eventData.agent_type ?? 'UNKNOWN',
      user_id: eventData.user_id ?? null,
      source_ip: eventData.source_ip || 'unknown',
      parent_id: parentId,
    });

  } catch (err) {
    logger.error('NEO4J_MERGE_FAILED', { 
      event_id: eventData.event_id,
      error: err.message 
    });
    // Explicitly do not throw to avoid crashing the worker completely if graph is down.
    // The DB write (PostgreSQL) is the source of truth, Neo4j is a secondary sink.
  } finally {
    await session.close();
  }
}
