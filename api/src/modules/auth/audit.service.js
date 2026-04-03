import logger from '../../shared/utils/logger.js';
import crypto from 'crypto';
import { recordStrike } from '../../shared/middleware/activeDefender.js';
import redisClient from '../../shared/config/redis.js';
import { classifyIp } from '../../shared/utils/ipClassifier.js';
import { securityEventSeverityCounter } from '../../metrics/metrics.js';

// ─────────────────────────────────────────────
// SEVERITY MAPPING: status → defense severity
// ─────────────────────────────────────────────
const SEVERITY_MAP = {
  FAILURE: 'HIGH',
  MFA_FAILED: 'HIGH',
  SUSPICIOUS_SESSION_DETECTED: 'CRITICAL',
  SESSION_COMPROMISED: 'CRITICAL',
  // Default failures
};

const inferSeverity = (status) => {
  return SEVERITY_MAP[status] || (status?.includes('FAIL') ? 'MEDIUM' : null);
};

export const logSecurityEvent = async (payload) => {
  // Normalize payload because activeDefender sends the raw flat object while auth.service sends { action, status, ip, metadata }
  const { userId, action, status, ip, userAgent, metadata, event_type, source_ip, sessionId, ...restOfPayload } = payload;
  const resolvedIp = ip || source_ip;
  const resolvedStatus = status || payload.result || 'SUCCESS';
  const resolvedEventType = event_type || metadata?.event_type || 'SECURITY';

  const metaJson = metadata ? JSON.parse(JSON.stringify(metadata)) : {};
  const mergedMeta = { ...metaJson, ...restOfPayload, event_type: resolvedEventType };

  // 🛡️ ACTIVE DEFENSE: Record strike BEFORE database operations
  // Pass event_id from metadata for attack→defense correlation
  const severity = inferSeverity(resolvedStatus);
  const triggeringEventId = mergedMeta?.event_id || null;
  if (severity && resolvedIp && resolvedEventType !== "DEFENSE") {
    // Only record strikes for non-defense events to avert recursion
    recordStrike(resolvedIp, severity, `${action}:${resolvedStatus}`, triggeringEventId).catch((err) => {
      logger.error('RECORD_STRIKE_FAILED', { error: err.message, ip: resolvedIp });
    });
  }

  // Use centralized IP classifier (consistent with activeDefender and neo4j_ingest)
  const ipType = classifyIp(resolvedIp, userAgent);
  
  // 🕸️ GRAPH_EVENT: Emit normalized event for Neo4j IMMEDIATELY
  const baseGraphEvent = {
      event_id: crypto.randomUUID(),
      correlation_id: mergedMeta?.correlation_id || payload.correlationId || crypto.randomUUID(),
      user_id: userId || 'SYSTEM',
      user_email: mergedMeta?.user_email || null,
      session_id: sessionId || mergedMeta?.jti || null,
      event_type: resolvedEventType,
      action,
      source_ip: resolvedIp || 'unknown',
      ip_type: ipType,
      user_agent: userAgent || 'unknown',
      agent_type: ipType === 'SIMULATED' ? "SIMULATED" : "REAL",
      target_type: "API",
      target_endpoint: mergedMeta?.path || "internal",
      result: resolvedStatus,
      severity: payload.severity || mergedMeta?.severity || (resolvedStatus === 'FAILURE' ? 'MEDIUM' : 'LOW'),
      timestamp: payload.timestamp || mergedMeta?.timestamp || new Date().toISOString()
  };
  
  const graphEvent = { ...baseGraphEvent, ...mergedMeta };
  logger.info('GRAPH_EVENT', graphEvent);

  try {
    if (graphEvent.severity) {
      securityEventSeverityCounter.inc({ severity: graphEvent.severity });
    }

    // Write normalized graphEvent to Redis Stream.
    // MAXLEN ~ 10000: approximate trim keeps memory bounded (O(1) amortized).
    // The worker is the ONLY writer to PostgreSQL — no direct DB call here.
    await redisClient.xadd(
      'security_events',
      'MAXLEN', '~', '10000',
      '*',
      'data',
      JSON.stringify(graphEvent)
    );
    
    // Explicit confirmation for DEFENSE events (critical for pipeline debugging)
    if (resolvedEventType === 'DEFENSE') {
      logger.info('DEFENSE_EVENT_QUEUED', { action, source_ip: resolvedIp, status: resolvedStatus });
    }
  } catch (error) {
    logger.error('Failed to queue security event to Redis', {
      error: error.message,
      action,
      event_type: resolvedEventType,
      source_ip: resolvedIp,
    });
  }
};