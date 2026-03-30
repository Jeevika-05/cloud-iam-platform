import prisma from '../../shared/config/database.js';
import logger from '../../shared/utils/logger.js';
import crypto from 'crypto';

export const logSecurityEvent = async ({ userId, action, status, ip, userAgent, metadata }) => {
  try {
    const metaJson = metadata ? JSON.parse(JSON.stringify(metadata)) : null;
    const auditRecord = await prisma.auditLog.create({
      data: {
        userId,
        action,
        status,
        ip,
        userAgent,
        metadata: metaJson,
      },
    });

    // 🕸️ GRAPH_EVENT: Emit normalized event for Neo4j (async stream/log parsing)
    // We infer target details from action where possible, otherwise use SAFE defaults
    const isSimulated = userAgent?.includes('attack-engine') || ip?.startsWith('192.168.');
    
    const graphEvent = {
        event_id: auditRecord.id, // Re-use the DB UUID
        correlation_id: metaJson?.correlation_id || crypto.randomUUID(),
        user_id: userId || 'SYSTEM',
        user_email: metaJson?.user_email || null,
        event_type: "SECURITY",
        action,
        source_ip: ip || 'unknown',
        ip_type: isSimulated ? "SIMULATED" : "REAL",
        user_agent: userAgent || 'unknown',
        agent_type: isSimulated ? "SIMULATED" : "REAL",
        target_type: "API",
        target_endpoint: metaJson?.path || "internal",
        result: status,
        severity: status === 'FAILURE' ? 'MEDIUM' : 'LOW',
        timestamp: new Date().toISOString()
    };

    logger.info('GRAPH_EVENT', graphEvent);
  } catch (error) {
    logger.error('Failed to write audit log', { error: error.message });
  }
};
