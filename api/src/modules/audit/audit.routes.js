// ─────────────────────────────────────────────────────────────
// AUDIT EVENTS API — Exposes security events for Neo4j ingestion
// ─────────────────────────────────────────────────────────────
// GET /api/v1/audit/events          → paginated, filterable (auth required)
// GET /api/v1/audit/events/defense  → DEFENSE events only (internalAuth required)
// GET /api/v1/audit/debug/counts    → diagnostic endpoint (internalAuth required)
// ─────────────────────────────────────────────────────────────

import { Router } from 'express';
import prisma from '../../shared/config/database.js';
import logger from '../../shared/utils/logger.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { internalAuth } from '../../shared/middleware/internalAuth.js';
import { internalLimiter } from '../../shared/middleware/rateLimiter.js';
import { authorizeRoles } from '../../shared/middleware/authorizeRoles.js';

const router = Router();

// ─────────────────────────────────────────────
// DIAGNOSTIC: Quick count of defense events in DB
// Helps debug "are events even being inserted?"
// 🔒 Internal only — requires x-internal-token
// ─────────────────────────────────────────────
router.get('/debug/counts', internalLimiter, internalAuth, async (req, res) => {
  try {
    const totalAuditLogs = await prisma.auditLog.count();
    const strikeRecorded = await prisma.auditLog.count({
      where: { action: 'STRIKE_RECORDED' },
    });
    const ipBanned = await prisma.auditLog.count({
      where: { action: 'IP_BANNED' },
    });
    const blockedBannedIp = await prisma.auditLog.count({
      where: { action: 'BLOCKED_BANNED_IP' },
    });
    const blockedRequest = await prisma.auditLog.count({
      where: { action: 'BLOCKED_REQUEST' },
    });

    // Also check for defense events by scanning metadata
    const allLogs = await prisma.auditLog.findMany({
      select: { action: true, status: true, metadata: true },
      take: 20,
      orderBy: { createdAt: 'desc' },
    });

    const recentActions = allLogs.map(l => ({
      action: l.action,
      status: l.status,
      event_type: l.metadata?.event_type || 'unknown',
    }));

    return res.json({
      total_audit_logs: totalAuditLogs,
      defense_events: {
        STRIKE_RECORDED: strikeRecorded,
        IP_BANNED: ipBanned,
        BLOCKED_BANNED_IP: blockedBannedIp,
        BLOCKED_REQUEST: blockedRequest,
        total: strikeRecorded + ipBanned + blockedBannedIp + blockedRequest,
      },
      recent_events: recentActions,
    });
  } catch (error) {
    logger.error('AUDIT_DEBUG_FAILED', { error: error.message });
    return res.status(500).json({ error: error.message });
  }
});

// ─────────────────────────────────────────────
// DEFENSE EVENTS — Internal pipeline use only
// Must be registered BEFORE /events to avoid Express path collision
// 🔒 Requires x-internal-token — not publicly accessible
// ─────────────────────────────────────────────
router.get('/events/defense', internalLimiter, internalAuth, async (req, res) => {
  try {
    const { since, limit = '1000' } = req.query;
    const take = Math.min(parseInt(limit, 10) || 1000, 5000);

    const where = {
      action: { in: ['STRIKE_RECORDED', 'IP_BANNED', 'BLOCKED_BANNED_IP', 'BLOCKED_REQUEST'] },
    };

    if (since) {
      where.createdAt = { gte: new Date(since) };
    }

    const logs = await prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'asc' },
      take,
      include: {
        user: { select: { email: true } },
      },
    });

    const events = logs.map((log) => {
      const meta = log.metadata || {};
      return {
        event_id: meta.event_id || log.id,
        correlation_id: meta.correlation_id || log.id,
        user_id: log.userId || meta.user_id || 'SYSTEM',
        user_email: log.user?.email || meta.user_email || null,
        session_id: meta.session_id || null,
        event_type: meta.event_type || 'DEFENSE',
        action: log.action,
        source_ip: log.ip || meta.source_ip || 'unknown',
        ip_type: meta.ip_type || 'SIMULATED',
        user_agent: meta.user_agent || 'active-defender',
        agent_type: 'SYSTEM',
        target_type: meta.target_type || 'SYSTEM',
        target_endpoint: meta.target_endpoint || 'defense-engine',
        result: meta.result || 'BLOCKED',
        severity: meta.severity || 'MEDIUM',
        risk_score: meta.risk_score ?? null,
        risk_level: meta.risk_level ?? null,
        timestamp: meta.timestamp || log.createdAt.toISOString(),
        mode: meta.mode,
        reason: meta.reason,
        strike_count: meta.strike_count,
        ban_duration: meta.ban_duration,
        ban_number: meta.ban_number,
        total_strikes: meta.total_strikes,
      };
    });

    return res.json({
      _metadata: {
        source: 'audit_defense_api',
        total_events: events.length,
        event_types: ['STRIKE_RECORDED', 'IP_BANNED', 'BLOCKED_BANNED_IP', 'BLOCKED_REQUEST'],
        generated_at: new Date().toISOString(),
      },
      events,
    });
  } catch (error) {
    logger.error('AUDIT_DEFENSE_QUERY_FAILED', { error: error.message });
    return res.status(500).json({
      success: false,
      code: 'AUDIT_QUERY_ERROR',
      message: 'Failed to query defense events',
    });
  }
});

// ─────────────────────────────────────────────
// GENERAL EVENTS — Auth required
// ─────────────────────────────────────────────
router.get('/events', authenticate, authorizeRoles('ADMIN', 'SECURITY_ANALYST'), async (req, res) => {
  try {
    const {
      event_type,
      action,
      since,
      limit = '500',
      offset = '0',
      format = 'neo4j',
    } = req.query;

    const take = Math.min(parseInt(limit, 10) || 500, 5000);
    const skip = parseInt(offset, 10) || 0;

    const where = {};
    if (action) where.action = action;
    if (since) where.createdAt = { gte: new Date(since) };
    // Push event_type filter to the DB via Prisma JSON path query —
    // avoids a full in-process scan of the metadata column.
    if (event_type) {
      where.metadata = { path: ['event_type'], equals: event_type };
    }

    const logs = await prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'asc' },
      take,
      skip,
      include: {
        user: { select: { email: true } },
      },
    });

    const filtered = logs;

    if (format === 'neo4j') {
      const events = filtered.map((log) => {
        const meta = log.metadata || {};
        return {
          event_id: meta.event_id || log.id,
          correlation_id: meta.correlation_id || log.id,
          user_id: log.userId || meta.user_id || 'SYSTEM',
          user_email: log.user?.email || meta.user_email || null,
          session_id: meta.session_id || null,
          event_type: meta.event_type || 'SECURITY',
          action: log.action,
          source_ip: log.ip || meta.source_ip || 'unknown',
          ip_type: meta.ip_type || 'REAL',
          user_agent: log.userAgent || meta.user_agent || 'unknown',
          agent_type: meta.agent_type || 'REAL',
          target_type: meta.target_type || 'API',
          target_endpoint: meta.target_endpoint || meta.path || 'internal',
          result: meta.result || log.status,
          severity: meta.severity || 'LOW',
          risk_score: meta.risk_score ?? null,
          risk_level: meta.risk_level ?? null,
          timestamp: meta.timestamp || log.createdAt.toISOString(),
          ...(meta.event_type === 'DEFENSE' && {
            mode: meta.mode,
            reason: meta.reason,
            strike_count: meta.strike_count,
            ban_duration: meta.ban_duration,
            ban_number: meta.ban_number,
            total_strikes: meta.total_strikes,
          }),
        };
      });

      return res.json({
        _metadata: {
          source: 'audit_log_api',
          total_returned: events.length,
          offset: skip,
          limit: take,
          filter: { event_type, action, since },
          generated_at: new Date().toISOString(),
        },
        events,
      });
    }

    return res.json({
      total: filtered.length,
      offset: skip,
      limit: take,
      logs: filtered,
    });
  } catch (error) {
    logger.error('AUDIT_EVENTS_QUERY_FAILED', { error: error.message });
    return res.status(500).json({
      success: false,
      code: 'AUDIT_QUERY_ERROR',
      message: 'Failed to query audit events',
    });
  }
});

export default router;