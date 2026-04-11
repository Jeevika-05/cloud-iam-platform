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
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { getAuditEvents } from '../auth/audit.service.js';

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

    return successResponse(res, {
      total_audit_logs: totalAuditLogs,
      defense_events: {
        STRIKE_RECORDED: strikeRecorded,
        IP_BANNED: ipBanned,
        BLOCKED_BANNED_IP: blockedBannedIp,
        BLOCKED_REQUEST: blockedRequest,
        total: strikeRecorded + ipBanned + blockedBannedIp + blockedRequest,
      },
      recent_events: recentActions,
    }, 'Audit counts retrieved successfully');
  } catch (error) {
    logger.error('AUDIT_DEBUG_FAILED', { error: error.message });
    return errorResponse(res, error.message, 500, 'AUDIT_DEBUG_FAILED');
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

    return successResponse(res, {
      _metadata: {
        source: 'audit_defense_api',
        total_events: events.length,
        event_types: ['STRIKE_RECORDED', 'IP_BANNED', 'BLOCKED_BANNED_IP', 'BLOCKED_REQUEST'],
        generated_at: new Date().toISOString(),
      },
      events,
    }, 'Defense events retrieved successfully');
  } catch (error) {
    logger.error('AUDIT_DEFENSE_QUERY_FAILED', { error: error.message });
    return errorResponse(res, 'Failed to query defense events', 500, 'AUDIT_QUERY_ERROR');
  }
});

// ─────────────────────────────────────────────
// GENERAL EVENTS — Auth + RBAC + Permission required
// Chain: authenticate → authorizeRoles → requirePermission → handler
// ─────────────────────────────────────────────
router.get('/events', authenticate, authorizeRoles('ADMIN', 'SECURITY_ANALYST', 'USER'), requirePermission('audit:view'), async (req, res) => {
  try {
    const events = await getAuditEvents({ 
      user: req.user, 
      filters: req.query 
    });

    const limit = parseInt(req.query.limit, 10) || 500;
    const skip = parseInt(req.query.offset, 10) || 0;

    return successResponse(res, {
      metadata: {
        source: 'audit_log_api',
        total_returned: events.length,
        offset: skip,
        limit: limit,
        filter: { 
          event_type: req.query.event_type, 
          action: req.query.action, 
          since: req.query.since 
        },
        generated_at: new Date().toISOString(),
      },
      events,
    }, 'Audit events retrieved successfully');
  } catch (error) {
    logger.error('AUDIT_EVENTS_QUERY_FAILED', { error: error.message });
    return errorResponse(res, 'Failed to query audit events', 500, 'AUDIT_QUERY_ERROR');
  }
});

export default router;