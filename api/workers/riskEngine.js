/**
 * ─────────────────────────────────────────────────────────────────────────────
 * riskEngine.js — Deterministic, Atomic Risk Scoring Engine
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * TASK 1 — REPLACE FLAG KEYS WITH STREAM PUSH
 *   Old design: SET defense:needed:<ip>:<slot> NX + SET defense:escalate:<ip>:<slot> NX
 *     Problems:
 *       - defenseWorker had to SCAN for keys (O(N) on keyspace)
 *       - No delivery guarantee — key could expire before worker ran
 *       - No retry/DLQ — failed defense silently dropped
 *
 *   New design: XADD to 'defense_events' stream
 *     Benefits:
 *       - O(1) push, O(1) read via XREADGROUP
 *       - PEL guarantees at-least-once delivery
 *       - XACK removes from PEL on success
 *       - XPENDING + XAUTOCLAIM handles retries
 *       - DLQ for permanently failing defense events
 *       - Works correctly under multiple defenseWorker instances
 *
 *   Deduplication contract (replaces NX flag):
 *     Each event pushed to defense_events carries a dedup_key:
 *       "<ip>:<slot>:<severity>"
 *     defenseWorker uses SET NX on defense:dedup:<dedup_key> (EX 600) before
 *     calling recordStrike. If NX fails → already processed → skip.
 *     This preserves the "one strike per severity per slot" invariant.
 *
 * All other functionality (Lua scoring, multi-entity, observability) unchanged.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join }  from 'path';
import logger from '../src/shared/utils/logger.js';
import config from '../src/shared/config/index.js';
import crypto from 'crypto';

// ─────────────────────────────────────────────
// Lua script — loaded once at startup
// ─────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const LUA_SCRIPT = readFileSync(join(__dirname, 'lua', 'atomicRiskUpdate.lua'), 'utf8');

// ─────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────
const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH:     15,
  MEDIUM:   8,
  LOW:      2,
};

const BASE_EVENT_WEIGHTS = {
  JWT_TAMPER:                   20,
  PASSWORD_BRUTE:               15,
  MFA_BRUTE_FORCE_SINGLE_IP:    15,
  MFA_BRUTE_FORCE_DISTRIBUTED:  25,
  SESSION_REUSE:                20,
  IDOR:                         20,
  CSRF:                         15,
  MASS_ASSIGNMENT:              15,
  ACCESS_TOKEN_ABUSE:           20,
  LOGIN_FAILED:                 5,
  MFA_FAILED:                   10,
  TOKEN_REUSE_DETECTED:         20,
  SUSPICIOUS_SESSION_DETECTED:  20,
  LOGIN_SUCCESS:                -10,
};

const PATTERNS = [
  { seq: ['MFA_FAILED', 'LOGIN_FAILED'],                         score: 15 },
  { seq: ['ACCESS_TOKEN_ABUSE', 'JWT_TAMPER'],                   score: 25 },
  { seq: ['TOKEN_REUSE_DETECTED', 'MFA_FAILED', 'LOGIN_FAILED'], score: 30 },
];

// TTL constants — aligned with sequence key lifetime + grace window
const RISK_STATE_TTL  = 90_000;  // 25h
const RISK_WINDOW_TTL = 600;     // 10min
const RISK_SEQ_TTL    = 3_600;   // 1h

// Defense stream
const DEFENSE_STREAM = 'defense_events';
const DEFENSE_STREAM_MAXLEN = 50_000;

// ─────────────────────────────────────────────
// PURE SCORING HELPERS
// ─────────────────────────────────────────────
function detectPatternScore(seq) {
  let best = 0;
  for (const { seq: pattern, score } of PATTERNS) {
    let match = true;
    for (let i = 0; i < pattern.length; i++) {
      if (seq[i] !== pattern[i]) { match = false; break; }
    }
    if (match && score > best) best = score;
  }
  return best;
}

function getContribution(type, count) {
  const w = BASE_EVENT_WEIGHTS[type] ?? 2;
  if (type === 'LOGIN_SUCCESS') return Math.max(-20, w * count);
  if (count <= 0) return 0;
  return Math.min(w * Math.min(count, 5), 50);
}

// ─────────────────────────────────────────────────────────────────────────────
export class RiskEngine {
  constructor(redisClient) {
    this.redis    = redisClient;
    this.luaSha   = null;
    this._loading = false;
  }

  // ─────────────────────────────────────────────
  // Lazy Lua SHA loader — concurrent-call safe
  // ─────────────────────────────────────────────
  async _getLuaSha() {
    if (this.luaSha) return this.luaSha;
    if (this._loading) {
      await new Promise(r => setTimeout(r, 50));
      return this.luaSha ?? await this._getLuaSha();
    }
    this._loading = true;
    try {
      this.luaSha = await this.redis.script('LOAD', LUA_SCRIPT);
      logger.info('RISK_LUA_LOADED', { sha: this.luaSha });
    } finally {
      this._loading = false;
    }
    return this.luaSha;
  }

  // Execute Lua with NOSCRIPT retry + structured observability
  async _runLua(keys, argv) {
    const sha   = await this._getLuaSha();
    const start = Date.now();
    let result;

    try {
      result = await this.redis.evalsha(sha, keys.length, ...keys, ...argv);
    } catch (err) {
      if (err.message?.includes('NOSCRIPT')) {
        this.luaSha  = null;
        const newSha = await this._getLuaSha();
        result = await this.redis.evalsha(newSha, keys.length, ...keys, ...argv);
      } else {
        throw err;
      }
    }

    logger.debug('RISK_LUA_EXEC', {
      duration_ms:    Date.now() - start,
      input_event:    argv[0],
      input_time_ms:  Number(argv[1]),
      out_count:      result?.[0],
      out_prev_score: result?.[1],
      out_seq_len:    (() => { try { return JSON.parse(result?.[3] ?? '[]').length; } catch { return 0; } })(),
    });

    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────
  /**
   * Push a defense task to the defense_events stream.
   *
   * TASK 1: Replaces SET defense:needed/escalate NX with XADD.
   *
   * Payload written to stream:
   *   event_id       — unique ID for this defense task
   *   correlation_id — from triggering ATTACK event (links defense to chain)
   *   source_ip      — IP to strike/ban
   *   severity       — HIGH | CRITICAL
   *   reason         — human-readable trigger reason
   *   score          — risk score that triggered this
   *   dedup_key      — "<ip>:<slot>:<severity>" used by defenseWorker for NX dedup
   *   timestamp      — ISO string
   *
   * The dedup_key on the stream payload allows defenseWorker to enforce
   * "one defense action per severity per 5-minute slot per IP"
   * using SET NX on defense:dedup:<dedup_key>.
   */
  async _pushDefenseTask(ip, slot, severity, score, delta, patternScore, triggeringEvent) {
    // BUG FIX: dedup_key MUST include correlation_id.
    //
    // OLD key: `${ip}:${slot}:${severity}`
    //   Problem: Two separate attack chains (different correlation_ids) hitting
    //   the same IP within the same 5-min slot at the same severity level produce
    //   an identical dedup_key. defenseWorker's SET NX on the second chain returns
    //   null (key already set by the first chain) → second defense is suppressed.
    //   This is incorrect — each attack chain deserves its own defense response.
    //
    // NEW key: `${ip}:${correlation_id}:${slot}:${severity}`
    //   Each chain is isolated. Deduplication still holds within the same chain
    //   (same correlation_id, same slot, same severity → one strike, as intended).
    const correlationId = triggeringEvent.correlation_id ?? 'no-corr';
    const dedupKey = `${ip}:${correlationId}:${slot}:${severity}`;
    const payload  = {
      event_id:       crypto.randomUUID(),
      correlation_id: triggeringEvent.correlation_id ?? null,
      source_ip:      ip,
      severity,
      reason:         `risk_score_${score}_delta_${Math.floor(delta)}_pattern_${patternScore}`,
      score,
      dedup_key:      dedupKey,
      timestamp:      new Date().toISOString(),
    };

    try {
      await this.redis.xadd(
        DEFENSE_STREAM,
        'MAXLEN', '~', DEFENSE_STREAM_MAXLEN,
        '*',
        'data', JSON.stringify(payload)
      );
      logger.info('DEFENSE_TASK_QUEUED', {
        ip,
        severity,
        score,
        dedup_key:      dedupKey,
        correlation_id: payload.correlation_id,
        event_id:       payload.event_id,
      });
    } catch (err) {
      // Stream write failure must NOT crash the scoring path
      logger.error('DEFENSE_TASK_QUEUE_FAILED', {
        ip,
        severity,
        error:          err.message,
        correlation_id: payload.correlation_id,
      });
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  /**
   * Compute risk for a single ATTACK event.
   *
   * HARD GATES:
   *   • event_type must not be "DEFENSE"
   *   • agent_type must NOT be "SYSTEM"
   */
  async processEvent(event) {
    try {
      // ── Guards ────────────────────────────────────────────────────────────
      if (!event || !event.source_ip) return null;
      const ip = event.source_ip;
      if (ip === 'unknown') return null;
      if (event.event_type === 'DEFENSE') return null;
      if (event.agent_type === 'SYSTEM')  return null;

      // ── Resolve event time ────────────────────────────────────────────────
      let eventTimeMs = Date.now();
      if (event.timestamp) {
        const parsed = new Date(event.timestamp).getTime();
        if (!isNaN(parsed) && parsed > 0) eventTimeMs = parsed;
      }

      // Slot is derived from event time — consistent with risk:window key
      const slot = Math.floor(eventTimeMs / 300_000);

      // ── Normalize eventType ───────────────────────────────────────────────
      let eventType = event.action || event.event_type || 'UNKNOWN';
      if (
        eventType === 'LOGIN_FAILED' &&
        (event.status === 'MFA_FAILED' || event.result === 'MFA_FAILED')
      ) {
        eventType = 'MFA_FAILED';
      }

      // ── Multi-entity scoring ──────────────────────────────────────────────
      const entities = [`IP:${ip}`];
      if (event.user_id)    entities.push(`USER:${event.user_id}`);
      if (event.session_id) entities.push(`SESSION:${event.session_id}`);

      let maxTotalScore   = 0;
      let finalSequence   = [];
      let finalDelta      = 0;
      let maxPatternScore = 0;

      // Batch state writes into a single pipeline
      const statePipeline = this.redis.pipeline();

      for (const entity of entities) {
        const windowKey   = `risk:window:${entity}:${slot}`;
        const sequenceKey = `risk:sequence:${entity}`;
        const stateKey    = `risk:state:${entity}`;

        const result = await this._runLua(
          [stateKey, windowKey, sequenceKey],
          [eventType, String(eventTimeMs), String(RISK_WINDOW_TTL), String(RISK_SEQ_TTL), String(RISK_STATE_TTL)]
        );

        const hincrbyCount  = Number(result[0]);
        const previousScore = Number(result[1]);
        const lastTime      = Number(result[2]);
        let   seq;
        try   { seq = JSON.parse(result[3]); }
        catch { seq = []; }

        // Time decay
        const timeDiffMinutes = Math.max(0, eventTimeMs - lastTime) / 60_000;
        const decayFactor     = Math.exp(-0.05 * timeDiffMinutes);
        const currentScore    = previousScore * decayFactor;

        // Incremental contribution
        const currentTotalCont  = getContribution(eventType, hincrbyCount);
        const prevTotalCont     = getContribution(eventType, hincrbyCount - 1);
        const increment         = currentTotalCont - prevTotalCont;
        const adjustedIncrement = increment + (event.event_type === 'ATTACK' ? 10 : 0);

        const patternScore  = detectPatternScore(seq);
        const severity      = (event.severity || 'LOW').toUpperCase();
        const severityScore = SEVERITY_WEIGHTS[severity] ?? 2;

        let entityTotal = currentScore + adjustedIncrement + patternScore + severityScore;
        entityTotal = Math.floor(Math.max(0, Math.min(100, entityTotal)));

        const delta = entityTotal - previousScore;

        logger.debug('RISK_ENTITY_SCORED', {
          entity,
          hincrby_count:  hincrbyCount,
          previous_score: previousScore,
          decay_factor:   Number(decayFactor.toFixed(4)),
          increment,
          pattern_score:  patternScore,
          severity_score: severityScore,
          entity_total:   entityTotal,
          delta,
          correlation_id: event.correlation_id ?? null,
          event_id:       event.event_id        ?? null,
        });

        // Queue state write
        statePipeline.set(
          stateKey,
          JSON.stringify({ score: entityTotal, timestamp: eventTimeMs }),
          'EX', RISK_STATE_TTL
        );

        if (entityTotal >= maxTotalScore) {
          maxTotalScore   = entityTotal;
          finalSequence   = seq;
          finalDelta      = delta;
          maxPatternScore = patternScore;
        }
      }

      // Flush all state writes atomically
      await statePipeline.exec();

      const score = maxTotalScore;

      // ── Thresholds ────────────────────────────────────────────────────────
      const thresholdHigh   = config.risk?.high   ?? 85;
      const thresholdMedium = config.risk?.medium  ?? 60;

      let riskLevel = 'LOW';
      if      (score >= thresholdHigh)   riskLevel = 'HIGH';
      else if (score >= thresholdMedium) riskLevel = 'MEDIUM';

      const formattedSequence = Array.isArray(finalSequence)
        ? [...finalSequence].reverse()
        : [];

      // ── Build enriched output ─────────────────────────────────────────────
      const enrichedEvent = {
        ...event,
        risk_score:           score ?? 0,
        risk_level:           riskLevel ?? 'LOW',
        sequence:             formattedSequence,
        risk_delta:           Math.floor(finalDelta),
        is_defense_triggered: false,
        defense_reason:       null,
        defense_action:       null,
      };

      // ── TASK 1: Push defense tasks to stream ─────────────────────────────
      // Replace SET NX flag approach with XADD to defense_events.
      // Two separate stream entries for base (HIGH) and escalation (CRITICAL).
      // defenseWorker uses dedup_key + SET NX to ensure at-most-once execution
      // per severity per slot per IP.
      const defenseNeeded   = score >= thresholdMedium || finalDelta > 20 || maxPatternScore >= 20;
      const defenseEscalate = score >= thresholdHigh   || maxPatternScore >= 30;

      if (defenseNeeded) {
        await this._pushDefenseTask(ip, slot, 'HIGH', score, finalDelta, maxPatternScore, event);
        enrichedEvent.is_defense_triggered = true;
        enrichedEvent.defense_reason       = `risk_score_${score}_delta_${Math.floor(finalDelta)}`;
        enrichedEvent.defense_action       = 'STRIKE';
      }
      if (defenseEscalate) {
        await this._pushDefenseTask(ip, slot, 'CRITICAL', score, finalDelta, maxPatternScore, event);
        enrichedEvent.is_defense_triggered = true;
        enrichedEvent.defense_reason       = `risk_score_${score}_delta_${Math.floor(finalDelta)}`;
        enrichedEvent.defense_action       = 'ESCALATE';
      }

      // ── Observability ─────────────────────────────────────────────────────
      logger.info('RISK_COMPUTED', {
        ip,
        score,
        risk_level:           riskLevel,
        event_type:           eventType,
        pattern_score:        maxPatternScore,
        sequence:             formattedSequence,
        delta:                Math.floor(finalDelta),
        is_defense_triggered: enrichedEvent.is_defense_triggered,
        defense_action:       enrichedEvent.defense_action,
        correlation_id:       event.correlation_id ?? null,
        event_id:             event.event_id        ?? null,
      });

      // ── Publish to analysis stream ────────────────────────────────────────
      await this.redis.xadd(
        'risk_scores',
        'MAXLEN', '~', 10_000,
        '*',
        'data', JSON.stringify({ ...enrichedEvent, timestamp: new Date().toISOString() })
      );

      return enrichedEvent;

    } catch (err) {
      logger.error('RISK_ENGINE_PROCESSING_ERROR', {
        error:          err.message,
        ip:             event?.source_ip,
        event_id:       event?.event_id,
        correlation_id: event?.correlation_id ?? null,
      });
      return null;
    }
  }
}
