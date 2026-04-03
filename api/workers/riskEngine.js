import logger from '../src/shared/utils/logger.js';
import config from '../src/shared/config/index.js';
import { recordStrike } from '../src/shared/middleware/activeDefender.js';

// ─────────────────────────────────────────────────────────────
// CONCURRENCY WARNING: SINGLE-WORKER CONSTRAINT
// ─────────────────────────────────────────────────────────────
// The RiskEngine uses Redis MULTI to batch reads (HINCRBY, LPUSH, GET).
// However, MULTI is NOT fully isolated — it batches commands but does
// not prevent read-modify-write race conditions when multiple workers
// process events for the same IP concurrently.
// 
// ⚠️ DO NOT RUN MULTIPLE WORKER INSTANCES in production without
// migrating this logic to an atomic Lua script.
// ─────────────────────────────────────────────────────────────

const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 2
};

const BASE_EVENT_WEIGHTS = {
  // Simulated Attacks from Rust
  JWT_TAMPER: 20,
  PASSWORD_BRUTE: 15,
  MFA_BRUTE_FORCE_SINGLE_IP: 15,
  MFA_BRUTE_FORCE_DISTRIBUTED: 25,
  SESSION_REUSE: 20,
  IDOR: 20,
  CSRF: 15,
  MASS_ASSIGNMENT: 15,
  ACCESS_TOKEN_ABUSE: 20,
  
  // API Internal Events
  LOGIN_FAILED: 5,
  MFA_FAILED: 10,
  TOKEN_REUSE_DETECTED: 20,
  SUSPICIOUS_SESSION_DETECTED: 20,
  LOGIN_SUCCESS: -10,
};

export class RiskEngine {
  constructor(redisClient) {
    this.redis = redisClient;
  }

  /**
   * Process a security event to dynamically calculate and record risk factors.
   * Runs non-blocking to avoid stalling the worker stream.
   * 
   * @param {Object} event Event payload containing source_ip, action/event_type, severity, timestamp
   */
  async processEvent(event) {
    try {
      if (!event || !event.source_ip) return null;
      
      const ip = event.source_ip;
      if (ip === 'unknown') return null;

      // 🛡️ Prevent DEFENSE event amplification loop:
      // DEFENSE events processed by the risk engine could trigger recordStrike(),
      // which emits another DEFENSE event, creating an infinite loop.
      // Skip risk computation for DEFENSE events entirely.
      if (event.event_type === 'DEFENSE') return null;
      
      // Calculate 5-minute sliding window slot based on event timestamp (or current time)
      let eventTimeMs = Date.now();
      if (event.timestamp) {
        const parsed = new Date(event.timestamp).getTime();
        if (!isNaN(parsed)) {
          eventTimeMs = parsed;
        }
      }
      const slot = Math.floor(eventTimeMs / 300000);

      let eventType = event.action || event.event_type || 'UNKNOWN';
      
      // Differentiate MFA failures from normal LOGIN failures since both share the same action
      if (eventType === 'LOGIN_FAILED' && (event.status === 'MFA_FAILED' || event.result === 'MFA_FAILED')) {
        eventType = 'MFA_FAILED';
      }

      // 4. Multi-Entity Risk
      const entities = [`IP:${ip}`];
      if (event.user_id) entities.push(`USER:${event.user_id}`);
      if (event.session_id) entities.push(`SESSION:${event.session_id}`);

      // 1. Group events using Redis Pipeline
      const pipeline = this.redis.multi();
      for (const entity of entities) {
        const windowKey = `risk:window:${entity}:${slot}`;
        const sequenceKey = `risk:sequence:${entity}`;
        const stateKey = `risk:state:${entity}`;
        
        // Window count
        pipeline.hincrby(windowKey, eventType, 1);
        pipeline.expire(windowKey, 600);
        
        // Sequence detection
        pipeline.lpush(sequenceKey, eventType);
        pipeline.ltrim(sequenceKey, 0, 4);
        pipeline.expire(sequenceKey, 3600);
        pipeline.lrange(sequenceKey, 0, 4);
        
        // State
        pipeline.get(stateKey);
      }
      
      const executeResults = await pipeline.exec();

      let maxTotalScore = 0;
      let finalSequence = [];
      let finalDelta = 0;
      let maxPatternScore = 0;

      let offset = 0;
      for (const entity of entities) {
        const hincrbyCount = executeResults[offset][1]; 
        const sequenceResult = executeResults[offset + 5][1] || [];
        const stateResultStr = executeResults[offset + 6][1];
        
        let previousScore = 0;
        let lastTime = eventTimeMs;
        if (stateResultStr) {
          try {
            const parsed = JSON.parse(stateResultStr);
            previousScore = parsed.score || 0;
            // Ensure we don't accidentally compute decay using future timestamps
            lastTime = Math.min(eventTimeMs, parsed.timestamp || eventTimeMs);
          } catch(e) {}
        }

        // 2. Add Time Decay
        const timeDiffMinutes = Math.max(0, eventTimeMs - lastTime) / 60000;
        const decayFactor = Math.exp(-0.05 * timeDiffMinutes); 
        const currentScore = previousScore * decayFactor;

        // 7. Prevent Double Counting (Incremental contribution with Cap)
        const getContribution = (type, count) => {
            const w = BASE_EVENT_WEIGHTS[type] || 2;
            if (type === 'LOGIN_SUCCESS') return Math.max(-20, w * count);
            if (count <= 0) return 0;
            
            // Monotonic growth: w*1, w*2, w*3 ... capped at w*5
            // Previous code had a dead zone at count=3 where increment was 0.
            const total = w * Math.min(count, 5);
            return Math.min(total, 50); // Cap at 50 max per type per rule 7
        };

        const currentTotalCont = getContribution(eventType, hincrbyCount);
        const prevTotalCont = getContribution(eventType, hincrbyCount - 1);
        const increment = currentTotalCont - prevTotalCont;

        // 3. Advanced Sequence Detection
        let patternScore = 0;
        const seq = sequenceResult; 
        if (seq.length >= 2) {
           if (seq[0] === 'MFA_FAILED' && seq[1] === 'LOGIN_FAILED') patternScore += 15;
           if (seq[0] === 'ACCESS_TOKEN_ABUSE' && seq[1] === 'JWT_TAMPER') patternScore += 25;
        }
        if (seq.length >= 3) {
           // Fixed: TOKEN_REUSE → TOKEN_REUSE_DETECTED (matches BASE_EVENT_WEIGHTS key)
           if (seq[0] === 'TOKEN_REUSE_DETECTED' && seq[1] === 'MFA_FAILED' && seq[2] === 'LOGIN_FAILED') patternScore += 30;
        }
        
        const severity = event.severity ? event.severity.toUpperCase() : 'LOW';
        const severityScore = (SEVERITY_WEIGHTS[severity] || 2);

        let adjustedIncrement = increment;
        if (event.event_type === 'ATTACK') {
          adjustedIncrement += 10;
        }

        let entityTotal = currentScore + adjustedIncrement + patternScore + severityScore;
        // Bounded Scoring Limits
        entityTotal = Math.floor(Math.max(0, Math.min(100, entityTotal)));
        
        if (patternScore > maxPatternScore) {
          maxPatternScore = patternScore;
        }
        
        const delta = entityTotal - previousScore;

        // Save state persistently
        await this.redis.set(`risk:state:${entity}`, JSON.stringify({
            score: entityTotal,
            timestamp: eventTimeMs
        }), 'EX', 86400); // 1-day expiry to prevent leak

        if (entityTotal >= maxTotalScore) {
           maxTotalScore = entityTotal;
           finalSequence = seq;
           finalDelta = delta;
        }
        offset += 7;
      }

      const score = maxTotalScore;

      // 5. Apply Config Thresholds
      // Use ?? (nullish coalescing) — || would swallow numeric 0 as falsy
      const thresholdHigh = config.risk?.high ?? 85;
      const thresholdMedium = config.risk?.medium ?? 60;

      let riskLevel = 'LOW';
      if (score >= thresholdHigh) {
        riskLevel = 'HIGH';
      } else if (score >= thresholdMedium) {
        riskLevel = 'MEDIUM';
      }

      let formattedSequence = [];

      if (Array.isArray(finalSequence)) {
        formattedSequence = finalSequence.slice().reverse();
      } else {
        logger.warn("Invalid finalSequence type", { finalSequence });
      } 

      const enrichedEvent = {
        ...event,
        risk_score: score ?? 0,
        risk_level: riskLevel ?? 'LOW',
        sequence: formattedSequence,
        risk_delta: Math.floor(finalDelta),
        is_defense_triggered: false
      };

      // Active Defense Trigger — pass correlation_id for attack→defense correlation
      if (score >= 60 || finalDelta > 20 || maxPatternScore >= 20) {
        const strikeTriggerKey = `risk:triggered:${ip}:${slot}`;
        const triggered = await this.redis.set(strikeTriggerKey, '1', 'EX', 600, 'NX');
        if (triggered === 'OK') {
          await recordStrike(ip, 'HIGH', `risk_engine_score_${score}_delta_${Math.floor(finalDelta)}`, enrichedEvent.correlation_id || enrichedEvent.event_id);
          enrichedEvent.is_defense_triggered = true;
          enrichedEvent.defense_reason = "risk_engine_trigger";
          enrichedEvent.defense_action = "STRIKE";
        }
      }

      // 6. Observability Improvements
      logger.info('RISK_COMPUTED', {
        ip,
        score: enrichedEvent.risk_score,
        riskLevel: enrichedEvent.risk_level,
        eventType,
        sequence: enrichedEvent.sequence,
        delta: Math.floor(finalDelta),
        is_defense_triggered: enrichedEvent.is_defense_triggered
      });

      // Output to Analysis Stream
      await this.redis.xadd(
        'risk_scores',
        'MAXLEN', '~', 10000,
        '*',
        'data', JSON.stringify({ ...enrichedEvent, timestamp: new Date().toISOString() })
      );

      return enrichedEvent;

    } catch (err) {
      logger.error('RISK_ENGINE_PROCESSING_ERROR', { error: err.message, ip: event?.source_ip });
      return null;
    }
  }
}
