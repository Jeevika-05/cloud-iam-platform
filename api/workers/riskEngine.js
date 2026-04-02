import logger from '../src/shared/utils/logger.js';
import config from '../src/shared/config/index.js';
import { recordStrike } from '../src/shared/middleware/activeDefender.js';

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
   * Process a security event to dynamically calculate and record IP risk.
   * Runs non-blocking to avoid stalling the worker stream.
   * 
   * @param {Object} event Event payload containing source_ip, action/event_type, severity, timestamp
   */
  async processEvent(event) {
    try {
      if (!event || !event.source_ip) return null;
      
      const ip = event.source_ip;
      if (ip === 'unknown') return null;
      
      // Calculate 5-minute sliding window slot based on event timestamp (or current time)
      let eventTimeMs = Date.now();
      if (event.timestamp) {
        const parsed = new Date(event.timestamp).getTime();
        if (!isNaN(parsed)) {
          eventTimeMs = parsed;
        }
      }
      const slot = Math.floor(eventTimeMs / 300000);
      const windowKey = `risk:window:${ip}:${slot}`;

      let eventType = event.action || event.event_type || 'UNKNOWN';
      
      // Differentiate MFA failures from normal LOGIN failures since both share the same action
      if (eventType === 'LOGIN_FAILED' && (event.status === 'MFA_FAILED' || event.result === 'MFA_FAILED')) {
        eventType = 'MFA_FAILED';
      }

      const lastEventKey = `risk:last_event:${ip}`;

      // 1. Group events using Redis Hash (HINCRBY)
      // Maintains footprint of activities within the 5-minute window
      const pipeline = this.redis.multi();
      pipeline.get(lastEventKey);
      pipeline.hincrby(windowKey, eventType, 1);
      pipeline.expire(windowKey, 600); 
      pipeline.set(lastEventKey, eventType, 'EX', 600);
      const executeResults = await pipeline.exec();
      
      const previousEventType = executeResults[0][1];

      // 2. Fetch footprint via controlled HMGET read
      const eventKeys = Array.from(new Set([...Object.keys(BASE_EVENT_WEIGHTS), eventType]));
      const hmgetValues = await this.redis.hmget(windowKey, ...eventKeys);
      
      const windowEvents = {};
      eventKeys.forEach((key, i) => {
        const val = hmgetValues[i];
        if (val!=null && val!=undefined) {
          const parsedVal = parseInt(val, 10);
          if (!isNaN(parsedVal)) {
            windowEvents[key] = parsedVal;
          }
        }
      });
      let score = 0;

      // Current event severity directly adds to the risk baseline
      const severity = event.severity ? event.severity.toUpperCase() : 'LOW';
      score += (SEVERITY_WEIGHTS[severity] || 2);

      // Loop over aggregate window memory
      for (const [type, countStr] of Object.entries(windowEvents)) {
        const count = parseInt(countStr, 10);
        const evtWeight = BASE_EVENT_WEIGHTS[type] || 2;
        
        let typeScore = evtWeight;
        
        // Frequency Boost: Multiplies risk if identical attacks happen multiple times
        if (count >= 3 && evtWeight > 0) {
          typeScore *= Math.min((count - 1), 5); // Caps frequency multiplier at 5x
        }

        // Handle positive events gracefully (don't over-reward)
        if (type === 'LOGIN_SUCCESS') {
          typeScore = Math.max(-20, evtWeight * count); // Caps the score reduction out
        }
        
        score += typeScore;
      }

      // 3. True Sequence-Based Scoring
      // Look for specific chained attack patterns from the immediately preceding event
      if (previousEventType === 'JWT_TAMPER' && eventType === 'MFA_FAILED') {
        score += 25; // Big boost for chaining
      }
      if (previousEventType === 'LOGIN_FAILED' && eventType === 'MFA_FAILED') {
        score += 10;
      }

      // 4. Bounded Scoring Limits
      score = Math.floor(score);
      score = Math.max(0, Math.min(100, score));

      // 5. Apply Config Thresholds
      const thresholdHigh = config.risk?.high || 85;
      const thresholdMedium = config.risk?.medium || 60;

      let riskLevel = 'LOW';
      if (score >= thresholdHigh) {
        riskLevel = 'HIGH';
      } else if (score >= thresholdMedium) {
        riskLevel = 'MEDIUM';
      }

      const riskOutput = {
        entity: `IP:${ip}`,
        risk_score: score,
        risk_level: riskLevel,
        contributing_events: Object.keys(windowEvents)
      };

      // 6. Output to Analysis Stream
      await this.redis.xadd(
        'risk_scores',
        'MAXLEN', '~', 10000,
        '*',
        'data', JSON.stringify({ ...riskOutput, timestamp: new Date().toISOString() })
      );

      // 7. Active Defense Integration
      if (riskLevel === 'HIGH') {
        const strikeTriggerKey = `risk:triggered:${ip}:${slot}`;
        // Ensure we only trigger one strike per window per IP
        const triggered = await this.redis.set(strikeTriggerKey, '1', 'EX', 600, 'NX');
        if (triggered === 'OK') {
          await recordStrike(ip, 'HIGH', `risk_engine_score_high_${score}`);
        }
      }

      return riskOutput;

    } catch (err) {
      logger.error('RISK_ENGINE_PROCESSING_ERROR', { error: err.message, ip: event?.source_ip });
      return null;
    }
  }
}
