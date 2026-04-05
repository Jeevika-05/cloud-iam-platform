import client from 'prom-client';

const register = new client.Registry();

// Enable default metrics (e.g., CPU, memory, event loop lag, etc.)
client.collectDefaultMetrics({ register });

// ─────────────────────────────────────────────
// LOGIN & AUTH METRICS
// ─────────────────────────────────────────────
export const loginCounter = new client.Counter({
  name: 'iam_login_requests_total',
  help: 'Total number of login requests',
  labelNames: ['status'],
});
register.registerMetric(loginCounter);

export const loginDuration = new client.Histogram({
  name: 'iam_login_duration_seconds',
  help: 'Duration of login requests in seconds',
  buckets: [0.1, 0.3, 0.5, 1, 2, 5],
});
register.registerMetric(loginDuration);

export const accountLockCounter = new client.Counter({
  name: 'iam_account_locks_total',
  help: 'Total account lockouts triggered by brute-force protection',
  labelNames: ['reason'],
});
register.registerMetric(accountLockCounter);

// ─────────────────────────────────────────────
// MFA METRICS
// ─────────────────────────────────────────────
export const mfaCounter = new client.Counter({
  name: 'iam_mfa_login_attempts_total',
  help: 'Total number of MFA login attempts',
  labelNames: ['status'],
});
register.registerMetric(mfaCounter);

// ─────────────────────────────────────────────
// JWT SECURITY METRICS
// ─────────────────────────────────────────────
export const jwtVerificationFailures = new client.Counter({
  name: 'iam_jwt_verification_failures_total',
  help: 'Total JWT verification failures by reason',
  labelNames: ['reason'],
});
register.registerMetric(jwtVerificationFailures);

// ─────────────────────────────────────────────
// RATE LIMITING METRICS
// ─────────────────────────────────────────────
export const rateLimitCounter = new client.Counter({
  name: 'iam_rate_limit_hits_total',
  help: 'Total number of rate limit hits',
  labelNames: ['type'],
});
register.registerMetric(rateLimitCounter);

// ─────────────────────────────────────────────
// SESSION SECURITY METRICS
// ─────────────────────────────────────────────
export const sessionSecurityCounter = new client.Counter({
  name: 'iam_session_security_events_total',
  help: 'Session security events: reuse detection, compromise, revocation',
  labelNames: ['event'],
});
register.registerMetric(sessionSecurityCounter);

// ─────────────────────────────────────────────
// AUTHORIZATION METRICS (RBAC / ABAC / IDOR)
// ─────────────────────────────────────────────
export const authorizationFailures = new client.Counter({
  name: 'iam_authorization_failures_total',
  help: 'Authorization denials by type (RBAC, ABAC policy, IDOR)',
  labelNames: ['type'],
});
register.registerMetric(authorizationFailures);

// ─────────────────────────────────────────────
// INPUT VALIDATION METRICS (mass assignment etc.)
// ─────────────────────────────────────────────
export const validationFailures = new client.Counter({
  name: 'iam_validation_failures_total',
  help: 'Input validation failures (schema violations, mass assignment blocks)',
  labelNames: ['endpoint'],
});
register.registerMetric(validationFailures);

// ─────────────────────────────────────────────
// AUTH MIDDLEWARE METRICS
// ─────────────────────────────────────────────
export const authFailureCounter = new client.Counter({
  name: 'iam_auth_failures_total',
  help: 'Authentication middleware failures by reason',
  labelNames: ['reason'],
});
register.registerMetric(authFailureCounter);

// ─────────────────────────────────────────────
// ACTIVE DEFENSE METRICS (IP Bans)
// ─────────────────────────────────────────────
export const ipBanCounter = new client.Counter({
  name: 'iam_ip_bans_total',
  help: 'Total number of IP bans issued by active defense',
  labelNames: ['reason', 'severity'],
});
register.registerMetric(ipBanCounter);

// ─────────────────────────────────────────────
// GLOBAL HTTP METRICS
// ─────────────────────────────────────────────
export const requestCounter = new client.Counter({
  name: 'iam_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
});
register.registerMetric(requestCounter);

// ─────────────────────────────────────────────
// SYSTEM METRICS
// ─────────────────────────────────────────────
export const streamConsumerLag = new client.Gauge({
  name: 'iam_stream_consumer_lag',
  help: 'Number of pending messages in the security events stream consumer group',
  labelNames: ['stream', 'group'],
});
register.registerMetric(streamConsumerLag);

export const securityEventSeverityCounter = new client.Counter({
  name: 'iam_security_event_severity_total',
  help: 'Total security events triggered by severity',
  labelNames: ['severity'],
});
register.registerMetric(securityEventSeverityCounter);

// ─────────────────────────────────────────────
// PROMETHEUS METRICS DESIGN: 1. EVENT PIPELINE
// ─────────────────────────────────────────────
export const securityEventsIngestedTotal = new client.Counter({
  name: 'security_events_ingested_total',
  help: 'Total number of security events ingested into the stream',
  labelNames: ['event_type', 'action', 'source']
});
register.registerMetric(securityEventsIngestedTotal);

export const securityEventsProcessedTotal = new client.Counter({
  name: 'security_events_processed_total',
  help: 'Total number of security events successfully processed by workers',
  labelNames: ['action', 'event_type', 'severity', 'status']
});
register.registerMetric(securityEventsProcessedTotal);

export const defenseEventsTriggeredTotal = new client.Counter({
  name: 'defense_events_triggered_total',
  help: 'Total defense tasks queued',
  labelNames: ['action', 'event_type', 'severity', 'status']
});
register.registerMetric(defenseEventsTriggeredTotal);

export const eventsProcessingLatencyMs = new client.Histogram({
  name: 'events_processing_latency_ms',
  help: 'Latency of event processing in milliseconds',
  labelNames: ['worker'],
  buckets: [10, 50, 100, 250, 500, 1000, 5000] // Updated bucketing
});
register.registerMetric(eventsProcessingLatencyMs);

// ── NEW: Pipeline Visibility ──
export const eventsInflightGauge = new client.Gauge({
  name: 'events_inflight_gauge',
  help: 'Number of events currently being processed',
  labelNames: ['worker']
});
register.registerMetric(eventsInflightGauge);

export const processingBacklogSize = new client.Gauge({
  name: 'processing_backlog_size',
  help: 'Queue depth of pending events to be processed',
  labelNames: ['stream']
});
register.registerMetric(processingBacklogSize);

// ─────────────────────────────────────────────
// PROMETHEUS METRICS DESIGN: 2. RISK ENGINE
// ─────────────────────────────────────────────
export const riskScoreComputedTotal = new client.Counter({
  name: 'risk_score_computed_total',
  help: 'Total risk scores computed',
  labelNames: ['action', 'event_type', 'severity', 'status']
});
register.registerMetric(riskScoreComputedTotal);

export const riskScoreDistribution = new client.Histogram({
  name: 'risk_score_distribution',
  help: 'Distribution of computed risk scores',
  buckets: [10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100]
});
register.registerMetric(riskScoreDistribution);

export const highRiskEventsTotal = new client.Counter({
  name: 'high_risk_events_total',
  help: 'Total high risk events identified',
  labelNames: ['risk_level', 'event_type', 'source']
});
register.registerMetric(highRiskEventsTotal);

export const escalateActionsTotal = new client.Counter({
  name: 'escalate_actions_total',
  help: 'Total escalation actions triggered'
});
register.registerMetric(escalateActionsTotal);

// ─────────────────────────────────────────────
// PROMETHEUS METRICS DESIGN: 3. DEFENSE SYSTEM
// ─────────────────────────────────────────────
export const strikesRecordedTotal = new client.Counter({
  name: 'strikes_recorded_total',
  help: 'Total strikes recorded against an IP',
  labelNames: ['severity']
});
register.registerMetric(strikesRecordedTotal);

export const bansTriggeredTotal = new client.Counter({
  name: 'bans_triggered_total',
  help: 'Total IP bans applied',
  labelNames: ['severity', 'duration']
});
register.registerMetric(bansTriggeredTotal);

export const blockedRequestsTotal = new client.Counter({
  name: 'blocked_requests_total',
  help: 'Total HTTP requests blocked by active defender',
  labelNames: ['reason']
});
register.registerMetric(blockedRequestsTotal);

export const activeBansGauge = new client.Gauge({
  name: 'active_bans_gauge',
  help: 'Current number of active IP bans'
});
register.registerMetric(activeBansGauge);

// ─────────────────────────────────────────────
// PROMETHEUS METRICS DESIGN: 4. NEO4J GRAPH
// ─────────────────────────────────────────────
// Replaced split success/failure bounds with unified counter + labels
export const neo4jWriteTotal = new client.Counter({
  name: 'neo4j_write_total',
  help: 'Total Neo4j graph writes (success/failure)',
  labelNames: ['action', 'event_type', 'severity', 'status']
});
register.registerMetric(neo4jWriteTotal);

export const neo4jWriteLatencyMs = new client.Histogram({
  name: 'neo4j_write_latency_ms',
  help: 'Latency of Neo4j write operations in milliseconds',
  buckets: [10, 50, 100, 200, 500, 1000, 3000]
});
register.registerMetric(neo4jWriteLatencyMs);

export const neo4jFailedEventsQueueSize = new client.Gauge({
  name: 'neo4j_failed_events_queue_size',
  help: 'Number of events in the neo4j repair queue'
});
register.registerMetric(neo4jFailedEventsQueueSize);

// ── NEW: Health & Reliability ──
export const workerLastProcessedTimestamp = new client.Gauge({
  name: 'worker_last_processed_timestamp',
  help: 'Epoch timestamp of the last processed event per worker',
  labelNames: ['worker']
});
register.registerMetric(workerLastProcessedTimestamp);

export const workerAliveGauge = new client.Gauge({
  name: 'worker_alive_gauge',
  help: 'Heartbeat gauge indicating the worker is running (1 = alive)',
  labelNames: ['worker']
});
register.registerMetric(workerAliveGauge);

export const redisConnectionStatus = new client.Gauge({
  name: 'redis_connection_status',
  help: 'Redis connection status (1 = connected, 0 = disconnected)'
});
register.registerMetric(redisConnectionStatus);

export const neo4jConnectionStatus = new client.Gauge({
  name: 'neo4j_connection_status',
  help: 'Neo4j connection status (1 = connected, 0 = disconnected)'
});
register.registerMetric(neo4jConnectionStatus);

// ─────────────────────────────────────────────
// PROMETHEUS METRICS DESIGN: 5. REDIS STREAMS
// ─────────────────────────────────────────────
export const redisStreamLag = new client.Gauge({
  name: 'redis_stream_lag',
  help: 'Number of pending messages (lag) per consumer group',
  labelNames: ['stream', 'group']
});
register.registerMetric(redisStreamLag);

export const dlqSize = new client.Gauge({
  name: 'dlq_size',
  help: 'Number of dead-letter queue messages',
  labelNames: ['stream']
});
register.registerMetric(dlqSize);

export const retryAttemptsTotal = new client.Counter({
  name: 'retry_attempts_total',
  help: 'Total stream message retry and reclaim operations',
  labelNames: ['stream']
});
register.registerMetric(retryAttemptsTotal);

// ─────────────────────────────────────────────
// PROMETHEUS METRICS DESIGN: 6. AUTH / ATTACKS
// ─────────────────────────────────────────────
export const loginFailuresTotal = new client.Counter({
  name: 'login_failures_total',
  help: 'Total failed logins',
  labelNames: ['status']
});
register.registerMetric(loginFailuresTotal);

export const mfaFailuresTotal = new client.Counter({
  name: 'mfa_failures_total',
  help: 'Total MFA code validation failures'
});
register.registerMetric(mfaFailuresTotal);

export const distributedMfaLockTotal = new client.Counter({
  name: 'distributed_mfa_lock_total',
  help: 'Total per-user MFA locks triggered by distributed brute force'
});
register.registerMetric(distributedMfaLockTotal);

export const jwtTamperDetectedTotal = new client.Counter({
  name: 'jwt_tamper_detected_total',
  help: 'Total JWT tampering attempts detected'
});
register.registerMetric(jwtTamperDetectedTotal);

export { register };

