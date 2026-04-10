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
// RBAC OBSERVABILITY METRICS
// Fine-grained per-permission grant/deny tracking.
//
// Labels are bounded low-cardinality:
//   role:       3 values  (ADMIN | SECURITY_ANALYST | USER)
//   permission: ~22 values (full set from permissions.js)
//   route:      Express path patterns — no userId/IP bleed
//
// Max time series: 3 × 22 × ~12 routes = ~792 series (safe)
// ─────────────────────────────────────────────
export const rbacAllowedTotal = new client.Counter({
  name: 'iam_rbac_allowed_total',
  help: 'Total RBAC permission checks that were granted, by role, permission, and route',
  labelNames: ['role', 'permission', 'route'],
});
register.registerMetric(rbacAllowedTotal);

export const rbacDeniedTotal = new client.Counter({
  name: 'iam_rbac_denied_total',
  help: 'Total RBAC permission checks that were denied, by role, permission, and route',
  labelNames: ['role', 'permission', 'route'],
});
register.registerMetric(rbacDeniedTotal);

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

export const httpResponseDuration = new client.Histogram({
  name: 'iam_http_response_duration_seconds',
  help: 'HTTP response duration in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
});
register.registerMetric(httpResponseDuration);

export const httpErrorRate = new client.Counter({
  name: 'iam_http_errors_total',
  help: 'Total HTTP error responses (4xx and 5xx)',
  labelNames: ['method', 'route', 'status', 'error_class'],
});
register.registerMetric(httpErrorRate);

// ─────────────────────────────────────────────
// ACTIVE DEFENSE — STRIKE METRICS
// ─────────────────────────────────────────────
export const strikesRecordedTotal = new client.Counter({
  name: 'iam_strikes_recorded_total',
  help: 'Total strike events recorded by active defense',
  labelNames: ['ip_type'],
});
register.registerMetric(strikesRecordedTotal);

export const bansTriggeredTotal = new client.Counter({
  name: 'iam_bans_triggered_total',
  help: 'Total ban events triggered by active defense',
  labelNames: ['ip_type', 'ban_tier'],
});
register.registerMetric(bansTriggeredTotal);

export const blockedRequestsTotal = new client.Counter({
  name: 'iam_blocked_requests_total',
  help: 'Total requests blocked by active defense (banned IP)',
  labelNames: ['ip_type'],
});
register.registerMetric(blockedRequestsTotal);

export const activeBansGauge = new client.Gauge({
  name: 'iam_active_bans_current',
  help: 'Current number of active IP bans in Redis',
});
register.registerMetric(activeBansGauge);

// ─────────────────────────────────────────────
// RISK ENGINE METRICS
// ─────────────────────────────────────────────
export const riskScoreHistogram = new client.Histogram({
  name: 'iam_risk_score_distribution',
  help: 'Distribution of risk scores from the risk engine',
  buckets: [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
  labelNames: ['risk_level'],
});
register.registerMetric(riskScoreHistogram);

export const riskEngineProcessingTime = new client.Histogram({
  name: 'iam_risk_engine_processing_seconds',
  help: 'Time taken by risk engine to evaluate an event',
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
});
register.registerMetric(riskEngineProcessingTime);

export const highRiskEventsTotal = new client.Counter({
  name: 'iam_high_risk_events_total',
  help: 'Total events classified as high risk (score >= 70)',
  labelNames: ['event_type', 'action'],
});
register.registerMetric(highRiskEventsTotal);

// ─────────────────────────────────────────────
// EVENT STREAM / WORKER METRICS
// ─────────────────────────────────────────────
export const eventWorkerProcessed = new client.Counter({
  name: 'iam_event_worker_processed_total',
  help: 'Total events processed by the stream worker',
  labelNames: ['event_type', 'result'],
});
register.registerMetric(eventWorkerProcessed);

export const eventWorkerErrors = new client.Counter({
  name: 'iam_event_worker_errors_total',
  help: 'Total errors encountered by the stream worker',
  labelNames: ['stage'],
});
register.registerMetric(eventWorkerErrors);

export const eventProcessingDuration = new client.Histogram({
  name: 'iam_event_processing_duration_seconds',
  help: 'Time taken to process a single security event',
  buckets: [0.005, 0.01, 0.05, 0.1, 0.5, 1, 2],
  labelNames: ['event_type'],
});
register.registerMetric(eventProcessingDuration);

// ─────────────────────────────────────────────
// NEO4J INGESTION METRICS
// ─────────────────────────────────────────────
export const neo4jIngestionTotal = new client.Counter({
  name: 'iam_neo4j_ingestion_total',
  help: 'Total events ingested into Neo4j',
  labelNames: ['event_type', 'result'],
});
register.registerMetric(neo4jIngestionTotal);

export const neo4jIngestionDuration = new client.Histogram({
  name: 'iam_neo4j_ingestion_duration_seconds',
  help: 'Time taken for Neo4j ingestion batch',
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5],
});
register.registerMetric(neo4jIngestionDuration);

// ─────────────────────────────────────────────
// REDIS STREAM METRICS
// ─────────────────────────────────────────────
export const redisStreamLength = new client.Gauge({
  name: 'redis_stream_length',
  help: 'Current length of a Redis stream',
  labelNames: ['stream']
});
register.registerMetric(redisStreamLength);

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

// ─────────────────────────────────────────────
// AUDIT SERVICE & EVENT INGESTION METRICS
// ─────────────────────────────────────────────
export const securityEventSeverityCounter = new client.Counter({
  name: 'iam_security_event_severity_total',
  help: 'Total number of security events logged, categorized by severity',
  labelNames: ['severity'],
});
register.registerMetric(securityEventSeverityCounter);

export const securityEventsIngestedTotal = new client.Counter({
  name: 'iam_security_events_ingested_total',
  help: 'Total number of security events ingested',
  labelNames: ['event_type', 'action', 'source'],
});
register.registerMetric(securityEventsIngestedTotal);


export const riskScoreDistribution = riskScoreHistogram;

export const riskScoreComputedTotal = new client.Counter({
  name: 'iam_risk_score_computed_total',
  help: 'Total risk scores computed',
  labelNames: ['action', 'event_type', 'severity', 'status'],
});
register.registerMetric(riskScoreComputedTotal);

export const escalateActionsTotal = new client.Counter({
  name: 'iam_escalate_actions_total',
  help: 'Total escalation actions triggered',
});
register.registerMetric(escalateActionsTotal);

export const defenseEventsTriggeredTotal = new client.Counter({
  name: 'iam_defense_events_triggered_total',
  help: 'Total defense events triggered',
  labelNames: ['action', 'event_type', 'severity', 'status'],
});
register.registerMetric(defenseEventsTriggeredTotal);

export const streamConsumerLag = new client.Gauge({
  name: 'iam_stream_consumer_lag',
  help: 'Stream consumer lag per group',
  labelNames: ['stream', 'group'],
});
register.registerMetric(streamConsumerLag);

export const securityEventsProcessedTotal = new client.Counter({
  name: 'iam_security_events_processed_total',
  help: 'Total security events processed by workers',
  labelNames: ['action', 'event_type', 'severity', 'status'],
});
register.registerMetric(securityEventsProcessedTotal);

export const eventsProcessingLatencyMs = new client.Histogram({
  name: 'iam_events_processing_latency_ms',
  help: 'Latency of event processing in ms',
  labelNames: ['worker'],
  buckets: [5, 10, 50, 100, 500, 1000, 5000],
});
register.registerMetric(eventsProcessingLatencyMs);

export const neo4jWriteTotal = new client.Counter({
  name: 'iam_neo4j_write_total',
  help: 'Total neo4j write operations',
  labelNames: ['action', 'event_type', 'severity', 'status'],
});
register.registerMetric(neo4jWriteTotal);

export const neo4jWriteLatencyMs = new client.Histogram({
  name: 'iam_neo4j_write_latency_ms',
  help: 'Latency of neo4j writes in ms',
  buckets: [5, 10, 50, 100, 500, 1000, 5000],
});
register.registerMetric(neo4jWriteLatencyMs);

export const neo4jFailedEventsQueueSize = new client.Counter({
  name: 'iam_neo4j_failed_events_queue_size',
  help: 'Number of failed neo4j events pushed to repair queue',
});
register.registerMetric(neo4jFailedEventsQueueSize);

export const eventsInflightGauge = new client.Gauge({
  name: 'iam_events_inflight_gauge',
  help: 'Number of events currently inflight being processed',
  labelNames: ['worker'],
});
register.registerMetric(eventsInflightGauge);

export const processingBacklogSize = new client.Gauge({
  name: 'iam_processing_backlog_size',
  help: 'Size of processing backlog per stream',
  labelNames: ['stream'],
});
register.registerMetric(processingBacklogSize);

export const workerLastProcessedTimestamp = new client.Gauge({
  name: 'iam_worker_last_processed_timestamp',
  help: 'Timestamp of last processed event per worker',
  labelNames: ['worker'],
});
register.registerMetric(workerLastProcessedTimestamp);

export const workerAliveGauge = new client.Gauge({
  name: 'iam_worker_alive_gauge',
  help: 'Indicates if worker is alive',
  labelNames: ['worker'],
});
register.registerMetric(workerAliveGauge);

export const redisConnectionStatus = new client.Gauge({
  name: 'iam_redis_connection_status',
  help: 'Redis connection status (1 for connected)',
});
register.registerMetric(redisConnectionStatus);

export const neo4jConnectionStatus = new client.Gauge({
  name: 'iam_neo4j_connection_status',
  help: 'Neo4j connection status (1 for connected)',
});
register.registerMetric(neo4jConnectionStatus);

export { register };
