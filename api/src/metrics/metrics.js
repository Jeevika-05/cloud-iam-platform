import client from 'prom-client';

const register = new client.Registry();

// Enable default metrics (e.g., CPU, memory, event loop lag, etc.)
client.collectDefaultMetrics({ register });

// Custom Counters
export const loginCounter = new client.Counter({
  name: 'iam_login_requests_total',
  help: 'Total number of login requests',
  labelNames: ['status'],
});
register.registerMetric(loginCounter);

export const mfaCounter = new client.Counter({
  name: 'iam_mfa_login_attempts_total',
  help: 'Total number of MFA login attempts',
  labelNames: ['status'],
});
register.registerMetric(mfaCounter);

export const rateLimitCounter = new client.Counter({
  name: 'iam_rate_limit_hits_total',
  help: 'Total number of rate limit hits',
  labelNames: ['type'],
});
register.registerMetric(rateLimitCounter);

export const requestCounter = new client.Counter({
  name: 'iam_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
});
register.registerMetric(requestCounter);

export const loginDuration = new client.Histogram({
  name: 'iam_login_duration_seconds',
  help: 'Duration of login requests in seconds',
  buckets: [0.1, 0.3, 0.5, 1, 2, 5],
});
register.registerMetric(loginDuration);

// ─────────────────────────────────────────────
// JWT SECURITY METRICS
// ─────────────────────────────────────────────
export const jwtVerificationFailures = new client.Counter({
  name: 'iam_jwt_verification_failures_total',
  help: 'Total JWT verification failures by reason',
  labelNames: ['reason'],
});
register.registerMetric(jwtVerificationFailures);

export { register };
