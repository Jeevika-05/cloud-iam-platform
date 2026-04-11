/**
 * ─────────────────────────────────────────────────────────────
 * CENTRALIZED CONFIGURATION MODULE
 * ─────────────────────────────────────────────────────────────
 *
 * This is the SINGLE SOURCE OF TRUTH for all configuration.
 *
 * Secret loading relies on the SecretProvider singleton.
 * Provider selection (via SECRET_PROVIDER env var):
 *   - 'env'             → EnvProvider (default)
 *   - 'docker-secrets'  → DockerSecretsProvider
 *   - 'vault'           → VaultProvider
 *
 * ⚠️  ALL other modules MUST import from this file.
 *     No other file should read process.env for secrets.
 *     Top-level await is used to guarantee secrets are 
 *     loaded before the application starts.
 * ─────────────────────────────────────────────────────────────
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { getSecretProvider } from '../providers/SecretProvider.js';

if (process.env.SECRET_PROVIDER !== 'docker-secrets') {
  const dotenv = await import('dotenv');
  dotenv.config();
}

// 1. PROVIDER INITIALIZATION
const secretProvider = getSecretProvider();

console.log(`[CONFIG] Bootstrapping configuration...`);
console.log(`[CONFIG] Active Secret Provider: ${secretProvider.getName()}`);
console.log(`[CONFIG] Environment: ${process.env.SECRET_PROVIDER === 'docker-secrets' ? 'Docker' : 'Local'}`);

// 2. REQUIRED SECRETS VALIDATION
const requiredSecrets = [
  'DATABASE_URL'
  // Note: JWT keys and Encryption keys are validated during their specific load phases 
  // because they support complex rotation (KIDs, versions) rather than a single explicit key.
];

for (const secret of requiredSecrets) {
  const value = await secretProvider.getSecret(secret);
  if (!value) {
    throw new Error(`[STARTUP ERROR] Missing critical secret: ${secret} (Provider: ${secretProvider.getName()})`);
  }
}

// ─────────────────────────────────────────────────────────────
// HELPER: Load secret from provider
// ─────────────────────────────────────────────────────────────

/**
 * Loads a secret asynchronously from the active SecretProvider.
 *
 * @param {string}  envKey       - Primary env var name (e.g., 'JWT_PRIVATE_KEY')
 * @param {object}  opts
 * @param {string}  [opts.defaultValue] - Fallback for non-secret config
 * @param {boolean} [opts.required]     - Throw if value is missing
 * @param {string}  [opts.description]  - Human-readable description for error messages
 */
async function loadSecret(envKey, opts = {}) {
  const { defaultValue, required = false, description } = opts;

  let secretValue = await secretProvider.getSecret(envKey);

  if (secretValue !== undefined && secretValue !== null && secretValue !== '') {
    if (!process.env[envKey]) process.env[envKey] = secretValue;
    return secretValue;
  }

  // Priority 2: Default value (non-secrets only)
  if (defaultValue !== undefined) {
    return defaultValue;
  }

  // Required but missing
  if (required) {
    throw new Error(
      `[CONFIG ERROR] Missing required configuration: ${envKey}${description ? ` (${description})` : ''}. ` +
      `Provider used: ${secretProvider.getName()}`
    );
  }

  return undefined;
}

/**
 * Loads an RSA key from the provider.
 * Handles newline normalization for keys stored in env vars.
 */
async function loadRsaKey(envKey, description) {
  let key = await loadSecret(envKey, { required: true, description });

  // If the key is stored in an env var, newlines may be escaped as \n
  if (key && !key.includes('\n') && key.includes('\\n')) {
    key = key.replace(/\\n/g, '\n');
  }

  return key;
}

// ═══════════════════════════════════════════════════════════════
//  CONFIGURATION OBJECTS
// ═══════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────
// APP CONFIG
// ─────────────────────────────────────────────────────────────
export const app = Object.freeze({
  nodeEnv:    process.env.NODE_ENV || 'development',
  port:       parseInt(process.env.PORT, 10) || 3000,
  workerMetricsPort: parseInt(process.env.WORKER_METRICS_PORT, 10) || 9091,
  defenseWorkerMetricsPort: parseInt(process.env.DEFENSE_WORKER_METRICS_PORT, 10) || 9092,
  logLevel:   process.env.LOG_LEVEL || 'info',
  corsOrigin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',')
    : ['http://localhost:3000'],
  isProduction: (process.env.NODE_ENV || 'development') === 'production',
  isDevelopment: (process.env.NODE_ENV || 'development') === 'development',
});

// ─────────────────────────────────────────────────────────────
// DATABASE CONFIG
// ─────────────────────────────────────────────────────────────
export const database = Object.freeze({
  url: await loadSecret('DATABASE_URL', {
    required: true,
    description: 'PostgreSQL connection string',
  }),
});

// ─────────────────────────────────────────────────────────────
// REDIS CONFIG
// ─────────────────────────────────────────────────────────────
export const redis = Object.freeze({
  url: await loadSecret('REDIS_URL', {
    defaultValue: 'redis://localhost:6379',
  }),
});

// ─────────────────────────────────────────────────────────────
// JWT CONFIG (RS256 — Multi-Key / KID Rotation)
// ─────────────────────────────────────────────────────────────

/**
 * Discovers and loads all KID-based key pairs from the provider environment.
 */
async function loadJwtKeys() {
  const keys = {};

  // ── Auto-discover KID-based key pairs from env ──────────────
  // Note: JWT keys need to be strictly formatted via the provider.
  const kidPattern = /^JWT_KEY_(.+)_PRIVATE$/;
  for (const envKey of Object.keys(process.env)) {
    const match = envKey.match(kidPattern);
    if (!match) continue;

    const kid = match[1].toLowerCase();
    const publicEnvKey = `JWT_KEY_${match[1]}_PUBLIC`;

    if (!(await secretProvider.getSecret(publicEnvKey))) {
      throw new Error(
        `Found private key for KID "${kid}" but missing corresponding public key.`
      );
    }

    try {
      const privateKey = await loadRsaKey(
        `JWT_KEY_${match[1]}_PRIVATE`,
        `RSA private key for KID "${kid}"`
      );
      const publicKey = await loadRsaKey(
        `JWT_KEY_${match[1]}_PUBLIC`,
        `RSA public key for KID "${kid}"`
      );

      keys[kid] = Object.freeze({ privateKey, publicKey });
    } catch (err) {
      throw new Error(`Failed to load key pair for KID "${kid}": ${err.message}`);
    }
  }

  // ── Fallback: legacy single-key as KID "default" ────────────
  if (Object.keys(keys).length === 0) {
    try {
      const privateKey = await loadRsaKey(
        'JWT_PRIVATE_KEY',
        'RSA private key for JWT signing (PEM format)'
      );
      const publicKey = await loadRsaKey(
        'JWT_PUBLIC_KEY',
        'RSA public key for JWT verification (PEM format)'
      );
      keys['default'] = Object.freeze({ privateKey, publicKey });
      console.log(`[CONFIG] No KID-based keys found — using legacy key pair as KID "default" via ${secretProvider.getName()} provider`);
    } catch {
      throw new Error(
        'No JWT keys configured. Set JWT_KEY_{KID}_PRIVATE / JWT_KEY_{KID}_PUBLIC, ' +
        'or fallback JWT_PRIVATE_KEY / JWT_PUBLIC_KEY.'
      );
    }
  }

  return keys;
}

const jwtKeys = await loadJwtKeys();
const jwtActiveKid = (process.env.JWT_ACTIVE_KID || 'default').toLowerCase();

// Validate activeKid references a loaded key pair
if (!jwtKeys[jwtActiveKid]) {
  const available = Object.keys(jwtKeys).join(', ');
  throw new Error(
    `JWT_ACTIVE_KID="${jwtActiveKid}" does not match any loaded key pair. ` +
    `Available KIDs: [${available}]`
  );
}

console.log(`[CONFIG] JWT keys loaded via ${secretProvider.getName()} provider: [${Object.keys(jwtKeys).join(', ')}]  active: "${jwtActiveKid}"`);

export const jwt = Object.freeze({
  algorithm: 'RS256',
  algorithms: ['RS256'],

  // ── Multi-key support ──────────────────────────────────────
  activeKid:  jwtActiveKid,
  keys:       Object.freeze(jwtKeys),

  // Convenience: active key pair (for signing)
  privateKey: jwtKeys[jwtActiveKid].privateKey,
  publicKey:  jwtKeys[jwtActiveKid].publicKey,

  /**
   * Look up a public key by KID for verification.
   * @param {string} kid - Key ID from JWT header
   * @returns {string} PEM-encoded public key
   * @throws {Error} if KID is unknown
   */
  getPublicKey(kid) {
    const normalized = (kid || '').toLowerCase();
    const entry = jwtKeys[normalized];
    if (!entry) {
      throw new Error(`Unknown JWT KID: "${kid}"`);
    }
    return entry.publicKey;
  },

  accessExpiresIn:  process.env.JWT_EXPIRES_IN || '15m',
  refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  tempExpiresIn:    process.env.JWT_TEMP_EXPIRES_IN || '5m',

  issuer:   'cloud-iam-platform',
  audience: 'cloud-iam-users',
});

// ─────────────────────────────────────────────────────────────
// ENCRYPTION CONFIG (AES-256-GCM)
// ─────────────────────────────────────────────────────────────
const activeKeyVersion = parseInt(process.env.ACTIVE_KEY_VERSION, 10);
if (!activeKeyVersion) {
  throw new Error('ACTIVE_KEY_VERSION is missing or invalid');
}

/**
 * Loads and validates a versioned AES-256 encryption key.
 */
async function loadEncryptionKey(version) {
  const envKey = `ENCRYPTION_KEY_V${version}`;

  const key = await loadSecret(envKey, {
    required: true,
    description: `AES-256 encryption key version ${version}`,
  });

  if (key.length !== 64 || !/^[0-9a-fA-F]+$/.test(key)) {
    throw new Error(
      `Invalid ${envKey}: must be exactly 64 hex characters (256-bit key)`
    );
  }

  return key;
}

// Pre-load all available key versions
const encryptionKeys = {};
for (let v = 1; v <= 10; v++) {
  const envKey = `ENCRYPTION_KEY_V${v}`;
  const hasKey = await secretProvider.getSecret(envKey);
  if (hasKey) {
    encryptionKeys[v] = await loadEncryptionKey(v);
  }
}

// Ensure the active version is loaded
if (!encryptionKeys[activeKeyVersion]) {
  throw new Error(`Active encryption key V${activeKeyVersion} is not configured`);
}

export const encryption = Object.freeze({
  algorithm: 'aes-256-gcm',
  ivLength: 16,
  activeKeyVersion,
  keys: Object.freeze(encryptionKeys),
  getKey(version) {
    const key = encryptionKeys[version];
    if (!key) throw new Error(`Encryption key V${version} is not configured`);
    return Buffer.from(key, 'hex');
  },
});

// ─────────────────────────────────────────────────────────────
// PASSWORD HASHING CONFIG (Argon2id)
// ─────────────────────────────────────────────────────────────
export const hashing = Object.freeze({
  // Argon2id parameters — OWASP recommended
  type:        2,       // argon2id
  memoryCost:  65536,   // 64 MiB
  timeCost:    3,       // 3 iterations
  parallelism: 4,       // 4 threads
  hashLength:  32,      // 256-bit hash
});

// ─────────────────────────────────────────────────────────────
// SECURITY CONFIG
// ─────────────────────────────────────────────────────────────
export const security = Object.freeze({
  maxLoginAttempts: 5,
  lockTime: app.isDevelopment
    ? 60 * 1000        // 1 min (dev)
    : 15 * 60 * 1000,  // 15 min (prod)
  maxSessions: 5,
});

// ─────────────────────────────────────────────────────────────
// ACTIVE DEFENSE CONFIG (Toggle + Tuning)
// ─────────────────────────────────────────────────────────────
export const activeDefense = Object.freeze({
  enabled: (process.env.ACTIVE_DEFENDER || 'true').toLowerCase() === 'true',
});

// ─────────────────────────────────────────────────────────────
// GOOGLE OAUTH CONFIG
// ─────────────────────────────────────────────────────────────
export const google = Object.freeze({
  clientId: await loadSecret('GOOGLE_CLIENT_ID', {
    defaultValue: '',
  }),
  clientSecret: await loadSecret('GOOGLE_CLIENT_SECRET', {
    defaultValue: '',
  }),
  redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/v1/auth/google/callback',
});

// ─────────────────────────────────────────────────────────────
// INTERNAL SERVICE TOKEN (Zero Trust)
// ─────────────────────────────────────────────────────────────
export const internal = Object.freeze({
  serviceToken: await loadSecret('INTERNAL_SERVICE_TOKEN', {
    defaultValue: '',
  }),
});

// ─────────────────────────────────────────────────────────────
// SEED CONFIG
// ─────────────────────────────────────────────────────────────
export const seed = Object.freeze({
  adminPassword:    process.env.SEED_ADMIN_PASSWORD    || 'Admin@1234!',
  analystPassword:  process.env.SEED_ANALYST_PASSWORD  || 'Analyst@1234!',
  userPassword:     process.env.SEED_USER_PASSWORD     || 'User@1234!',
  mfaTargetEmail:   process.env.MFA_TARGET_EMAIL       || 'admin_attack@example.com',
  mfaTargetPassword: process.env.MFA_TARGET_PASSWORD   || undefined,
});

// ─────────────────────────────────────────────────────────────
// RISK COMPUTE CONFIG
// ─────────────────────────────────────────────────────────────
// Helper: parseInt returns NaN for undefined, and NaN ?? fallback is still NaN.
// This safely handles both unset vars (NaN) AND intentional zero values.
const safeInt = (val, fallback) => {
  const parsed = parseInt(val, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
};

export const risk = Object.freeze({
  low:    safeInt(process.env.RISK_THRESHOLD_LOW,    30),
  medium: safeInt(process.env.RISK_THRESHOLD_MEDIUM, 60),
  high:   safeInt(process.env.RISK_THRESHOLD_HIGH,   85),
});

// ─────────────────────────────────────────────────────────────
// DEFAULT EXPORT — full config tree
// ─────────────────────────────────────────────────────────────
const config = Object.freeze({
  app,
  database,
  redis,
  jwt,
  encryption,
  hashing,
  security,
  activeDefense,
  google,
  internal,
  seed,
  risk,
});

export default config;
