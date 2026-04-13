#!/usr/bin/env node
/**
 * ─────────────────────────────────────────────────────────────
 * validate-secrets.js — Pre-flight Secret Consistency Checker
 * ─────────────────────────────────────────────────────────────
 *
 * Validates that all secrets required by the IAM platform are
 * resolvable by the active SecretProvider BEFORE the application
 * starts accepting traffic.
 *
 * Usage:
 *   node scripts/validate-secrets.js          # runs in current env
 *   SECRET_PROVIDER=docker-secrets node scripts/validate-secrets.js
 *
 * Exit codes:
 *   0 — all checks passed
 *   1 — one or more critical checks failed
 *
 * ─────────────────────────────────────────────────────────────
 */

import { getSecretProvider } from '../src/shared/providers/SecretProvider.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

// Load .env for local dev
if (process.env.SECRET_PROVIDER !== 'docker-secrets') {
  const dotenv = await import('dotenv');
  dotenv.config();
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const provider = getSecretProvider();

let passed = 0;
let warned = 0;
let failed = 0;

function ok(label, detail = '') {
  passed++;
  console.log(`  ✅ ${label}${detail ? ` — ${detail}` : ''}`);
}

function warn(label, detail = '') {
  warned++;
  console.log(`  ⚠️  ${label}${detail ? ` — ${detail}` : ''}`);
}

function fail(label, detail = '') {
  failed++;
  console.log(`  ❌ ${label}${detail ? ` — ${detail}` : ''}`);
}

// ─── Helpers ──────────────────────────────────────────────
async function checkSecret(key, { required = true, description = '' } = {}) {
  const value = await provider.getSecret(key);
  if (value && value.trim().length > 0) {
    // Don't log the actual value — just confirm it's present
    const preview = value.length > 8 ? `${value.slice(0, 4)}…(${value.length} chars)` : `(${value.length} chars)`;
    ok(key, `${description} ${preview}`);
    return value;
  }
  if (required) {
    fail(key, `MISSING — ${description}`);
  } else {
    warn(key, `not set — ${description}`);
  }
  return null;
}

function isPEM(value) {
  return value && (
    value.includes('-----BEGIN') ||
    value.includes('-----END')
  );
}

function validateRSAKeyPair(privateKey, publicKey, kid) {
  try {
    // Sign a test payload with the private key and verify with public
    const testData = Buffer.from('secret-validation-test');
    const signature = crypto.sign('sha256', testData, {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    });
    const verified = crypto.verify('sha256', testData, {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    }, signature);

    if (verified) {
      ok(`JWT key pair "${kid}"`, 'sign/verify roundtrip passed');
    } else {
      fail(`JWT key pair "${kid}"`, 'signature verification FAILED — keys may be mismatched');
    }
  } catch (err) {
    fail(`JWT key pair "${kid}"`, `crypto error: ${err.message}`);
  }
}

// ─── Main ─────────────────────────────────────────────────
console.log('');
console.log('═══════════════════════════════════════════════════');
console.log('  SECRET VALIDATION — Cloud IAM Platform');
console.log(`  Provider: ${provider.getName()}`);
console.log(`  Mode: ${process.env.SECRET_PROVIDER === 'docker-secrets' ? 'Docker' : 'Local'}`);
console.log('═══════════════════════════════════════════════════');
console.log('');

// ── 1. Connection Secrets ─────────────────────────────────
console.log('── Connection Secrets ──────────────────────────');
await checkSecret('DATABASE_URL', { description: 'PostgreSQL connection string' });
await checkSecret('REDIS_URL', { description: 'Redis connection string', required: false });
await checkSecret('NEO4J_PASSWORD', { description: 'Neo4j authentication password' });
console.log('');

// ── 2. OAuth Secrets ──────────────────────────────────────
console.log('── OAuth Secrets ──────────────────────────────');
await checkSecret('GOOGLE_CLIENT_ID', { description: 'Google OAuth client ID', required: false });
await checkSecret('GOOGLE_CLIENT_SECRET', { description: 'Google OAuth client secret', required: false });
console.log('');

// ── 3. Internal Auth ──────────────────────────────────────
console.log('── Internal Auth ──────────────────────────────');
await checkSecret('INTERNAL_SERVICE_TOKEN', { description: 'Service-to-service auth token', required: false });
console.log('');

// ── 4. Encryption Keys ───────────────────────────────────
console.log('── Encryption Keys ────────────────────────────');
const activeVersion = parseInt(process.env.ACTIVE_KEY_VERSION, 10) || 1;
for (let v = 1; v <= 2; v++) {
  const key = await checkSecret(`ENCRYPTION_KEY_V${v}`, {
    description: `AES-256 key version ${v}${v === activeVersion ? ' (ACTIVE)' : ''}`,
    required: v === activeVersion,
  });
  if (key) {
    if (key.length === 64 && /^[0-9a-fA-F]+$/.test(key)) {
      ok(`ENCRYPTION_KEY_V${v} format`, '64 hex chars (256-bit) ✓');
    } else {
      fail(`ENCRYPTION_KEY_V${v} format`, `Expected 64 hex chars, got ${key.length} chars`);
    }
  }
}
console.log('');

// ── 5. JWT Key Pairs ──────────────────────────────────────
console.log('── JWT Key Pairs ──────────────────────────────');

const activeKid = (process.env.JWT_ACTIVE_KID || 'default').toLowerCase();
const kidsEnv = process.env.JWT_KIDS;
const kids = kidsEnv ? kidsEnv.split(',').map(k => k.trim().toLowerCase()) : [];

if (kids.length > 0) {
  console.log(`  Active KID: "${activeKid}"`);
  console.log(`  Configured KIDs: [${kids.join(', ')}]`);
  console.log('');

  for (const kid of kids) {
    const kidUpper = kid.toUpperCase();
    const privKey = await checkSecret(`JWT_KEY_${kidUpper}_PRIVATE`, {
      description: `RSA private key for KID "${kid}"`,
    });
    const pubKey = await checkSecret(`JWT_KEY_${kidUpper}_PUBLIC`, {
      description: `RSA public key for KID "${kid}"`,
    });

    if (privKey && pubKey) {
      if (isPEM(privKey) && isPEM(pubKey)) {
        // Normalize escaped newlines
        const normalizedPriv = privKey.includes('\\n') ? privKey.replace(/\\n/g, '\n') : privKey;
        const normalizedPub = pubKey.includes('\\n') ? pubKey.replace(/\\n/g, '\n') : pubKey;
        validateRSAKeyPair(normalizedPriv, normalizedPub, kid);
      } else {
        warn(`JWT key pair "${kid}"`, 'Keys do not appear to be PEM-formatted');
      }
    }
  }

  if (!kids.includes(activeKid)) {
    fail('JWT_ACTIVE_KID', `Active KID "${activeKid}" is not in JWT_KIDS list [${kids.join(', ')}]`);
  } else {
    ok('JWT_ACTIVE_KID', `"${activeKid}" found in configured KIDs`);
  }
} else {
  // Legacy fallback
  console.log('  No KID-based keys configured — checking legacy keys...');
  const privKey = await checkSecret('JWT_PRIVATE_KEY', { description: 'Legacy RSA private key' });
  const pubKey = await checkSecret('JWT_PUBLIC_KEY', { description: 'Legacy RSA public key' });

  if (privKey && pubKey && isPEM(privKey) && isPEM(pubKey)) {
    const normalizedPriv = privKey.includes('\\n') ? privKey.replace(/\\n/g, '\n') : privKey;
    const normalizedPub = pubKey.includes('\\n') ? pubKey.replace(/\\n/g, '\n') : pubKey;
    validateRSAKeyPair(normalizedPriv, normalizedPub, 'default');
  }
}
console.log('');

// ── 6. File-level Duplicate Check ─────────────────────────
console.log('── File Consistency ───────────────────────────');
const keysDir = path.join(__dirname, '..', 'keys');
const secretsDir = path.join(__dirname, '..', 'secrets');

const duplicatePairs = [
  { keysFile: 'key1/private.pem', secretsFile: 'key1_private.pem', label: 'key1 private' },
  { keysFile: 'key1/public.pem',  secretsFile: 'key1_public.pem',  label: 'key1 public' },
  { keysFile: 'key2/private.pem', secretsFile: 'key2_private.pem', label: 'key2 private' },
  { keysFile: 'key2/public.pem',  secretsFile: 'key2_public.pem',  label: 'key2 public' },
  { keysFile: 'encryption_v1.key', secretsFile: 'encryption_v1.key', label: 'encryption v1' },
  { keysFile: 'encryption_v2.key', secretsFile: 'encryption_v2.key', label: 'encryption v2' },
];

for (const { keysFile, secretsFile, label } of duplicatePairs) {
  const keysPath = path.join(keysDir, keysFile);
  const secretsPath = path.join(secretsDir, secretsFile);

  const keysExists = fs.existsSync(keysPath);
  const secretsExists = fs.existsSync(secretsPath);

  if (keysExists && secretsExists) {
    const keysContent = fs.readFileSync(keysPath, 'utf8').trim();
    const secretsContent = fs.readFileSync(secretsPath, 'utf8').trim();
    if (keysContent === secretsContent) {
      ok(`${label}`, 'keys/ and secrets/ copies match');
    } else {
      fail(`${label}`, 'keys/ and secrets/ copies DIFFER — potential key drift!');
    }
  } else if (keysExists && !secretsExists) {
    ok(`${label}`, 'exists in keys/ only (correct — docker-compose references keys/)');
  } else if (!keysExists && secretsExists) {
    warn(`${label}`, 'exists in secrets/ only — docker-compose references keys/ (unused)');
  }
}
console.log('');

// ── Summary ───────────────────────────────────────────────
console.log('═══════════════════════════════════════════════════');
console.log(`  Results: ${passed} passed, ${warned} warnings, ${failed} FAILED`);
if (failed > 0) {
  console.log('  ⛔ SECRET VALIDATION FAILED — fix errors above before proceeding.');
  console.log('═══════════════════════════════════════════════════');
  process.exit(1);
} else if (warned > 0) {
  console.log('  ⚠️  Passed with warnings — review optional items above.');
  console.log('═══════════════════════════════════════════════════');
  process.exit(0);
} else {
  console.log('  🎉 All checks passed!');
  console.log('═══════════════════════════════════════════════════');
  process.exit(0);
}
