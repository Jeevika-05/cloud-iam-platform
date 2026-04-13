/**
 * ─────────────────────────────────────────────────────────────
 * SECRET PROVIDER — Pluggable Secrets Management Interface
 * ─────────────────────────────────────────────────────────────
 *
 * Defines the contract for secret providers. All providers must
 * implement getSecret(key) → Promise<string>.
 *
 * Current providers:
 *   - EnvProvider          (active)   — reads from env vars (local dev)
 *   - DockerSecretsProvider (active)  — reads from /run/secrets/*
 *   - VaultProvider        (placeholder) — reads from HashiCorp Vault API
 *
 * Docker Compose `secrets:` mounts files at /run/secrets/<secret_name>.
 * The <secret_name> is the key used in the docker-compose.yml secrets block.
 * DockerSecretsProvider maps logical config keys (e.g., 'DATABASE_URL')
 * to the actual filenames under /run/secrets/.
 *
 * Usage:
 *   import { getSecretProvider } from './providers/SecretProvider.js';
 *   const provider = getSecretProvider();
 *   const dbUrl = await provider.getSecret('DATABASE_URL');
 *
 * To add a new provider:
 *   1. Create a class implementing the SecretProvider interface
 *   2. Add it to the PROVIDERS registry in this file
 *   3. Set SECRET_PROVIDER env var to the new provider name
 *
 * ─────────────────────────────────────────────────────────────
 */

import fs from 'fs';
import path from 'path';
import logger from '../utils/logger.js';

// ─────────────────────────────────────────────────────────────
// INTERFACE: SecretProvider
// All providers must implement this contract.
// ─────────────────────────────────────────────────────────────

/**
 * @interface SecretProvider
 * @method getSecret(key: string): Promise<string | undefined>
 * @method getName(): string
 * @method isAvailable(): Promise<boolean>
 */

// ─────────────────────────────────────────────────────────────
// PROVIDER 1: EnvProvider
// Reads secrets from environment variables (local dev only).
// ─────────────────────────────────────────────────────────────

export class EnvProvider {
  getName() {
    return 'env';
  }

  async isAvailable() {
    return true; // Always available
  }

  /**
   * @param {string} key - Secret key name (e.g., 'DATABASE_URL')
   * @returns {Promise<string | undefined>}
   */
  async getSecret(key) {
    return process.env[key];
  }
}

// ─────────────────────────────────────────────────────────────
// PROVIDER 2: DockerSecretsProvider
// Reads secrets from Docker Compose `secrets:` mount at /run/secrets/
//
// Docker Compose mounts each secret as a file at:
//   /run/secrets/<secret_name>
//
// The KEY_MAP below maps logical config keys used by the application
// (e.g., 'DATABASE_URL') to the Docker secret name (e.g., 'db_url')
// which corresponds to the filename under /run/secrets/.
//
// If a key is NOT in KEY_MAP, we fall back to reading
// /run/secrets/<key> directly (case-sensitive filename match).
// ─────────────────────────────────────────────────────────────

export class DockerSecretsProvider {
  constructor(basePath = '/run/secrets') {
    this.basePath = basePath;
  }

  getName() {
    return 'docker-secrets';
  }

  async isAvailable() {
    try {
      await fs.promises.access(this.basePath, fs.constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Maps application-level config key → Docker Compose secret name.
   *
   * Left side  = the key used in config/index.js (e.g., loadSecret('DATABASE_URL'))
   * Right side = the secret name from docker-compose.yml secrets: block
   *              which becomes the filename under /run/secrets/
   *
   * To add a new secret:
   *   1. Add it to docker-compose.yml `secrets:` block
   *   2. Add it to the service's `secrets:` list
   *   3. Add the mapping here
   */
  static KEY_MAP = Object.freeze({
    // ── Connection strings ──────────────────────────────────
    'DATABASE_URL':           'db_url',
    'REDIS_URL':              'redis_url',

    // ── OAuth ───────────────────────────────────────────────
    'GOOGLE_CLIENT_ID':       'google_client_id',
    'GOOGLE_CLIENT_SECRET':   'google_client_secret',

    // ── Internal service auth ───────────────────────────────
    'INTERNAL_SERVICE_TOKEN': 'internal_service_token',

    // ── Neo4j ───────────────────────────────────────────────
    'NEO4J_PASSWORD':         'neo4j_password',

    // ── Encryption keys ─────────────────────────────────────
    'ENCRYPTION_KEY_V1':      'encryption_v1',
    'ENCRYPTION_KEY_V2':      'encryption_v2',

    // ── JWT KID-based key pairs ─────────────────────────────
    'JWT_KEY_KEY1_PRIVATE':   'jwt_key1_private',
    'JWT_KEY_KEY1_PUBLIC':    'jwt_key1_public',
    'JWT_KEY_KEY2_PRIVATE':   'jwt_key2_private',
    'JWT_KEY_KEY2_PUBLIC':    'jwt_key2_public',

    // ── JWT legacy fallback key pair ────────────────────────
    'JWT_PRIVATE_KEY':        'jwt_private_legacy',
    'JWT_PUBLIC_KEY':         'jwt_public_legacy',
  });

  /**
   * @param {string} key - Logical config key (e.g., 'DATABASE_URL')
   * @returns {Promise<string | undefined>}
   */
  async getSecret(key) {
    // Resolve: KEY_MAP lookup → fallback to raw key as filename
    const secretFileName = DockerSecretsProvider.KEY_MAP[key] || key;
    const secretPath = path.join(this.basePath, secretFileName);

    try {
      const value = await fs.promises.readFile(secretPath, 'utf8');
      return value.trim();
    } catch (err) {
      if (err.code === 'ENOENT') {
        // Not found at /run/secrets — this is normal for optional secrets
        return undefined;
      }
      logger.error('DOCKER_SECRETS_READ_FAILED', {
        key,
        resolvedFile: secretFileName,
        path: secretPath,
        error: err.message,
      });
      throw err;
    }
  }
}

// ─────────────────────────────────────────────────────────────
// PROVIDER 3: VaultProvider (Placeholder — Future-Ready)
// Designed for HashiCorp Vault integration.
// ─────────────────────────────────────────────────────────────

export class VaultProvider {
  /**
   * @param {object} opts
   * @param {string} opts.address  - Vault address (e.g., 'https://vault.internal:8200')
   * @param {string} opts.token    - Vault authentication token
   * @param {string} opts.mountPath - KV engine mount path (default: 'secret')
   * @param {string} opts.secretPath - Path to the secret in Vault
   */
  constructor(opts = {}) {
    this.address = opts.address || process.env.VAULT_ADDR || 'http://127.0.0.1:8200';
    this.token = opts.token || process.env.VAULT_TOKEN;
    this.mountPath = opts.mountPath || process.env.VAULT_MOUNT_PATH || 'secret';
    this.secretPath = opts.secretPath || process.env.VAULT_SECRET_PATH || 'data/iam-platform';
  }

  getName() {
    return 'vault';
  }

  async isAvailable() {
    // Placeholder: In production, this would perform a health check
    // against the Vault API (GET /v1/sys/health)
    return !!this.token;
  }

  /**
   * @param {string} key - Secret key name within the Vault secret path
   * @returns {Promise<string | undefined>}
   *
   * @example
   * // Vault KV v2: GET /v1/secret/data/iam-platform
   * // Response: { data: { data: { DATABASE_URL: "postgres://..." } } }
   */
  async getSecret(key) {
    // ─────────────────────────────────────────────────────────
    // PLACEHOLDER IMPLEMENTATION
    // Replace with actual Vault HTTP API call when ready.
    //
    // Example implementation outline:
    //
    //   const url = `${this.address}/v1/${this.mountPath}/${this.secretPath}`;
    //   const response = await fetch(url, {
    //     headers: { 'X-Vault-Token': this.token }
    //   });
    //   const body = await response.json();
    //   return body?.data?.data?.[key];
    //
    // Consider:
    //   - Token renewal (lease management)
    //   - Response caching with TTL
    //   - AppRole or Kubernetes auth method
    //   - Dynamic secret generation (database credentials)
    // ─────────────────────────────────────────────────────────
    throw new Error(
      `VaultProvider.getSecret() is not yet implemented. ` +
      `Set SECRET_PROVIDER=env to use environment variables, ` +
      `or implement the Vault HTTP client for key: ${key}`
    );
  }
}

// ─────────────────────────────────────────────────────────────
// PROVIDER REGISTRY & FACTORY
// ─────────────────────────────────────────────────────────────

const PROVIDERS = {
  env: EnvProvider,
  'docker-secrets': DockerSecretsProvider,
  vault: VaultProvider,
};

/** @type {SecretProvider | null} */
let _instance = null;

export function getSecretProvider() {
  if (_instance) return _instance;

  const providerName = (process.env.SECRET_PROVIDER || 'env').toLowerCase();
  
  if (providerName === 'docker-secrets') {
    _instance = new DockerSecretsProvider();
  } else if (providerName === 'vault') {
    _instance = new VaultProvider();
  } else {
    _instance = new EnvProvider();
  }

  logger.info('SECRET_PROVIDER_INITIALIZED', { provider: _instance.getName() });
  return _instance;
}

export default { getSecretProvider, EnvProvider, DockerSecretsProvider, VaultProvider };
